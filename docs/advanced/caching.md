# Caching in melange2

melange2 provides multiple caching mechanisms to improve build performance. This document covers BuildKit cache mounts, registry cache, and configuration options.

## Overview

melange2 uses three types of caching:

1. **Cache Mounts** - Persistent storage for package manager caches (Go modules, pip, npm, etc.)
2. **Registry Cache** - BuildKit's cache-to/cache-from for LLB layer caching
3. **Host Cache Directory** - Local directory mounted at `/var/cache/melange`

## Cache Mounts

Cache mounts are BuildKit persistent cache directories that survive across builds. They are automatically configured for common package managers and build tools.

### Default Cache Mounts

The following cache mounts are enabled by default when using `WithDefaultCacheMounts()`:

| Cache ID | Mount Path | Purpose |
|----------|------------|---------|
| `melange-go-mod-cache` | `/home/build/go/pkg/mod` | Go module cache |
| `melange-go-build-cache` | `/home/build/.cache/go-build` | Go build cache |
| `melange-pip-cache` | `/home/build/.cache/pip` | Python pip cache |
| `melange-npm-cache` | `/home/build/.npm` | Node.js npm cache |
| `melange-cargo-registry-cache` | `/home/build/.cargo/registry` | Rust Cargo registry cache |
| `melange-cargo-build-cache` | `/home/build/.cargo/git` | Rust Cargo git cache |
| `melange-ccache-cache` | `/home/build/.ccache` | C/C++ ccache |
| `melange-apk-cache` | `/var/cache/apk` | APK package cache |

### Cache Environment Variables

When default cache mounts are enabled, the following environment variables are automatically set to ensure tools use the correct cache locations:

| Variable | Value |
|----------|-------|
| `GOMODCACHE` | `/home/build/go/pkg/mod` |
| `GOCACHE` | `/home/build/.cache/go-build` |
| `GOPATH` | `/home/build/go` |
| `PIP_CACHE_DIR` | `/home/build/.cache/pip` |
| `NPM_CONFIG_CACHE` | `/home/build/.npm` |
| `CARGO_HOME` | `/home/build/.cargo` |
| `CCACHE_DIR` | `/home/build/.ccache` |

### Cache Mount Sharing Mode

All cache mounts use `CacheMountShared` mode, which allows multiple concurrent builds to read from the cache simultaneously. This provides optimal performance for parallel builds.

### Cache Mount Ownership

Cache directories are created with build user ownership (UID/GID 1000) so that pipeline steps running as the build user can write to the cache. This is handled automatically by the `CacheMountOption()` function which creates a scratch state with proper directory permissions.

### Language-Specific Cache Mounts

For builds that only need specific caches, you can use language-specific helpers:

```go
// Go builds only
builder.WithCacheMounts(buildkit.GoCacheMounts())

// Python builds only
builder.WithCacheMounts(buildkit.PythonCacheMounts())

// Rust builds only
builder.WithCacheMounts(buildkit.RustCacheMounts())

// Node.js builds only
builder.WithCacheMounts(buildkit.NodeCacheMounts())

// C/C++ builds only
builder.WithCacheMounts(buildkit.CCacheMounts())
```

## Registry Cache

Registry cache uses BuildKit's cache-to/cache-from mechanism to store LLB layer cache in a container registry. This significantly improves build performance by:

- Persisting cache across BuildKit pod restarts
- Sharing cache across multiple BuildKit instances
- Enabling LLB layer cache reuse between builds

### Configuration

Registry cache is configured via the `CacheConfig` struct in `BuildConfig`:

```go
cfg := &buildkit.BuildConfig{
    // ... other config ...
    CacheConfig: &buildkit.CacheConfig{
        Registry: "registry:5000/melange-cache",
        Mode:     "max",
    },
}
```

### Environment Variables

For server deployments, cache is configured via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `CACHE_REGISTRY` | Registry URL for cache storage | `registry:5000/melange-cache` |
| `CACHE_MODE` | Export mode: `min` or `max` | `max` |

### Cache Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `max` | Export all intermediate layers | Better cache hit rate, recommended for most builds |
| `min` | Export only final layers | Smaller cache size, faster export |

### In-Cluster Registry Setup

The GKE deployment includes an in-cluster Docker Registry for cache storage. This provides fast, local cache storage without external network dependencies.

**Registry Deployment (`deploy/gke/registry.yaml`):**
- Uses the official `registry:2` image
- Runs on port 5000
- Uses `emptyDir` for ephemeral storage (cache loss is acceptable)
- 50Gi size limit for cache storage

**BuildKit Configuration (`deploy/gke/buildkit.yaml`):**

BuildKit must be configured to allow insecure access to the in-cluster registry:

```toml
[registry."registry:5000"]
  http = true
  insecure = true
```

### How Cache Works

BuildKit's content-addressable cache handles deduplication automatically:

1. **On build start**: BuildKit imports cache layers from the registry
2. **During build**: BuildKit checks if each LLB operation already has a cached result
3. **On build complete**: BuildKit exports new/changed layers to the registry

No custom cache key logic is needed - BuildKit computes cache keys from the LLB graph content.

## Host Cache Directory

The `--cache-dir` flag (default: `./melange-cache/`) specifies a host directory mounted at `/var/cache/melange` inside the build container.

This is useful for:
- Caching fetch/download artifacts
- Sharing cached files between local builds
- Pre-populating cache with known artifacts

### Usage

```bash
./melange2 build pkg.yaml --cache-dir /path/to/cache
```

### Directory Setup

The cache directory is automatically created with build user ownership (UID/GID 1000) during workspace preparation:

```go
// From PrepareWorkspace()
mkdir -p /var/cache/melange
chown 1000:1000 /var/cache/melange
chmod 755 /var/cache/melange
```

## Best Practices

### 1. Use Default Cache Mounts for General Builds

For most builds, enable all default cache mounts:

```go
builder.WithDefaultCacheMounts()
```

This provides caching for all common package managers with minimal configuration.

### 2. Use Registry Cache for CI/CD

For CI/CD environments, configure registry cache to persist cache across pipeline runs:

```yaml
# deploy/gke/configmap.yaml
data:
  cache-registry: "registry:5000/melange-cache"
  cache-mode: "max"
```

### 3. Use max Mode for Better Cache Hits

The `max` mode exports all intermediate layers, which provides better cache hit rates for incremental builds. Only use `min` mode if cache storage is a concern.

### 4. Understand Cache Persistence

| Cache Type | Persistence | Scope |
|------------|-------------|-------|
| Cache Mounts | Per BuildKit instance | Survives container restarts |
| Registry Cache | Per registry instance | Shared across BuildKit instances |
| Host Cache Dir | Persistent on host | Local to host machine |

### 5. Cache Mount Paths

All cache mount paths use `/home/build` instead of `/root` to support running pipeline steps as the build user (UID 1000). This ensures consistent permissions and avoids permission denied errors.
