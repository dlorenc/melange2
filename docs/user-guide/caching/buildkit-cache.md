# BuildKit Caching

melange2 leverages BuildKit's content-addressable caching for fast, incremental builds.

## How Caching Works

BuildKit caches each operation in the build graph. When you rebuild:

1. BuildKit computes a cache key for each step
2. If the inputs haven't changed, the cached result is reused
3. Only modified steps are re-executed

You'll see cache status in the build output:

```
INFO [3/12] copy apko rootfs
INFO   -> copy apko rootfs (0.0s) [CACHED]
INFO [7/12] uses: go/build
INFO   -> uses: go/build (18.3s) [done]
```

## Cache Types

### Layer Cache

BuildKit caches filesystem layers:
- Build environment (apko layer)
- Source file copies
- Pipeline step outputs

### Cache Mounts

Persistent directories for package managers:

| Cache ID | Mount Path | Purpose |
|----------|------------|---------|
| `melange-go-mod-cache` | `/go/pkg/mod` | Go modules |
| `melange-go-build-cache` | `/root/.cache/go-build` | Go build cache |
| `melange-pip-cache` | `/root/.cache/pip` | Python pip |
| `melange-npm-cache` | `/root/.npm` | Node.js npm |
| `melange-cargo-registry-cache` | `/root/.cargo/registry` | Rust crates |
| `melange-cargo-build-cache` | `/root/.cargo/git` | Rust git deps |
| `melange-ccache-cache` | `/root/.ccache` | C/C++ ccache |
| `melange-apk-cache` | `/var/cache/apk` | APK packages |

These caches persist between builds and are automatically mounted.

## Host Cache Directory

Use `--cache-dir` to mount a host directory at `/var/cache/melange`:

```bash
melange2 build package.yaml --cache-dir ./melange-cache
```

### Pre-populating Cache

Copy files to your cache directory before building:

```bash
# Use existing Go module cache
melange2 build package.yaml --cache-dir "$(go env GOMODCACHE)"
```

### Configuring for Go

Set `GOMODCACHE` to use the mounted cache:

```yaml
environment:
  environment:
    GOMODCACHE: /var/cache/melange
```

Or in pipeline:

```yaml
pipeline:
  - runs: |
      export GOMODCACHE=/var/cache/melange
      go build .
```

## Cache Behavior

### Cache Invalidation

Caches are invalidated when:
- Source files change (content hash differs)
- Build environment changes (different packages)
- Pipeline commands change
- Environment variables change

### Cache Sharing

Cache mounts use `CacheMountShared` mode by default:
- Multiple builds can read simultaneously
- Writes are isolated until step completes
- Safe for parallel builds

## Optimizing Cache Usage

### Stable Dependencies First

Order pipeline steps to maximize cache hits:

```yaml
pipeline:
  # Download dependencies (cacheable, rarely changes)
  - uses: fetch
    with:
      uri: https://example.com/source.tar.gz

  # Install build deps (cacheable)
  - runs: |
      go mod download

  # Build (changes more often)
  - runs: |
      go build .
```

### Avoid Cache Busters

Don't include timestamps or random values:

```yaml
# BAD - busts cache every build
pipeline:
  - runs: |
      echo "Built at $(date)" > version.txt

# GOOD - deterministic
pipeline:
  - runs: |
      echo "Version ${{package.version}}" > version.txt
```

### Use SOURCE_DATE_EPOCH

melange sets `SOURCE_DATE_EPOCH` for reproducible builds. This is automatically used by many build systems.

## Debugging Cache

### View Cache Status

The build output shows `[CACHED]` for cache hits:

```
INFO [3/12] Compile source
INFO   -> Compile source (0.0s) [CACHED]
```

### Force Rebuild

To bypass cache (useful for debugging):

```bash
# Remove BuildKit cache
docker exec buildkitd buildctl prune

# Or remove and recreate container
docker rm -f buildkitd
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234
```

### Cache Mount Contents

Cache mounts persist in BuildKit's storage. To inspect:

```bash
docker exec buildkitd ls -la /var/lib/buildkit/
```

## Best Practices

1. **Keep source fetches early** - Downloading sources is often cacheable
2. **Separate dependency installation** - `go mod download` before `go build`
3. **Use built-in pipelines** - They're optimized for caching
4. **Don't modify source in place** - Copy to output directory instead
5. **Avoid random/time-based values** - They bust the cache
