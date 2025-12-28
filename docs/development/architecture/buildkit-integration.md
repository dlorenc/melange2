# BuildKit Integration

This document explains how melange2 integrates with BuildKit.

## Overview

BuildKit is a next-generation container build toolkit. melange2 uses BuildKit to:

1. Execute build commands in isolated environments
2. Cache build artifacts efficiently
3. Export results to the local filesystem

## Connection

melange2 connects to BuildKit via the `--buildkit-addr` flag:

```go
// pkg/buildkit/client.go
client, err := client.New(ctx, addr)
```

BuildKit must be running as a daemon (Docker container or local service).

## Build Process

### 1. Load Build Environment

The apko-generated environment is loaded as a local mount:

```go
// pkg/buildkit/image.go
result := &LoadResult{
    LocalName:  fmt.Sprintf("apko-%s", pkgName),  // "apko-mypackage"
    ExtractDir: extractDir,                        // Temp dir with rootfs
    Layer:      layer,                             // OCI layer
}
```

### 2. Create Local Mounts

Local directories are registered for access:

```go
// pkg/buildkit/builder.go
localDirs := map[string]string{
    "apko-mypackage": "/tmp/melange-apko-xxx",  // Build environment
    "source":         "./",                      // Source code
    "cache":          "./melange-cache/",        // Host cache
}
```

### 3. Reference in LLB

Use `llb.Local()` to reference mounted directories:

```go
// Copy build environment
state := llb.Scratch().File(
    llb.Copy(llb.Local("apko-mypackage"), "/", "/"),
)

// Copy source files
state = state.File(
    llb.Copy(llb.Local("source"), "/", "/home/build/"),
)
```

### 4. Execute Pipeline

Each pipeline step becomes an `llb.Run()` operation:

```go
state = state.Run(
    llb.Args([]string{"/bin/sh", "-c", script}),
    llb.Dir("/home/build"),
    llb.User("build"),
    llb.WithCustomName("Build the application"),
    // Cache mount options...
).Root()
```

### 5. Export Results

The melange-out directory is exported:

```go
// Create export state
export := llb.Scratch().File(
    llb.Copy(state, "/home/build/melange-out", "/"),
)

// Solve with local export
client.Solve(ctx, def, client.SolveOpt{
    LocalDirs: localDirs,
    Exports: []client.ExportEntry{{
        Type:      client.ExporterLocal,
        OutputDir: outputDir,
    }},
})
```

## Cache Mounts

BuildKit provides persistent cache volumes:

```go
// pkg/buildkit/cache.go
var DefaultCacheMounts = []CacheMount{
    {ID: "melange-go-mod-cache", Target: "/go/pkg/mod"},
    {ID: "melange-pip-cache", Target: "/root/.cache/pip"},
    // ...
}
```

Applied to run operations:

```go
opts := []llb.RunOption{
    llb.Args(cmd),
}

for _, mount := range cacheMounts {
    opts = append(opts, llb.AddMount(
        mount.Target,
        llb.Scratch(),
        llb.AsPersistentCacheDir(mount.ID, mount.Mode),
    ))
}

state = state.Run(opts...).Root()
```

## Progress Display

BuildKit provides streaming progress updates:

```go
// pkg/buildkit/progress.go
ch := make(chan *client.SolveStatus)
go displayProgress(ch)

client.Solve(ctx, def, solveOpt, ch)
```

This powers the real-time build output:

```
INFO [3/12] copy apko rootfs
INFO   -> copy apko rootfs (0.0s) [CACHED]
INFO [7/12] uses: go/build
INFO   -> uses: go/build (18.3s) [done]
```

## Debug Image Export

On build failure, melange2 can export a debug image:

```go
// pkg/buildkit/export.go
func ExportDebugImage(ctx context.Context, client *client.Client, state llb.State, tag string) error
```

This creates an OCI image at the point of failure for debugging.

## Determinism

LLB graphs must be deterministic for caching:

```go
// pkg/buildkit/determinism.go
// Environment variables are sorted for deterministic LLB
func SortedEnvOpts(env map[string]string) []llb.RunOption {
    keys := slices.Sorted(maps.Keys(env))
    opts := make([]llb.RunOption, 0, len(keys))
    for _, k := range keys {
        opts = append(opts, llb.AddEnv(k, env[k]))
    }
    return opts
}
```

## Error Handling

BuildKit errors are wrapped with context:

```go
if err != nil {
    return fmt.Errorf("buildkit solve failed: %w", err)
}
```

Common errors:
- Connection refused: BuildKit not running
- Context deadline exceeded: Build timeout
- Cache mount errors: Ownership/permission issues
