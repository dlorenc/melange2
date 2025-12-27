# BuildKit LLB Architecture

This document explains how melange2 constructs BuildKit LLB (Low-Level Build) graphs to execute package builds.

## Overview

BuildKit uses LLB as its intermediate representation for builds. LLB is a directed acyclic graph (DAG) of operations that BuildKit executes. Each node in the graph represents either:
- A filesystem state (the result of operations)
- An operation that transforms a filesystem state

Melange2 converts YAML pipeline definitions into LLB operations, executes them via BuildKit, and exports the results.

## High-Level Build Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              melange build                                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  1. Parse YAML config                                                        │
│     - Load package.yaml                                                      │
│     - Substitute variables (${{package.name}}, etc.)                         │
│     - Evaluate conditionals                                                  │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  2. Build guest environment with apko                                        │
│     - Resolve packages from environment.contents.packages                    │
│     - Download and install APKs                                              │
│     - Create OCI layer (v1.Layer)                                            │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  3. Construct LLB graph                                                      │
│     - Load apko layer via llb.Local()                                        │
│     - Create workspace directories                                           │
│     - Copy source files                                                      │
│     - Convert pipelines to llb.Run() operations                              │
│     - Add cache mounts                                                       │
│     - Create export state                                                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  4. Solve and export                                                         │
│     - Marshal LLB to protobuf definition                                     │
│     - Send to BuildKit daemon                                                │
│     - BuildKit executes operations                                           │
│     - Export results to local filesystem                                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  5. Post-processing                                                          │
│     - Run linters                                                            │
│     - Generate SBOMs                                                         │
│     - Create APK packages                                                    │
│     - Sign packages                                                          │
│     - Generate APKINDEX                                                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

## LLB Graph Structure

The LLB graph for a typical melange build looks like this:

```
                    ┌─────────────┐
                    │   Scratch   │  (empty filesystem)
                    └──────┬──────┘
                           │
                           ▼
              ┌────────────────────────┐
              │  llb.Copy(apko-layer)  │  Copy apko rootfs
              └────────────┬───────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │  llb.Mkdir(/home/build)│  Create workspace
              └────────────┬───────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │  llb.Mkdir(melange-out)│  Create output dirs
              └────────────┬───────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │  llb.Copy(source)      │  Copy source files (optional)
              └────────────┬───────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │  llb.Copy(cache)       │  Copy host cache (optional, --cache-dir)
              └────────────┬───────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │  llb.Run(pipeline[0])  │  Execute pipeline step
              │  + cache mounts        │
              └────────────┬───────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │  llb.Run(pipeline[1])  │  Execute pipeline step
              │  + cache mounts        │
              └────────────┬───────────┘
                           │
                           ▼
                          ...
                           │
                           ▼
              ┌────────────────────────┐
              │  llb.Run(subpkg pipe)  │  Subpackage pipelines
              └────────────┬───────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │  ExportWorkspace       │  Copy melange-out to /
              │  (Scratch + Copy)      │
              └────────────────────────┘
```

## Inputs and Mounts

### Local Mounts (Host → BuildKit)

Local mounts allow BuildKit to access files from the host filesystem. They are declared in `SolveOpt.LocalDirs` and referenced in LLB via `llb.Local(name)`.

| Name | Source | Purpose |
|------|--------|---------|
| `apko-{package}` | Temp directory with extracted apko layer | Base filesystem (Alpine packages) |
| `source` | `--source-dir` flag or `.` | Source code to build |
| `cache` | `--cache-dir` flag | Host cache at `/var/cache/melange` |

**How it works:**

```go
// In builder.go
localDirs := map[string]string{
    loadResult.LocalName: loadResult.ExtractDir,  // "apko-mypackage" -> "/tmp/melange-apko-..."
}
if cfg.SourceDir != "" {
    localDirs["source"] = cfg.SourceDir           // "source" -> "./my-source"
}
if cfg.CacheDir != "" {
    localDirs["cache"] = cfg.CacheDir             // "cache" -> "./melange-cache/"
}

// When solving
client.Solve(ctx, def, client.SolveOpt{
    LocalDirs: localDirs,
    ...
})
```

**In LLB:**

```go
// Reference in LLB graph
apkoRootfs := llb.Local("apko-mypackage")
sourceFiles := llb.Local("source")
cacheFiles := llb.Local("cache")

// Copy cache to /var/cache/melange
state = CopyCacheToWorkspace(state, "cache")
```

### Host Cache Directory (`--cache-dir`)

The `--cache-dir` flag mounts a host directory at `/var/cache/melange` inside the build. This is different from BuildKit cache mounts:

| Feature | Host Cache (`--cache-dir`) | BuildKit Cache Mounts |
|---------|---------------------------|----------------------|
| Storage | Host filesystem | BuildKit-internal volumes |
| Pre-population | Yes (copy existing files) | No |
| Persistence | On host, survives BuildKit restart | In BuildKit, cleared if BuildKit storage is cleared |
| Use case | Sharing Go modules, fetch artifacts | Package manager caches |

**How it works:**

```go
// Copy host cache directory into build
func CopyCacheToWorkspace(base llb.State, localName string) llb.State {
    return base.File(
        llb.Copy(llb.Local(localName), "/", DefaultCacheDir+"/", &llb.CopyInfo{
            CopyDirContentsOnly: true,
            CreateDestPath:      true,
        }),
    )
}
```

**Note:** Changes made to `/var/cache/melange` during the build are NOT synced back to the host. The cache is read-only from the host's perspective. To pre-populate, place files in your `--cache-dir` before building.

### Cache Mounts (BuildKit-Managed)

Cache mounts are persistent volumes managed by BuildKit. They survive between builds and are shared based on cache ID.

| Cache ID | Mount Path | Purpose |
|----------|------------|---------|
| `melange-go-mod-cache` | `/go/pkg/mod` | Go module cache |
| `melange-go-build-cache` | `/root/.cache/go-build` | Go build cache |
| `melange-pip-cache` | `/root/.cache/pip` | Python pip cache |
| `melange-npm-cache` | `/root/.npm` | Node.js npm cache |
| `melange-cargo-registry-cache` | `/root/.cargo/registry` | Rust crate registry |
| `melange-cargo-build-cache` | `/root/.cargo/git` | Rust git dependencies |
| `melange-ccache-cache` | `/root/.ccache` | C/C++ compiler cache |
| `melange-apk-cache` | `/var/cache/apk` | APK package cache |

**Sharing modes:**

- `CacheMountShared` - Multiple builds can read simultaneously (default)
- `CacheMountPrivate` - Exclusive access for one build
- `CacheMountLocked` - Exclusive access with locking

**How it works:**

```go
// Define cache mount
mount := CacheMount{
    ID:     "melange-go-mod-cache",
    Target: "/go/pkg/mod",
    Mode:   llb.CacheMountShared,
}

// Convert to LLB option
opt := llb.AddMount(mount.Target, llb.Scratch(),
    llb.AsPersistentCacheDir(mount.ID, mount.Mode))

// Add to run operation
state = state.Run(
    llb.Args([]string{"/bin/sh", "-c", script}),
    opt,  // Cache mount attached here
).Root()
```

## Outputs and Export

### Workspace Structure

During the build, files are written to a specific directory structure:

```
/home/build/                     # DefaultWorkDir - working directory
├── <source files>               # Copied from --source-dir
└── melange-out/                 # MelangeOutDir - output directory
    ├── {package-name}/          # Main package output
    │   └── usr/
    │       └── bin/
    │           └── myapp
    └── {subpackage-name}/       # Subpackage outputs
        └── usr/
            └── share/
                └── doc/
```

### Export Process

The export extracts only the `melange-out` directory:

```go
// Create export state - starts from Scratch, copies only melange-out
func ExportWorkspace(state llb.State) llb.State {
    melangeOutPath := filepath.Join(DefaultWorkDir, MelangeOutDir)
    return llb.Scratch().File(
        llb.Copy(state, melangeOutPath, "/", &llb.CopyInfo{
            CopyDirContentsOnly: true,
        }),
    )
}
```

**Export configuration:**

```go
client.Solve(ctx, def, client.SolveOpt{
    Exports: []client.ExportEntry{{
        Type:      client.ExporterLocal,   // Export to local filesystem
        OutputDir: melangeOutDir,          // Target directory
    }},
})
```

After export, the workspace directory contains:

```
{workspace}/melange-out/
├── {package-name}/
│   └── ...
└── {subpackage-name}/
    └── ...
```

## YAML to LLB Mapping

### Pipeline Steps

Each pipeline step in the YAML becomes an `llb.Run()` operation:

```yaml
pipeline:
  - name: Build the application
    runs: |
      go build -o myapp .
```

Becomes:

```go
state.Run(
    llb.Args([]string{"/bin/sh", "-c", `set -e
[ -d '/home/build' ] || mkdir -p '/home/build'
cd '/home/build'
go build -o myapp .
exit 0`}),
    llb.Dir("/home/build"),
    llb.AddEnv("PATH", "/usr/local/sbin:..."),
    llb.WithCustomName("Build the application"),
    // + cache mount options
).Root()
```

### Working Directory

The `working-directory` field maps to `llb.Dir()`:

```yaml
pipeline:
  - runs: make
    working-directory: src/myproject
```

Becomes:

```go
workdir := "/home/build/src/myproject"  // Relative paths joined with DefaultWorkDir
state.Run(
    llb.Args([]string{"/bin/sh", "-c", script}),
    llb.Dir(workdir),
).Root()
```

### Environment Variables

Environment from YAML is merged with base environment:

```yaml
environment:
  environment:
    GOPATH: /home/build/go
    CGO_ENABLED: "0"

pipeline:
  - runs: go build
    environment:
      GOOS: linux
```

Becomes:

```go
// Base environment (always present)
baseEnv := map[string]string{
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
}

// Merged with config environment
env := MergeEnv(baseEnv, map[string]string{
    "GOPATH":      "/home/build/go",
    "CGO_ENABLED": "0",
    "SOURCE_DATE_EPOCH": "...",
})

// Pipeline-specific environment merged last
env = MergeEnv(env, map[string]string{
    "GOOS": "linux",
})

// Added to run as sorted options (for determinism)
opts := SortedEnvOpts(env)  // Returns []llb.RunOption
```

### Conditional Execution

The `if` field is evaluated before converting to LLB:

```yaml
pipeline:
  - if: ${{build.arch}} == "x86_64"
    runs: |
      ./configure --enable-sse4
```

```go
func (b *PipelineBuilder) BuildPipeline(base llb.State, p *config.Pipeline) (llb.State, error) {
    if p.If != "" {
        shouldRun, err := cond.Evaluate(p.If)
        if err != nil {
            return llb.State{}, err
        }
        if !shouldRun {
            return base, nil  // Skip this pipeline, return unchanged state
        }
    }
    // ... continue building LLB
}
```

### Nested Pipelines

Nested pipelines inherit and extend the parent's environment:

```yaml
pipeline:
  - environment:
      FOO: bar
    pipeline:
      - runs: echo $FOO $BAZ
        environment:
          BAZ: qux
```

```go
// Parent pipeline sets up child builder with merged env
childBuilder := &PipelineBuilder{
    Debug:       b.Debug,
    BaseEnv:     MergeEnv(b.BaseEnv, p.Environment),  // Inherit + extend
    CacheMounts: b.CacheMounts,
}

// Child pipelines execute with inherited context
for i := range p.Pipeline {
    state, err = childBuilder.BuildPipeline(state, &p.Pipeline[i])
}
```

## Key Files

| File | Purpose |
|------|---------|
| `pkg/buildkit/builder.go` | High-level build orchestration |
| `pkg/buildkit/llb.go` | Pipeline to LLB conversion |
| `pkg/buildkit/image.go` | Loading apko layers into BuildKit |
| `pkg/buildkit/cache.go` | Cache mount definitions |
| `pkg/buildkit/determinism.go` | Ensuring reproducible LLB |
| `pkg/buildkit/client.go` | BuildKit client wrapper |
| `pkg/buildkit/progress.go` | Build progress display |
| `pkg/build/build_buildkit.go` | Integration with melange build system |

## Determinism

LLB graphs must be deterministic for caching to work. Key considerations:

1. **Environment variables are sorted** - Go map iteration is random, so we sort keys before adding to LLB
2. **Consistent naming** - Local mount names are derived from package names
3. **Stable ordering** - Pipelines are processed in array order

```go
// SortedEnvOpts ensures deterministic LLB regardless of map iteration order
func SortedEnvOpts(env map[string]string) []llb.RunOption {
    keys := slices.Sorted(maps.Keys(env))
    opts := make([]llb.RunOption, 0, len(keys))
    for _, k := range keys {
        opts = append(opts, llb.AddEnv(k, env[k]))
    }
    return opts
}
```

## Future Improvements

- **Issue #2**: Built-in pipeline support (fetch, git-checkout as native LLB operations)
- **Issue #3**: Interactive debug support via terminal injection
