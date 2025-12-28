# Architecture Overview

melange2 converts declarative YAML build configurations into BuildKit LLB operations for execution.

## High-Level Flow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  melange.yaml   │────▶│   LLB Builder   │────▶│    BuildKit     │
│  (pipelines)    │     │  (pkg/buildkit) │     │    Daemon       │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                        ┌─────────────────┐             │
                        │   APK Output    │◀────────────┘
                        │  (packages/)    │
                        └─────────────────┘
```

## Core Components

### pkg/buildkit/ - BuildKit Integration

The heart of melange2. Converts YAML pipelines to BuildKit LLB.

| File | Purpose |
|------|---------|
| `builder.go` | Main `Builder` struct and `Build()` method |
| `llb.go` | `PipelineBuilder` - converts pipelines to LLB |
| `cache.go` | Cache mount definitions |
| `image.go` | OCI image/layer handling |
| `progress.go` | Real-time build progress display |
| `client.go` | BuildKit client wrapper |
| `export.go` | Debug image export on failure |

### pkg/build/ - Build Orchestration

High-level build coordination inherited from upstream melange.

| File | Purpose |
|------|---------|
| `build.go` | Main build orchestration |
| `build_buildkit.go` | BuildKit-specific build logic |
| `options.go` | Build configuration options |
| `pipelines/` | Built-in pipeline YAML definitions |

### pkg/config/ - Configuration

YAML parsing and configuration structures.

| File | Purpose |
|------|---------|
| `config.go` | Main configuration types |
| `parse.go` | YAML parsing logic |
| `substitution.go` | Variable substitution |

### pkg/cli/ - Command Line

Cobra CLI commands.

| File | Purpose |
|------|---------|
| `build.go` | `melange build` command |
| `test.go` | `melange test` command |
| `keygen.go` | `melange keygen` command |

## Data Flow

### 1. Parse Configuration

```go
// pkg/config/
cfg, err := config.ParseConfiguration(ctx, "package.yaml")
// Returns: *config.Configuration with package, environment, pipeline
```

### 2. Create Build Environment

```go
// pkg/buildkit/image.go
layer, err := LoadApkoLayer(ctx, client, cfg)
// Returns: OCI layer with build environment packages
```

### 3. Construct LLB Graph

```go
// pkg/buildkit/llb.go
builder := NewPipelineBuilder()
state, err := builder.BuildPipeline(base, pipeline)
// Returns: llb.State representing the build
```

### 4. Execute via BuildKit

```go
// pkg/buildkit/builder.go
def, err := export.Marshal(ctx, llb.LinuxAmd64)
resp, err := client.Solve(ctx, def, solveOpt)
// BuildKit executes and exports results
```

### 5. Package Results

```go
// pkg/build/build.go
apk, err := tarball.Create(outDir, pkgName)
sign.Sign(apk, signingKey)
// Creates signed APK package
```

## Key Abstractions

### llb.State

BuildKit's immutable filesystem state. Operations return new states:

```go
state := llb.Image("alpine")
state = state.Run(llb.Args([]string{"apk", "add", "go"})).Root()
state = state.File(llb.Copy(src, "/app", "/app"))
```

### PipelineBuilder

Converts melange pipelines to LLB:

```go
type PipelineBuilder struct {
    Debug       bool
    BaseEnv     map[string]string
    CacheMounts []CacheMount
}

func (b *PipelineBuilder) BuildPipeline(base llb.State, p *config.Pipeline) (llb.State, error)
```

### CacheMount

Persistent volumes for package managers:

```go
type CacheMount struct {
    ID     string              // e.g., "melange-go-mod-cache"
    Target string              // e.g., "/go/pkg/mod"
    Mode   llb.CacheMountMode  // Shared, Private, or Locked
}
```

## Build User Context

Commands run as the `build` user (UID 1000) rather than root:

```go
llb.Run(
    llb.Args(cmd),
    llb.User("build"),
    llb.Dir("/home/build"),
)
```

This matches the upstream melange behavior and improves security.

## Related Documentation

- [BuildKit Integration](buildkit-integration.md) - Detailed BuildKit usage
- [LLB Construction](llb-construction.md) - Pipeline to LLB mapping
