# Architecture

This document describes the architecture of melange2, focusing on the BuildKit integration and core components.

## High-Level Architecture

melange2 converts YAML build definitions into BuildKit LLB operations:

```
YAML Config --> Config Parser --> Pipeline Builder --> LLB Graph --> BuildKit --> APK Output
```

## Core Components

### 1. Entry Point (`main.go`)

The CLI entry point creates a Cobra command tree and executes it:

```go
func main() {
    ctx, done := signal.NotifyContext(context.Background(), os.Interrupt)
    defer done()

    if err := cli.New().ExecuteContext(ctx); err != nil {
        clog.Error(err.Error())
        done()
        os.Exit(1)
    }
}
```

### 2. BuildKit Package (`pkg/buildkit/`)

The core of melange2 - converts pipelines to LLB operations.

#### Builder (`builder.go`)

The `Builder` struct manages the BuildKit connection and orchestrates builds:

```go
type Builder struct {
    client   *Client           // BuildKit client connection
    loader   *ImageLoader      // Loads apko layers into BuildKit
    pipeline *PipelineBuilder  // Converts pipelines to LLB

    ProgressMode ProgressMode  // Controls progress display
    ShowLogs     bool          // Enable stdout/stderr from build steps
}
```

**Key Methods:**

- `NewBuilder(addr string)`: Creates a new builder connected to BuildKit
- `Build(ctx, layer, cfg)`: Execute a single-layer build
- `BuildWithLayers(ctx, layers, cfg)`: Execute a multi-layer build (better caching)
- `Test(ctx, layer, cfg)`: Execute test pipelines
- `TestWithLayers(ctx, layers, cfg)`: Execute tests with multi-layer support

**Build Configuration:**

```go
type BuildConfig struct {
    PackageName     string                   // Package being built
    Arch            apko_types.Architecture  // Target architecture
    Pipelines       []config.Pipeline        // Main package pipelines
    Subpackages     []config.Subpackage      // Subpackage configurations
    BaseEnv         map[string]string        // Base environment variables
    SourceDir       string                   // Source files directory
    WorkspaceDir    string                   // Output directory
    CacheDir        string                   // Host cache directory
    Debug           bool                     // Enable shell debugging
    ExportOnFailure string                   // Debug export mode
    CacheConfig     *CacheConfig             // Remote cache configuration
}
```

#### LLB Construction (`llb.go`)

The `PipelineBuilder` converts melange pipelines to BuildKit LLB:

```go
type PipelineBuilder struct {
    Debug       bool                // Enable shell debugging (set -x)
    BaseEnv     map[string]string   // Base environment for all steps
    CacheMounts []CacheMount        // Cache mounts for build steps
}
```

**Key Constants:**

```go
const (
    DefaultWorkDir  = "/home/build"        // Default working directory
    MelangeOutDir   = "melange-out"        // Output directory name
    DefaultPath     = "/usr/local/sbin:..."// Default PATH
    DefaultCacheDir = "/var/cache/melange" // Cache directory
    BuildUserUID    = 1000                 // Build user UID
    BuildUserGID    = 1000                 // Build user GID
    BuildUserName   = "build"              // Build username
)
```

**LLB Operations:**

The builder creates LLB operations for:

1. **Workspace Preparation**: `PrepareWorkspace(state, pkgName)`
2. **Source Copying**: `CopySourceToWorkspace(state, localName)`
3. **Pipeline Execution**: `BuildPipeline(state, pipeline)`
4. **Export**: `ExportWorkspace(state)`

Each pipeline step becomes an LLB Run operation:

```go
state = state.Run(
    llb.Args([]string{"/bin/sh", "-c", script}),
    llb.Dir(workdir),
    llb.User(BuildUserName),  // Run as build user (UID 1000)
    // ... environment variables
    // ... cache mounts
).Root()
```

#### Cache Mounts (`cache.go`)

Defines persistent cache mounts for package managers:

```go
type CacheMount struct {
    ID     string                    // Unique cache identifier
    Target string                    // Mount path
    Mode   llb.CacheMountSharingMode // Shared, Private, or Locked
}
```

**Predefined Cache IDs:**

| Cache ID | Target Path | Purpose |
|----------|-------------|---------|
| `melange-go-mod-cache` | `/home/build/go/pkg/mod` | Go modules |
| `melange-go-build-cache` | `/home/build/.cache/go-build` | Go build cache |
| `melange-pip-cache` | `/home/build/.cache/pip` | Python pip |
| `melange-npm-cache` | `/home/build/.npm` | Node.js npm |
| `melange-cargo-registry-cache` | `/home/build/.cargo/registry` | Rust Cargo |
| `melange-ccache-cache` | `/home/build/.ccache` | C/C++ ccache |
| `melange-apk-cache` | `/var/cache/apk` | APK packages |

### 3. Configuration Package (`pkg/config/`)

Parses melange YAML configuration files:

```go
type Configuration struct {
    Package     Package          // Package metadata
    Environment Environment      // Build environment
    Pipeline    []Pipeline       // Build pipelines
    Subpackages []Subpackage     // Subpackage definitions
    Vars        map[string]string // Custom variables
    Test        *Test            // Test configuration
}

type Pipeline struct {
    Name        string            // Pipeline name
    Uses        string            // Built-in pipeline reference
    With        map[string]string // Pipeline inputs
    Runs        string            // Shell script to run
    Pipeline    []Pipeline        // Nested pipelines
    If          string            // Conditional execution
    WorkDir     string            // Working directory
    Environment map[string]string // Pipeline-specific environment
}
```

### 4. Service Package (`pkg/service/`)

Remote build infrastructure components.

#### API Server (`api/server.go`)

HTTP API for the build service:

```go
type Server struct {
    buildStore store.BuildStore  // Build state storage
    pool       *buildkit.Pool    // BuildKit backend pool
    mux        *http.ServeMux    // HTTP router
}
```

**Routes:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/builds` | GET | List builds |
| `/api/v1/builds` | POST | Submit new build |
| `/api/v1/builds/{id}` | GET | Get build status |
| `/api/v1/backends` | GET | List backends |
| `/api/v1/backends` | POST | Add backend |
| `/api/v1/backends/status` | GET | Get backend status |
| `/healthz` | GET | Health check |

#### BuildKit Pool (`buildkit/pool.go`)

Manages multiple BuildKit backends with throttling:

```go
type Pool struct {
    backends map[string]*Backend  // Address -> Backend
    throttle *Throttle            // Per-backend throttling
}

type Backend struct {
    Addr   string            // BuildKit address
    Arch   string            // Supported architecture
    Labels map[string]string // Backend labels
}
```

#### Scheduler (`scheduler/scheduler.go`)

Schedules and executes build jobs with dependency resolution.

#### Storage (`storage/`)

Artifact storage backends:

- `local.go`: Local filesystem storage
- `gcs.go`: Google Cloud Storage

## Build Flow

### 1. Configuration Parsing

```
melange.yaml --> config.ParseConfiguration() --> *config.Configuration
```

### 2. Environment Setup

```
apko layer(s) --> ImageLoader.LoadLayers() --> llb.State
```

### 3. Workspace Preparation

```
llb.State --> PrepareWorkspace() --> llb.State with /home/build structure
```

### 4. Pipeline Execution

For each pipeline:

```
llb.State --> PipelineBuilder.BuildPipeline() --> llb.State (modified)
```

The script wrapper:
```bash
set -ex  # (x only if debug enabled)
[ -d '/home/build' ] || mkdir -p '/home/build'
cd '/home/build'
<user script>
exit 0
```

### 5. Export

```
llb.State --> ExportWorkspace() --> llb.Scratch with melange-out contents
```

### 6. Solve

```
llb.State --> Marshal() --> *llb.Definition
*llb.Definition --> client.Solve() --> Output files
```

## Variable Substitution

melange2 supports variable substitution in YAML:

| Variable | Description |
|----------|-------------|
| `${{package.name}}` | Package name |
| `${{package.version}}` | Package version |
| `${{package.epoch}}` | Package epoch |
| `${{targets.destdir}}` | Output directory (`/home/build/melange-out/{pkg}`) |
| `${{targets.contextdir}}` | Build context (`/home/build`) |
| `${{targets.subpkgdir}}` | Subpackage output directory |
| `${{vars.*}}` | Custom variables |
| `${{inputs.*}}` | Pipeline inputs |

## Caching Strategy

### Layer Caching

BuildKit automatically caches LLB layers by content hash. Strategies:

1. **Multi-layer builds**: Split environment into layers that change at different rates
2. **Cache mounts**: Persist package manager caches between builds
3. **Remote cache**: Use registry-based cache for sharing across builds

### Remote Registry Cache

```go
type CacheConfig struct {
    Registry string  // e.g., "registry:5000/melange-cache"
    Mode     string  // "min" or "max"
}
```

- **min**: Export only final layers (smaller, faster)
- **max**: Export all intermediate layers (better hit rate)

## Security Model

### Build User

Builds run as non-root user (UID/GID 1000) for:

- Permission parity with baseline melange
- Consistent file ownership in outputs
- Security isolation

### File Permissions

- Workspace: 755 (build user writable)
- Cache directories: 755 (build user writable)
- Output files: Follow source permissions

## Error Handling

### Recovery on Failure

The `BuildPipelinesWithRecovery` method tracks the last successful state:

```go
type PipelineResult struct {
    State         llb.State  // Last good state
    FailedAtIndex int        // Index of failed pipeline (-1 if all succeeded)
    Error         error      // Error that occurred
}
```

This enables exporting a debug image of the environment before the failing step.

### Debug Image Export

On failure, the build environment can be exported as:

- `tarball`: Local tar file
- `docker`: Docker image
- `registry`: Push to container registry

## Extending melange2

### Adding a New CLI Command

1. Create `pkg/cli/newcmd.go`
2. Add command to root in `pkg/cli/root.go`
3. Implement using Cobra conventions

### Adding a New Storage Backend

1. Implement `storage.Backend` interface in `pkg/service/storage/`
2. Register in storage initialization

### Adding a New Pipeline

See [adding-pipelines.md](adding-pipelines.md) for detailed instructions.
