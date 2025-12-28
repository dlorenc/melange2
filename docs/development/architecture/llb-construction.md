# LLB Construction

This document explains how melange2 converts YAML pipelines into BuildKit LLB operations.

## LLB Overview

LLB (Low-Level Build) is BuildKit's intermediate representation. It's a directed acyclic graph (DAG) where:

- Nodes are filesystem states or operations
- Edges represent dependencies
- Leaves are exports or final states

## Pipeline to LLB Mapping

### runs

Shell commands become `llb.Run()`:

```yaml
pipeline:
  - name: Build the application
    runs: |
      go build -o myapp .
```

Becomes:

```go
state = state.Run(
    llb.Args([]string{"/bin/sh", "-c", `set -e
[ -d '/home/build' ] || mkdir -p '/home/build'
cd '/home/build'
go build -o myapp .
exit 0`}),
    llb.Dir("/home/build"),
    llb.User("build"),
    llb.WithCustomName("Build the application"),
    // Environment variables...
    // Cache mounts...
).Root()
```

### uses

Built-in pipelines are expanded and converted:

```yaml
pipeline:
  - uses: go/build
    with:
      packages: ./cmd/app
      output: myapp
```

The pipeline YAML is loaded, inputs substituted, and converted to LLB.

### working-directory

Maps to `llb.Dir()`:

```yaml
pipeline:
  - runs: make
    working-directory: src/myproject
```

Becomes:

```go
workdir := "/home/build/src/myproject"  // Relative paths joined with DefaultWorkDir
state = state.Run(
    llb.Args(cmd),
    llb.Dir(workdir),
).Root()
```

### environment

Merged with base environment:

```yaml
pipeline:
  - runs: go build
    environment:
      CGO_ENABLED: "0"
```

Becomes:

```go
env := MergeEnv(baseEnv, map[string]string{
    "CGO_ENABLED": "0",
})
opts := SortedEnvOpts(env)  // Sorted for determinism
state = state.Run(opts...).Root()
```

### if (conditionals)

Evaluated before LLB construction:

```yaml
pipeline:
  - if: ${{build.arch}} == "x86_64"
    runs: ./configure --enable-sse4
```

```go
func (b *PipelineBuilder) BuildPipeline(base llb.State, p *config.Pipeline) (llb.State, error) {
    if p.If != "" {
        shouldRun, err := cond.Evaluate(p.If)
        if err != nil {
            return llb.State{}, err
        }
        if !shouldRun {
            return base, nil  // Skip this step
        }
    }
    // Continue building LLB...
}
```

### Nested pipelines

Child pipelines inherit parent environment:

```yaml
pipeline:
  - environment:
      FOO: bar
    pipeline:
      - runs: echo $FOO
```

```go
childBuilder := &PipelineBuilder{
    Debug:       b.Debug,
    BaseEnv:     MergeEnv(b.BaseEnv, p.Environment),  // Inherit + extend
    CacheMounts: b.CacheMounts,
}

for i := range p.Pipeline {
    state, err = childBuilder.BuildPipeline(state, &p.Pipeline[i])
}
```

## LLB Graph Structure

A typical build produces this graph:

```
┌─────────────┐
│   Scratch   │  (empty filesystem)
└──────┬──────┘
       │
       ▼
┌────────────────────────┐
│  llb.Copy(apko-layer)  │  Copy build environment
└────────────┬───────────┘
       │
       ▼
┌────────────────────────┐
│  llb.Mkdir(/home/build)│  Create workspace
└────────────┬───────────┘
       │
       ▼
┌────────────────────────┐
│  llb.Copy(source)      │  Copy source files
└────────────┬───────────┘
       │
       ▼
┌────────────────────────┐
│  llb.Run(pipeline[0])  │  First pipeline step
└────────────┬───────────┘
       │
       ▼
┌────────────────────────┐
│  llb.Run(pipeline[1])  │  Second pipeline step
└────────────┬───────────┘
       │
       ▼
┌────────────────────────┐
│  ExportWorkspace       │  Copy melange-out to export
└────────────────────────┘
```

## Workspace Layout

During build:

```
/home/build/                     # DefaultWorkDir - working directory
├── <source files>               # Copied from --source-dir
└── melange-out/                 # MelangeOutDir - output directory
    ├── {package-name}/          # Main package output
    │   └── usr/bin/myapp
    └── {subpackage-name}/       # Subpackage outputs
        └── usr/share/doc/
```

## Export Process

Only melange-out is exported:

```go
func ExportWorkspace(state llb.State) llb.State {
    melangeOutPath := filepath.Join(DefaultWorkDir, MelangeOutDir)
    return llb.Scratch().File(
        llb.Copy(state, melangeOutPath, "/", &llb.CopyInfo{
            CopyDirContentsOnly: true,
        }),
    )
}
```

## Key Files

| File | Purpose |
|------|---------|
| `pkg/buildkit/llb.go` | `PipelineBuilder` and LLB construction |
| `pkg/buildkit/builder.go` | High-level build orchestration |
| `pkg/buildkit/cache.go` | Cache mount definitions |
| `pkg/buildkit/determinism.go` | Ensuring reproducible LLB |
