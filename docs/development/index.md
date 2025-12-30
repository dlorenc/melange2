# melange2 Development Guide

This guide provides comprehensive documentation for developing and contributing to melange2, an experimental BuildKit-based APK package builder.

## Overview

melange2 is a fork of the original melange project that uses BuildKit for container-based package builds. The core innovation is converting YAML pipeline definitions to BuildKit LLB (Low-Level Builder) operations, enabling:

- Efficient caching through BuildKit's content-addressable storage
- Multi-layer build environments for better cache efficiency
- Remote build execution via the melange-server component
- Parallel build execution with dependency resolution

## Module Information

- **Module Path**: `github.com/dlorenc/melange2`
- **Go Version**: 1.24.6
- **License**: Apache License 2.0

## Architecture Overview

```
+------------------+     +------------------+     +------------------+
|   CLI (melange2) | --> |   pkg/build      | --> |   pkg/buildkit   |
|                  |     |   Orchestration  |     |   LLB Generation |
+------------------+     +------------------+     +------------------+
         |                        |                        |
         v                        v                        v
+------------------+     +------------------+     +------------------+
|   pkg/config     |     |   pkg/build/     |     |   BuildKit       |
|   YAML Parsing   |     |   pipelines/     |     |   Daemon         |
+------------------+     |   Built-in YAML  |     +------------------+
                         +------------------+

+------------------+     +------------------+     +------------------+
| melange-server   | --> |   pkg/service/   | --> |   BuildKit Pool  |
|  (cmd/melange-   |     |   - api/         |     |   (Multiple      |
|   server/)       |     |   - scheduler/   |     |    backends)     |
+------------------+     |   - storage/     |     +------------------+
                         |   - store/       |
                         +------------------+
```

## Repository Structure

```
.
+-- main.go                    # CLI entry point
+-- cmd/
|   +-- melange-server/        # Build service entry point
+-- pkg/
|   +-- buildkit/              # CORE: BuildKit integration
|   |   +-- builder.go         # Main Build() method
|   |   +-- llb.go             # Pipeline -> LLB conversion
|   |   +-- cache.go           # Cache mount definitions
|   |   +-- progress.go        # Build progress display
|   |   +-- e2e_test.go        # E2E tests
|   +-- build/                 # Build orchestration
|   |   +-- pipelines/         # Built-in pipeline YAMLs
|   +-- cli/                   # CLI commands
|   +-- config/                # YAML config parsing
|   +-- service/               # melange-server components
|       +-- api/               # HTTP API handlers
|       +-- scheduler/         # Job scheduling
|       +-- storage/           # Storage backends (local, GCS)
|       +-- store/             # Job store (memory)
|       +-- types/             # Service types
+-- deploy/
|   +-- kind/                  # Local Kind cluster deployment
|   +-- gke/                   # GKE deployment with GCS storage
+-- docs/                      # Documentation
+-- examples/                  # Example build files
+-- test/compare/              # Comparison tests vs Wolfi
```

## Key Components

### 1. BuildKit Package (`pkg/buildkit/`)

The core of melange2 - converts melange YAML pipelines to BuildKit LLB operations:

- **builder.go**: Main `Builder` struct with `Build()` and `Test()` methods
- **llb.go**: `PipelineBuilder` that converts pipelines to LLB
- **cache.go**: Cache mount configurations for Go, Python, Rust, Node.js, etc.
- **progress.go**: Build progress display

### 2. Service Package (`pkg/service/`)

Remote build infrastructure components:

- **api/**: HTTP API server for job submission and status
- **scheduler/**: Job scheduling and execution
- **buildkit/pool.go**: BuildKit backend pool management with throttling
- **storage/**: Artifact storage (local filesystem, GCS)
- **store/**: Build state store (in-memory, planned: PostgreSQL)

### 3. Configuration Package (`pkg/config/`)

YAML configuration parsing for melange build definitions.

### 4. CLI Package (`pkg/cli/`)

Command-line interface implementation using Cobra.

## Documentation Index

| Document | Description |
|----------|-------------|
| [setup.md](setup.md) | Development environment setup |
| [architecture.md](architecture.md) | Detailed architecture and code flow |
| [testing.md](testing.md) | Testing strategies and commands |
| [adding-pipelines.md](adding-pipelines.md) | Contributing new pipelines |
| [git-workflow.md](git-workflow.md) | Git branching and PR process |

## Key Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/moby/buildkit` | BuildKit client and LLB construction |
| `chainguard.dev/apko` | OCI image building |
| `github.com/spf13/cobra` | CLI framework |
| `github.com/stretchr/testify` | Test assertions |
| `github.com/testcontainers/testcontainers-go` | E2E test infrastructure |
| `cloud.google.com/go/storage` | GCS storage backend |

## Quick Start for Contributors

```bash
# Clone the repository
git clone https://github.com/dlorenc/melange2.git
cd melange2

# Build the binary
go build -o melange2 .

# Run unit tests
go test -short ./...

# Start BuildKit for E2E tests
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234

# Run E2E tests
go test -v ./pkg/buildkit/...

# Build a package
./melange2 build examples/minimal.yaml --buildkit-addr tcp://localhost:1234
```

## Current Focus Areas

- **Issue #32**: Comparison testing validation against Wolfi packages
- **Issue #4**: Improving test coverage

## Getting Help

- Review the documentation in this directory
- Check existing issues on GitHub
- Review the CLAUDE.md file for AI agent guidance
