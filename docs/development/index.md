# Development Guide

Welcome to the melange2 development guide. This documentation covers the architecture, testing, and contribution process for the project.

## Overview

melange2 is an experimental fork of [melange](https://github.com/chainguard-dev/melange) that uses BuildKit as the execution backend. The core innovation is converting YAML pipeline definitions into BuildKit LLB (Low-Level Build) operations.

**Module path:** `github.com/dlorenc/melange2`

## Getting Started

- [Development Environment](setup/development-environment.md) - Set up your local environment
- [IDE Setup](setup/ide-setup.md) - Configure your editor

## Architecture

- [Overview](architecture/overview.md) - System design and key concepts
- [BuildKit Integration](architecture/buildkit-integration.md) - How melange2 uses BuildKit
- [LLB Construction](architecture/llb-construction.md) - Pipeline to LLB conversion

## Testing

- [Testing Strategy](testing/testing-strategy.md) - Overview of test types
- [E2E Tests](testing/e2e-tests.md) - BuildKit integration tests
- [Comparison Tests](testing/comparison-tests.md) - Validation against Wolfi

## Contributing

- [Git Workflow](contributing/git-workflow.md) - Branches, PRs, and commits
- [Adding Pipelines](contributing/adding-pipelines.md) - Create new built-in pipelines
- [CI Pipeline](contributing/ci-pipeline.md) - What CI checks run

## Quick Reference

### Build & Test

```bash
# Build
go build -o melange2 .

# Unit tests (fast)
go test -short ./...

# E2E tests (requires Docker)
go test -v ./pkg/buildkit/...

# Lint
go vet ./...
```

### Key Directories

| Directory | Purpose |
|-----------|---------|
| `pkg/buildkit/` | BuildKit integration (core) |
| `pkg/build/` | Build orchestration |
| `pkg/cli/` | CLI commands |
| `pkg/config/` | YAML parsing |
| `pkg/build/pipelines/` | Built-in pipelines |

### Key Files

| File | Purpose |
|------|---------|
| `pkg/buildkit/builder.go` | Main build orchestration |
| `pkg/buildkit/llb.go` | Pipeline to LLB conversion |
| `pkg/buildkit/cache.go` | Cache mount definitions |
| `pkg/buildkit/progress.go` | Build progress display |
