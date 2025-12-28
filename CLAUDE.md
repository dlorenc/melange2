# CLAUDE.md - AI Agent Guide for melange2

This document is optimized for AI agents working on the melange2 codebase.

## Quick Reference

| Task | Command |
|------|---------|
| Build binary | `go build -o melange2 .` |
| Unit tests | `go test -short ./...` |
| E2E tests | `go test -v ./pkg/buildkit/...` |
| All tests | `go test ./...` |
| Lint | `go vet ./...` |
| Build package | `./melange2 build pkg.yaml --buildkit-addr tcp://localhost:1234` |
| Debug build | `./melange2 build pkg.yaml --buildkit-addr tcp://localhost:1234 --debug` |

## Git Workflow (CRITICAL)

**Never push directly to main. Always use branches and PRs.**

```bash
# Create branch
git checkout -b feat/description

# Commit (use conventional prefixes: feat/fix/docs/test/refactor/ci)
git add -A && git commit -m "feat: description"

# Push and create PR
git push -u origin feat/description
gh pr create --title "feat: description" --body "## Summary
- Changes made

## Test Plan
- How tested"
```

### Commit Message Format
```
type: short description

Longer explanation if needed.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
```

## Project Overview

- **What**: BuildKit-based APK package builder (experimental fork of melange)
- **Module**: `github.com/dlorenc/melange2`
- **Core Innovation**: Converts YAML pipelines to BuildKit LLB operations

## Repository Map

```
.
├── pkg/buildkit/          # CORE - BuildKit integration
│   ├── builder.go         # Main Build() method
│   ├── llb.go             # Pipeline → LLB conversion
│   ├── cache.go           # Cache mount definitions
│   ├── progress.go        # Build progress display
│   └── e2e_test.go        # E2E tests
├── pkg/build/             # Build orchestration
│   └── pipelines/         # Built-in pipeline YAMLs
├── pkg/cli/               # CLI commands (build, test, etc.)
├── pkg/config/            # YAML config parsing
├── docs/
│   ├── user-guide/        # End-user documentation
│   └── development/       # Developer documentation
├── examples/              # Example build files
└── test/compare/          # Comparison tests vs Wolfi
```

## Key Files by Task

| Task | Read These Files |
|------|------------------|
| Modify build process | `pkg/buildkit/builder.go`, `pkg/buildkit/llb.go` |
| Add CLI flag | `pkg/cli/build.go` |
| Add built-in pipeline | `pkg/build/pipelines/{category}/{name}.yaml` |
| Debug test failures | `pkg/buildkit/e2e_test.go` |
| Understand caching | `pkg/buildkit/cache.go` |
| Config parsing | `pkg/config/config.go` |

## Common Tasks

### Start BuildKit
```bash
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234
```

### Add E2E Test
1. Create fixture: `pkg/buildkit/testdata/e2e/XX-name.yaml`
2. Add test function in `pkg/buildkit/e2e_test.go`:
```go
func TestE2E_Name(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping e2e test in short mode")
    }
    e := newE2ETestContext(t)
    cfg := loadTestConfig(t, "XX-name.yaml")
    outDir, err := e.buildConfig(cfg)
    require.NoError(t, err)
    verifyFileExists(t, outDir, "expected/path")
}
```

### Add Built-in Pipeline
1. Create `pkg/build/pipelines/category/name.yaml`:
```yaml
name: Pipeline name
needs:
  packages:
    - required-package
inputs:
  param:
    description: Parameter description
    default: default-value
pipeline:
  - runs: |
      echo ${{inputs.param}}
```
2. Rebuild: `go build -o melange2 .`

### Run Comparison Tests
```bash
git clone --depth 1 https://github.com/wolfi-dev/os /tmp/wolfi-os
go test -v -tags=compare ./test/compare/... \
  -wolfi-os-path="/tmp/wolfi-os" \
  -buildkit-addr="tcp://localhost:1234" \
  -arch="aarch64" \
  -packages="pkgconf,scdoc"
```

## Code Patterns

### Variable Substitution (YAML)
```yaml
${{package.name}}        # Package name
${{package.version}}     # Package version
${{targets.destdir}}     # Output directory
${{build.arch}}          # Target architecture
${{vars.custom}}         # Custom variable
```

### LLB Construction (Go)
```go
// Run command
state = state.Run(
    llb.Args([]string{"/bin/sh", "-c", script}),
    llb.Dir("/home/build"),
    llb.User("build"),
).Root()

// Add cache mount
state = state.Run(
    llb.Args(cmd),
    llb.AddMount("/go/pkg/mod", llb.Scratch(),
        llb.AsPersistentCacheDir("melange-go-mod-cache", llb.CacheMountShared)),
).Root()
```

### Environment Variables (deterministic)
```go
// Sort keys for reproducible LLB
keys := slices.Sorted(maps.Keys(env))
for _, k := range keys {
    opts = append(opts, llb.AddEnv(k, env[k]))
}
```

## CI Jobs

| Job | Command | Duration |
|-----|---------|----------|
| Build | `go build -v ./...` | ~30s |
| Test | `go test -short ./...` | ~2min |
| E2E | `go test ./pkg/buildkit/...` | ~2min |
| Lint | `golangci-lint run` | ~1min |
| Verify | `go mod tidy && git diff` | ~20s |

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| "connection reset by peer" | Wrong BuildKit command | `docker rm -f buildkitd && docker run -d --name buildkitd --privileged -p 1234:1234 moby/buildkit:latest --addr tcp://0.0.0.0:1234` |
| "connection refused" | BuildKit not running | `docker start buildkitd` |
| Test timeout | BuildKit unresponsive | `docker restart buildkitd` |
| E2E test skipped | Using `-short` flag | Remove `-short` to run E2E tests |
| Rate limit errors | Docker Hub limits | Use `cgr.dev/chainguard/wolfi-base` images |
| Permission denied in cache | Cache mount ownership | Cache mounts use build user (UID 1000) |

## What NOT to Do

- **Don't push to main** - Always use PRs
- **Don't use `-i` with git** - Interactive mode not supported
- **Don't skip hooks** - No `--no-verify`
- **Don't force push to main** - Even if asked
- **Don't include timestamps** - Breaks cache determinism
- **Don't use Docker Hub for tests** - Rate limits; use cgr.dev

## Current Focus Areas

- Issue #32: Comparison testing validation
- Issue #4: Test coverage improvements

## Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/moby/buildkit` | BuildKit client and LLB |
| `chainguard.dev/apko` | OCI image building |
| `github.com/testcontainers/testcontainers-go` | E2E test infrastructure |
| `github.com/stretchr/testify` | Test assertions |

## File Locations

| What | Where |
|------|-------|
| E2E test fixtures | `pkg/buildkit/testdata/e2e/*.yaml` |
| Built-in pipelines | `pkg/build/pipelines/**/*.yaml` |
| CLI commands | `pkg/cli/*.go` |
| Example configs | `examples/*.yaml` |
| User docs | `docs/user-guide/` |
| Dev docs | `docs/development/` |
