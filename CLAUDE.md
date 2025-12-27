# CLAUDE.md - AI Agent Guide for melange2

This document helps AI agents work effectively on the melange2 codebase.

## Important: Git Workflow

**Always use branches and pull requests for changes.** Do not push directly to main.

```bash
# Create a feature branch
git checkout -b descriptive-branch-name

# Make changes and commit
git add -A
git commit -m "type: description

Details here.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"

# Push and create PR
git push -u origin descriptive-branch-name
gh pr create --title "type: description" --body "## Summary
..."
```

### Branch Protection

The `main` branch has protection rules:
- Changes must be made through pull requests
- Required status checks must pass (Build, Test, Lint)
- PRs should be reviewed before merging

### Commit Message Format

Use conventional commit prefixes:
- `feat:` - New features
- `fix:` - Bug fixes
- `test:` - Adding or updating tests
- `docs:` - Documentation changes
- `ci:` - CI/CD changes
- `refactor:` - Code refactoring

## Project Overview

melange2 is an experimental fork of [melange](https://github.com/chainguard-dev/melange) that uses BuildKit as the execution backend for building APK packages. It converts declarative YAML pipelines into BuildKit LLB operations.

**Module path:** `github.com/dlorenc/melange2`

## Repository Structure

```
.
├── pkg/                    # Main packages
│   ├── buildkit/          # BuildKit integration (core of melange2)
│   │   ├── builder.go     # Main Builder struct and Build() method
│   │   ├── client.go      # BuildKit client connection
│   │   ├── llb.go         # LLB graph construction
│   │   ├── image.go       # OCI image/layer handling
│   │   ├── progress.go    # Build progress display
│   │   └── e2e_test.go    # E2E tests using testcontainers
│   ├── build/             # Legacy build orchestration
│   │   └── pipelines/     # Builtin pipeline definitions (YAML)
│   ├── cli/               # CLI commands (build, test, etc.)
│   ├── config/            # YAML configuration parsing
│   ├── cond/              # Conditional expression evaluation
│   ├── container/         # Legacy container runners (bubblewrap, docker)
│   ├── sca/               # Software Composition Analysis
│   ├── sbom/              # SBOM generation
│   ├── sign/              # APK signing
│   ├── tarball/           # APK/tar file handling
│   └── source/            # Source fetching (fetch, git-checkout)
├── internal/              # Internal utilities
├── e2e-tests/             # End-to-end test packages
├── examples/              # Example melange configurations
├── docs/                  # Documentation
└── hack/                  # Development scripts
```

## Key Files

| File | Purpose |
|------|---------|
| `pkg/buildkit/builder.go` | Main BuildKit builder - converts configs to LLB |
| `pkg/buildkit/llb.go` | Pipeline to LLB conversion |
| `pkg/buildkit/progress.go` | Real-time build progress display |
| `pkg/config/config.go` | YAML configuration structures |
| `pkg/build/pipelines/*.yaml` | Builtin pipeline definitions |
| `pkg/cli/build.go` | `melange build` command |

## Development Commands

### Building

```bash
# Build the binary
go build -o melange2 .

# Build all packages
go build -v ./...
```

### Testing

```bash
# Run unit tests (fast, no Docker required)
go test -short ./...

# Run all tests including integration tests
go test ./...

# Run e2e tests only (requires Docker for testcontainers)
go test -v -run "TestE2E_" ./pkg/buildkit/...

# Run tests with coverage
go test -coverprofile=coverage.out ./...

# View coverage report
go tool cover -html=coverage.out
```

### Linting

```bash
# The project uses golangci-lint (latest version)
# Note: Local golangci-lint may have version issues
# CI uses: golangci/golangci-lint-action@v6 with version: latest

# Run go vet as alternative
go vet ./...
```

## CI Workflow

The CI runs on GitHub Actions (`.github/workflows/ci.yaml`) with these jobs:

| Job | Description | Duration |
|-----|-------------|----------|
| **Build** | Compiles all packages and binary | ~30s |
| **Test** | Unit tests with `-short` flag | ~2min |
| **E2E Tests** | BuildKit integration tests | ~2min |
| **Lint** | golangci-lint | ~1min |
| **Verify** | Checks go.mod is tidy | ~20s |

### E2E Tests in CI

E2E tests use testcontainers to automatically start BuildKit:
- Docker is available on GitHub Actions runners
- Tests skip with `-short` flag
- Each test gets its own BuildKit container

## Testing Patterns

### Unit Tests
```go
func TestSomething(t *testing.T) {
    // Use testify/require for assertions
    require.NoError(t, err)
    require.Equal(t, expected, actual)
}
```

### E2E Tests with BuildKit
```go
func TestE2E_SomeFlow(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping e2e test in short mode")
    }

    ctx := context.Background()
    bk := startBuildKitContainer(t, ctx)  // From apko_load_test.go

    // Use bk.Addr to connect to BuildKit
    c, err := client.New(ctx, bk.Addr)
    require.NoError(t, err)
    defer c.Close()

    // Build and verify...
}
```

### Test Fixtures

E2E test configs are in `pkg/buildkit/testdata/e2e/`:
- Simple YAML configs testing specific flows
- Use alpine as base image (fast, available)
- Avoid external dependencies

## Code Patterns

### Variable Substitution

Melange configs use `${{...}}` syntax:
```yaml
${{package.name}}        # Package name
${{package.version}}     # Package version
${{targets.destdir}}     # Output directory (/home/build/melange-out/PKG)
${{targets.contextdir}}  # Build context (/home/build)
${{vars.custom}}         # Custom variables
```

### Pipeline Environment

```go
// In pkg/buildkit/llb.go
pipeline := NewPipelineBuilder()
pipeline.BaseEnv["HOME"] = "/home/build"
pipeline.BaseEnv["CUSTOM_VAR"] = "value"
```

### LLB Construction

```go
// Start from base image
state := llb.Image("alpine:latest")

// Run commands
state = state.Run(
    llb.Args([]string{"/bin/sh", "-c", script}),
    llb.Dir(workdir),
    llb.AddEnv("KEY", "value"),
).Root()

// Export results
export := llb.Scratch().File(llb.Copy(state, "/output", "/"))
```

## Common Tasks

### Submitting Changes

1. **Create a branch:**
   ```bash
   git checkout -b feature-name
   ```

2. **Make changes and test locally:**
   ```bash
   go build ./...
   go test -short ./...
   go vet ./...
   ```

3. **Commit and push:**
   ```bash
   git add -A
   git commit -m "type: description"
   git push -u origin feature-name
   ```

4. **Create PR:**
   ```bash
   gh pr create --title "type: description" --body "## Summary
   - What changed
   - Why

   ## Test Plan
   - How it was tested
   "
   ```

5. **Monitor CI and iterate:**
   ```bash
   # Watch CI status
   gh run list --repo dlorenc/melange2 --limit 1

   # View run details
   gh run view <run-id> --repo dlorenc/melange2

   # Get failure logs
   gh run view <run-id> --repo dlorenc/melange2 --log-failed
   ```

6. **Fix any CI failures, commit, and push again.** CI will re-run automatically.

7. **Merge when CI passes:**
   ```bash
   gh pr merge <pr-number> --repo dlorenc/melange2 --squash
   ```

### Adding a New E2E Test

1. Create test fixture in `pkg/buildkit/testdata/e2e/XX-name.yaml`
2. Add test function in `pkg/buildkit/e2e_test.go`:
```go
func TestE2E_NewFlow(t *testing.T) {
    e := newE2ETestContext(t)
    cfg := loadTestConfig(t, "XX-name.yaml")

    outDir, err := e.buildConfig(cfg)
    require.NoError(t, err)

    verifyFileExists(t, outDir, "expected/path")
    verifyFileContains(t, outDir, "file.txt", "expected content")
}
```

### Adding a New Pipeline

1. Create YAML in `pkg/build/pipelines/category/name.yaml`
2. Pipeline structure:
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
      # Commands using ${{inputs.param}}
```

### Modifying BuildKit Integration

Key files:
- `pkg/buildkit/llb.go` - Pipeline to LLB conversion
- `pkg/buildkit/builder.go` - Build orchestration
- `pkg/buildkit/progress.go` - Progress display

## Debugging

### Build Failures

```bash
# Run with debug flag for verbose output
melange2 build package.yaml --buildkit-addr tcp://localhost:1234 --debug
```

### Test Failures

```bash
# Run specific test with verbose output
go test -v -run TestE2E_SpecificTest ./pkg/buildkit/...

# Check testcontainers logs
# Tests log BuildKit address: "BuildKit running at tcp://localhost:XXXXX"
```

## Dependencies

Key dependencies:
- `github.com/moby/buildkit` - BuildKit client and LLB
- `chainguard.dev/apko` - OCI image building
- `github.com/testcontainers/testcontainers-go` - E2E test infrastructure
- `github.com/stretchr/testify` - Test assertions

## Comparison Testing

The comparison test harness validates melange2 against upstream melange by building the same packages and comparing results. See [docs/COMPARISON-TESTING.md](docs/COMPARISON-TESTING.md) for full documentation.

### Quick Start

```bash
# Start BuildKit (correct command - don't double 'buildkitd')
docker run -d --name buildkitd --privileged -p 8372:8372 \
  moby/buildkit:latest --addr tcp://0.0.0.0:8372

# Run comparison (use aarch64 on ARM Macs for speed)
go test -v -tags=compare ./test/compare/... \
  -wolfi-repo="/tmp/melange-compare/os" \
  -baseline-melange="/tmp/melange-compare/melange-upstream" \
  -buildkit-addr="tcp://localhost:8372" \
  -arch="aarch64" \
  -packages="pkgconf,scdoc,jq"
```

Key files:
- `test/compare/compare_test.go` - Comparison test implementation
- `docs/COMPARISON-TESTING.md` - Full documentation

Progress tracking: [GitHub Issue #32](https://github.com/dlorenc/melange2/issues/32)

## Open Issues

Check GitHub issues for current work:
```bash
gh issue list --repo dlorenc/melange2 --state open
```

Key tracking issues:
- #4 - Test coverage improvements
- #8-12 - Specific test additions needed
- #32 - Comparison testing validation
