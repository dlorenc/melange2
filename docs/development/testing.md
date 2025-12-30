# Testing Guide

This document covers the testing strategies and commands for melange2.

## Test Categories

melange2 uses three categories of tests:

| Category | Command | Duration | Requires |
|----------|---------|----------|----------|
| Unit Tests | `go test -short ./...` | ~2 min | Nothing |
| E2E Tests | `go test -v ./pkg/buildkit/...` | ~2 min | BuildKit |
| Comparison Tests | `make compare ...` | ~4 hr | BuildKit, Wolfi OS |

## Running Tests

### Unit Tests

Unit tests are fast and don't require external dependencies:

```bash
# Run all unit tests
go test -short ./...

# Run with race detection (slower but catches race conditions)
go test -v -race -short ./...

# Run with coverage
go test -v -race -short -coverprofile=coverage.out ./...
```

### E2E Tests

E2E tests require a running BuildKit daemon:

```bash
# Start BuildKit
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234

# Run E2E tests
go test -v ./pkg/buildkit/...

# Run specific E2E test
go test -v -run TestE2E_SimpleRun ./pkg/buildkit/...
```

### All Tests

```bash
# Run all tests (requires BuildKit)
go test ./...
```

## CI Pipeline

The CI workflow (`.github/workflows/ci.yaml`) runs these jobs:

| Job | Command | Duration | Description |
|-----|---------|----------|-------------|
| Build | `go build -v ./...` | ~30s | Compile all packages |
| Test | `go test -v -race -short -coverprofile=coverage.out ./...` | ~2min | Unit tests with coverage |
| E2E | `go test -v -coverprofile=e2e-coverage.out -run "TestE2E_..." ./pkg/buildkit/...` | ~2min | E2E tests |
| Lint | `golangci-lint run` | ~1min | Code linting |
| Verify | `go mod tidy && git diff --exit-code` | ~20s | Module verification |

### What Each Job Validates

- **Build**: Ensures all code compiles without errors
- **Test**: Runs unit tests with race detection; `-short` skips E2E tests
- **E2E**: Runs BuildKit integration tests using testcontainers (Docker required)
- **Lint**: Runs golangci-lint with project configuration
- **Verify**: Ensures `go.mod` and `go.sum` are up to date

All jobs must pass before merging a PR.

### Viewing CI Results

```bash
# List recent workflow runs
gh run list --limit 5

# View a specific run
gh run view <run-id>

# Watch a running workflow
gh run watch

# View failed job logs
gh run view <run-id> --log-failed
```

## E2E Test Framework

### Test Context

E2E tests use a shared context with BuildKit:

```go
type e2eTestContext struct {
    t          *testing.T
    ctx        context.Context
    bk         *buildKitContainer
    workingDir string
}

func newE2ETestContext(t *testing.T) *e2eTestContext {
    if testing.Short() {
        t.Skip("skipping e2e test in short mode")
    }
    ctx := context.Background()
    bk := startBuildKitContainer(t, ctx)
    workingDir := t.TempDir()
    return &e2eTestContext{t: t, ctx: ctx, bk: bk, workingDir: workingDir}
}
```

### Test Pattern

Typical E2E test structure:

```go
func TestE2E_FeatureName(t *testing.T) {
    // Create test context (starts BuildKit if needed)
    e := newE2ETestContext(t)

    // Load test configuration
    cfg := loadTestConfig(t, "XX-feature-name.yaml")

    // Execute build
    outDir, err := e.buildConfig(cfg)
    require.NoError(t, err, "build should succeed")

    // Verify outputs
    verifyFileExists(t, outDir, "package-name/path/to/expected/file")
    verifyFileContains(t, outDir, "package-name/path/to/file", "expected content")
}
```

### Test Fixtures

Test configurations are stored in `pkg/buildkit/testdata/e2e/`:

| File | Purpose |
|------|---------|
| `01-simple-run.yaml` | Basic shell command execution |
| `02-variable-substitution.yaml` | Package variable substitution |
| `03-environment-vars.yaml` | Environment variable handling |
| `04-subpackage-basic.yaml` | Basic subpackage handling |
| `05-working-directory.yaml` | Working directory handling |
| `06-multi-pipeline.yaml` | Multiple pipeline steps |
| `07-test-pipeline.yaml` | Test pipeline execution |
| `08-uses-pipeline.yaml` | Uses built-in pipeline |
| `09-conditional-if.yaml` | Conditional pipeline execution |
| `10-script-assertions.yaml` | Script assertions and chaining |
| `11-nested-pipelines.yaml` | Nested pipeline execution |
| `12-permissions.yaml` | File permissions and symlinks |
| `13-fetch-source.yaml` | Source fetching with checksums |
| `14-git-operations.yaml` | Git clone and checkout |
| `15-multiple-subpackages.yaml` | Multiple subpackage handling |
| `16-cache-mounts.yaml` | Cache mount isolation |
| `17-go-cache.yaml` | Go cache persistence |
| `18-python-cache.yaml` | Python pip cache |
| `19-node-cache.yaml` | Node.js npm cache |
| `20-rust-cache.yaml` | Rust cargo cache |
| `21-apk-cache.yaml` | APK package cache |
| `22-cache-dir.yaml` | Host cache directory |
| `23-autoconf-build.yaml` | Autoconf workflow |
| `24-cmake-build.yaml` | CMake workflow |
| `25-go-build.yaml` | Go build workflow |
| `26-simple-test.yaml` | Simple test pipeline |
| `27-subpackage-test-isolation.yaml` | Subpackage test isolation |
| `28-test-failure.yaml` | Test failure detection |
| `29-test-with-sources.yaml` | Test with source directory |

### Helper Functions

```go
// Load a test configuration from testdata/e2e/
func loadTestConfig(t *testing.T, name string) *config.Configuration

// Verify a file exists in the output directory
func verifyFileExists(t *testing.T, outDir, path string)

// Verify a file contains expected content
func verifyFileContains(t *testing.T, outDir, path, expected string)
```

## Adding New E2E Tests

### 1. Create Test Fixture

Create `pkg/buildkit/testdata/e2e/XX-feature-name.yaml`:

```yaml
package:
  name: feature-test
  version: 1.0.0
  epoch: 0
  description: Test for feature X
  copyright:
    - license: Apache-2.0

environment:
  contents:
    packages:
      - busybox

pipeline:
  - name: Test feature X
    runs: |
      mkdir -p ${{targets.destdir}}/usr/share/feature-test
      echo "feature output" > ${{targets.destdir}}/usr/share/feature-test/result.txt
```

### 2. Add Test Function

Add to `pkg/buildkit/e2e_test.go`:

```go
func TestE2E_FeatureName(t *testing.T) {
    e := newE2ETestContext(t)
    cfg := loadTestConfig(t, "XX-feature-name.yaml")

    outDir, err := e.buildConfig(cfg)
    require.NoError(t, err, "build should succeed")

    verifyFileExists(t, outDir, "feature-test/usr/share/feature-test/result.txt")
    verifyFileContains(t, outDir, "feature-test/usr/share/feature-test/result.txt", "feature output")
}
```

### 3. Run the Test

```bash
go test -v -run TestE2E_FeatureName ./pkg/buildkit/...
```

## Comparison Tests

Comparison tests validate melange2 builds against the Wolfi APK repository.

### Setup

```bash
# Clone the Wolfi OS repository
git clone --depth 1 https://github.com/wolfi-dev/os /tmp/wolfi-os
```

### Running Comparison Tests

```bash
# Compare specific packages
make compare WOLFI_OS_PATH=/tmp/wolfi-os PACKAGES="pkgconf scdoc"

# Compare packages from a file
make compare WOLFI_OS_PATH=/tmp/wolfi-os PACKAGES_FILE=packages.txt

# With custom BuildKit address
make compare WOLFI_OS_PATH=/tmp/wolfi-os PACKAGES="jq" BUILDKIT_ADDR=tcp://localhost:8372

# With specific architecture
make compare WOLFI_OS_PATH=/tmp/wolfi-os PACKAGES="jq" BUILD_ARCH=aarch64
```

### Makefile Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WOLFI_OS_PATH` | Path to wolfi-dev/os clone | (required) |
| `PACKAGES` | Space-separated packages | (required unless PACKAGES_FILE) |
| `PACKAGES_FILE` | File with package list | (required unless PACKAGES) |
| `BUILDKIT_ADDR` | BuildKit address | `tcp://localhost:8372` |
| `BUILD_ARCH` | Target architecture | `x86_64` |
| `KEEP_OUTPUTS` | Keep output directories | (unset) |

## Test Cache Mounts

Testing cache mount functionality requires multiple builds:

```go
func TestE2E_CacheMountPersistence(t *testing.T) {
    e := newE2ETestContext(t)
    cfg := loadTestConfig(t, "17-go-cache.yaml")

    cacheMounts := GoCacheMounts()

    // First build - populates cache
    outDir1, err := e.buildConfigWithCacheMounts(cfg, cacheMounts, map[string]string{"BUILD_ID": "1"})
    require.NoError(t, err)
    verifyFileContains(t, outDir1, "go-cache-test/usr/share/go-cache-test/mod-count.txt", "1")

    // Second build - should see cached data
    outDir2, err := e.buildConfigWithCacheMounts(cfg, cacheMounts, map[string]string{"BUILD_ID": "2"})
    require.NoError(t, err)
    verifyFileContains(t, outDir2, "go-cache-test/usr/share/go-cache-test/mod-count.txt", "2")
}
```

## Test Pipeline Execution

Testing test pipelines (as opposed to build pipelines):

```go
func TestE2E_SimpleTestPipeline(t *testing.T) {
    e := newE2ETestContext(t)
    cfg := loadTestConfig(t, "26-simple-test.yaml")

    outDir, err := e.testConfig(cfg)
    require.NoError(t, err, "test should succeed")

    // Verify test results were exported
    verifyFileExists(t, outDir, "test-results/simple-test/status.txt")
    verifyFileContains(t, outDir, "test-results/simple-test/status.txt", "PASSED")
}
```

## Troubleshooting Tests

### E2E Tests Skipped

If E2E tests are skipped, you're using `-short` flag:

```bash
# This skips E2E tests
go test -short ./pkg/buildkit/...

# This runs E2E tests
go test -v ./pkg/buildkit/...
```

### BuildKit Connection Issues

```bash
# Check if BuildKit is running
docker ps | grep buildkitd

# Restart BuildKit
docker restart buildkitd

# Check BuildKit logs
docker logs buildkitd
```

### Rate Limit Errors

Use cgr.dev images instead of Docker Hub:

```go
const TestBaseImage = "cgr.dev/chainguard/wolfi-base:latest"
```

### Timeout Issues

E2E tests may timeout on slow systems. The default timeout is 10 minutes for comparison tests:

```bash
go test -v -timeout 30m ./pkg/buildkit/...
```

## Coverage Reports

### Generate Coverage

```bash
go test -coverprofile=coverage.out ./...
```

### View Coverage

```bash
go tool cover -html=coverage.out
```

### Coverage in CI

The CI pipeline uploads coverage artifacts:

- `coverage-unit`: Unit test coverage
- `coverage-e2e`: E2E test coverage

## Linting

### Run Linter

```bash
make lint
# or
golangci-lint run
```

### Format Code

```bash
make fmt
# or
goimports -w $(find . -type f -name '*.go')
```

## Best Practices

1. **Skip E2E in unit test runs**: Use `testing.Short()` to skip E2E tests during quick iterations
2. **Use testify/require**: Fail fast on assertion failures
3. **Clean up resources**: Use `t.Cleanup()` for automatic cleanup
4. **Parallel tests**: E2E tests use shared BuildKit but can run concurrently
5. **Descriptive names**: Test function names should describe what they test
