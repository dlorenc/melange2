# Testing Guide

This document covers the testing strategies and commands for melange2.

## Test Categories

melange2 uses three categories of tests:

| Category | Command | Duration | Requires |
|----------|---------|----------|----------|
| Unit Tests | `go test -short ./...` | ~2 min | Nothing |
| E2E Tests | `go test -v ./e2e/...` | ~3 min | Docker (testcontainers) |
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

E2E tests use testcontainers to automatically spin up BuildKit and other dependencies:

```bash
# Run all E2E tests
go test -v ./e2e/...

# Run specific test category
go test -v -run TestBuild ./e2e/...     # Build tests
go test -v -run TestRemote ./e2e/...    # Remote build tests
go test -v -run TestTestPipeline ./e2e/... # Test pipeline tests

# Run with verbose output
go test -v -count=1 ./e2e/...
```

### All Tests

```bash
# Run all tests (requires Docker for E2E)
go test ./...
```

## CI Pipeline

The CI workflow (`.github/workflows/ci.yaml`) runs these jobs:

| Job | Command | Duration | Description |
|-----|---------|----------|-------------|
| Build | `go build -v ./...` | ~30s | Compile all packages |
| Test | `go test -v -race -short -coverprofile=coverage.out ./...` | ~2min | Unit tests with coverage |
| E2E | `go test -v -coverprofile=e2e-coverage.out ./e2e/...` | ~3min | E2E tests with testcontainers |
| Lint | `golangci-lint run` | ~1min | Code linting |
| Verify | `go mod tidy && git diff --exit-code` | ~20s | Module verification |

## E2E Test Framework

### Architecture

The E2E test framework is located in `e2e/` and has this structure:

```
e2e/
├── DESIGN.md           # Framework design document
├── harness/
│   ├── harness.go      # Test harness (BuildKit, registry, server)
│   ├── buildkit.go     # BuildKit testcontainer management
│   ├── registry.go     # Registry testcontainer management
│   └── assertions.go   # Common test assertions
├── fixtures/
│   ├── build/          # Build test fixtures
│   ├── test/           # Test pipeline fixtures
│   └── remote/         # Remote build fixtures
├── build_test.go       # Local build tests
├── test_test.go        # Test pipeline tests
└── remote_test.go      # Remote build tests
```

### Test Harness

The test harness manages infrastructure:

```go
// Create a basic harness with BuildKit
h := harness.New(t)
addr := h.BuildKitAddr()

// Create a harness with in-process server
h := harness.New(t, harness.WithServer())
client := h.Client()

// Create a harness with registry
h := harness.New(t, harness.WithServer(), harness.WithRegistry())
```

The harness automatically:
- Starts BuildKit via testcontainers
- Starts optional registry via testcontainers
- Runs the melange server in-process (for coverage measurement)
- Cleans up on test completion

### Test Categories

#### Build Tests (`build_test.go`)

Test local build functionality:

| Test | Description |
|------|-------------|
| `TestBuild_Simple` | Basic shell command execution |
| `TestBuild_Variables` | Package variable substitution |
| `TestBuild_Environment` | Environment variable propagation |
| `TestBuild_WorkingDirectory` | Working directory handling |
| `TestBuild_MultiPipeline` | Sequential pipeline execution |
| `TestBuild_Conditional` | if: conditions |
| `TestBuild_Subpackages` | Multiple package outputs |
| `TestBuild_FullIntegration` | Full build path |

#### Remote Tests (`remote_test.go`)

Test remote build server:

| Test | Description |
|------|-------------|
| `TestRemote_HealthCheck` | Server health endpoint |
| `TestRemote_ListBackends` | Backend listing |
| `TestRemote_BackendManagement` | Add/remove backends |
| `TestRemote_SinglePackageBuild` | Single package submission |
| `TestRemote_MultiPackageBuild` | Multi-package (flat mode) |
| `TestRemote_DAGModeBuild` | Dependency-ordered builds |
| `TestRemote_BuildStatusPolling` | Status updates |
| `TestRemote_ListBuilds` | Build listing |

#### Test Pipeline Tests (`test_test.go`)

Test `melange test` functionality:

| Test | Description |
|------|-------------|
| `TestTestPipeline_Simple` | Basic test execution |
| `TestTestPipeline_SubpackageIsolation` | Subpackage isolation |
| `TestTestPipeline_FailureDetection` | Failure reporting |
| `TestTestPipeline_NoTests` | No-test handling |

### Test Fixtures

Fixtures are in `e2e/fixtures/`:

#### Build Fixtures (`fixtures/build/`)
| File | Purpose |
|------|---------|
| `simple.yaml` | Basic shell commands |
| `variables.yaml` | Variable substitution |
| `environment.yaml` | Environment variables |
| `workdir.yaml` | Working directory |
| `multi-pipeline.yaml` | Sequential pipelines |
| `conditional.yaml` | Conditional pipelines |
| `subpackages.yaml` | Multi-package builds |

#### Test Fixtures (`fixtures/test/`)
| File | Purpose |
|------|---------|
| `simple-test.yaml` | Basic test pipeline |
| `isolation.yaml` | Subpackage isolation |
| `failure.yaml` | Failure detection |

#### Remote Fixtures (`fixtures/remote/`)
| File | Purpose |
|------|---------|
| `simple.yaml` | Basic remote build |

### Helper Functions

The harness provides assertion helpers:

```go
// Check file exists
harness.FileExists(t, outDir, "path/to/file")

// Check file does not exist
harness.FileNotExists(t, outDir, "path/to/file")

// Check file contains string
harness.FileContains(t, outDir, "path/to/file", "expected content")

// Check file does not contain string
harness.FileNotContains(t, outDir, "path/to/file", "unexpected")

// Check multiple files exist
harness.FilesExist(t, outDir, "file1", "file2", "file3")

// Read file content
content := harness.ReadFile(t, outDir, "path/to/file")
```

## Adding New E2E Tests

### 1. Create Test Fixture

Create a fixture in the appropriate directory:

```yaml
# e2e/fixtures/build/my-feature.yaml
package:
  name: my-feature-test
  version: 1.0.0

pipeline:
  - runs: |
      mkdir -p "${{targets.destdir}}/usr/share/my-feature"
      echo "test output" > "${{targets.destdir}}/usr/share/my-feature/result.txt"
```

### 2. Add Test Function

Add to the appropriate test file:

```go
// e2e/build_test.go
func TestBuild_MyFeature(t *testing.T) {
    c := newBuildTestContext(t)
    cfg := c.loadConfig("my-feature.yaml")

    outDir := c.buildConfig(cfg)

    harness.FileExists(t, outDir, "my-feature-test/usr/share/my-feature/result.txt")
    harness.FileContains(t, outDir, "my-feature-test/usr/share/my-feature/result.txt", "test output")
}
```

### 3. Run the Test

```bash
go test -v -run TestBuild_MyFeature ./e2e/...
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
```

## Coverage

### Generate Coverage

```bash
# E2E tests run server in-process for coverage measurement
go test -coverprofile=coverage.out ./e2e/... ./pkg/...

# View coverage report
go tool cover -html=coverage.out
```

### Coverage in CI

The CI pipeline uploads coverage artifacts:
- `coverage-unit`: Unit test coverage
- `coverage-e2e`: E2E test coverage

## Troubleshooting

### E2E Tests Skipped

If E2E tests are skipped, you're using `-short` flag:

```bash
# This skips E2E tests
go test -short ./e2e/...

# This runs E2E tests
go test -v ./e2e/...
```

### Docker Not Available

E2E tests require Docker for testcontainers:

```bash
# Check Docker is running
docker info

# Run Docker daemon if not running
sudo systemctl start docker
```

### Rate Limit Errors

The tests use `cgr.dev/chainguard/wolfi-base` to avoid Docker Hub rate limits.

### Timeout Issues

E2E tests may timeout on slow systems:

```bash
go test -v -timeout 30m ./e2e/...
```

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

1. **Skip E2E in unit test runs**: Use `testing.Short()` to skip E2E tests
2. **Use testify/require**: Fail fast on assertion failures
3. **Clean up resources**: The harness handles cleanup automatically
4. **Use in-process server**: Remote tests run the server in-process for coverage
5. **Descriptive names**: Test function names should describe what they test
6. **Isolated fixtures**: Each test uses its own fixture file
