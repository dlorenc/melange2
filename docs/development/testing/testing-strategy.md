# Testing Strategy

melange2 uses multiple test types to ensure correctness.

## Test Types

| Type | Purpose | Requirements | Duration |
|------|---------|--------------|----------|
| Unit | Test individual functions | None | Fast (~2s) |
| E2E | Test BuildKit integration | Docker | Medium (~2min) |
| Comparison | Validate against Wolfi | Docker, wolfi-dev/os | Slow (~5-30min) |

## Running Tests

### Unit Tests

```bash
# All unit tests
go test -short ./...

# Specific package
go test -short ./pkg/config/...

# With verbose output
go test -short -v ./pkg/buildkit/...
```

### E2E Tests

```bash
# All E2E tests (requires Docker)
go test -v ./pkg/buildkit/...

# Specific E2E test
go test -v -run TestE2E_FetchSource ./pkg/buildkit/...

# E2E tests matching pattern
go test -v -run "TestE2E_.*Cache" ./pkg/buildkit/...
```

### Comparison Tests

```bash
# See docs/development/testing/comparison-tests.md
go test -v -tags=compare ./test/compare/... \
  -wolfi-os-path="/tmp/wolfi-os" \
  -buildkit-addr="tcp://localhost:1234"
```

## Test Organization

### Unit Tests

Located alongside source files:

```
pkg/config/
├── config.go
├── config_test.go    # Unit tests
├── parse.go
└── parse_test.go
```

Pattern:

```go
func TestFunctionName(t *testing.T) {
    // Arrange
    input := "test input"

    // Act
    result, err := FunctionUnderTest(input)

    // Assert
    require.NoError(t, err)
    require.Equal(t, expected, result)
}
```

### E2E Tests

Located in `pkg/buildkit/`:

```
pkg/buildkit/
├── e2e_test.go           # E2E test implementations
├── testdata/e2e/         # Test fixtures (YAML configs)
│   ├── 01-minimal.yaml
│   ├── 13-fetch-source.yaml
│   └── ...
└── apko_load_test.go     # BuildKit container helper
```

Pattern:

```go
func TestE2E_SomeFlow(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping e2e test in short mode")
    }

    e := newE2ETestContext(t)
    cfg := loadTestConfig(t, "XX-name.yaml")

    outDir, err := e.buildConfig(cfg)
    require.NoError(t, err)

    verifyFileExists(t, outDir, "expected/path")
    verifyFileContains(t, outDir, "file.txt", "expected content")
}
```

### Comparison Tests

Located in `test/compare/`:

```
test/compare/
├── compare_test.go    # Main test logic
├── apkindex.go        # APKINDEX parsing
├── fetch.go           # Package downloading
└── apkindex_test.go   # Unit tests for helpers
```

## Test Fixtures

### E2E Fixtures

Create in `pkg/buildkit/testdata/e2e/`:

```yaml
# XX-descriptive-name.yaml
package:
  name: test-package
  version: 1.0.0
  epoch: 0
  description: "Test description"
  copyright:
    - license: MIT

environment:
  contents:
    packages:
      - busybox

pipeline:
  - runs: |
      mkdir -p ${{targets.destdir}}/usr/bin
      echo "test" > ${{targets.destdir}}/usr/bin/test
```

Guidelines:
- Use `cgr.dev/chainguard/wolfi-base` to avoid Docker Hub rate limits
- Keep tests focused on one feature
- Include verification commands

## CI Integration

CI runs on GitHub Actions:

| Job | Tests | Duration |
|-----|-------|----------|
| Test | `go test -short ./...` | ~2min |
| E2E Tests | `go test ./pkg/buildkit/...` | ~2min |
| Lint | `golangci-lint run` | ~1min |

Tests must pass before merging.

## Best Practices

1. **Use `require` for fatal assertions, `assert` for non-fatal**
2. **Name tests descriptively**: `TestE2E_GoCache_PersistsBetweenBuilds`
3. **Skip E2E in short mode**: `if testing.Short() { t.Skip(...) }`
4. **Clean up resources**: Use `t.Cleanup()`
5. **Use table-driven tests** for multiple cases
6. **Keep fixtures minimal** - only what's needed to test the feature

## Coverage

```bash
# Generate coverage report
go test -coverprofile=coverage.out ./...

# View in browser
go tool cover -html=coverage.out

# Check coverage percentage
go tool cover -func=coverage.out | grep total
```
