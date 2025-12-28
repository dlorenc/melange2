# E2E Tests

End-to-end tests verify the complete BuildKit integration.

## How E2E Tests Work

1. Start a BuildKit container using testcontainers
2. Load a test YAML configuration
3. Build the package via BuildKit
4. Verify the output files

## Running E2E Tests

```bash
# All E2E tests
go test -v ./pkg/buildkit/...

# Specific test
go test -v -run TestE2E_FetchSource ./pkg/buildkit/...

# Skip E2E tests (unit tests only)
go test -short ./...
```

## Test Structure

### Test File

Tests are in `pkg/buildkit/e2e_test.go`:

```go
func TestE2E_FetchSource(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping e2e test in short mode")
    }

    e := newE2ETestContext(t)
    cfg := loadTestConfig(t, "13-fetch-source.yaml")

    outDir, err := e.buildConfig(cfg)
    require.NoError(t, err)

    verifyFileExists(t, outDir, "test-package/usr/share/hello.txt")
    verifyFileContains(t, outDir, "test-package/usr/share/hello.txt", "Hello")
}
```

### Test Context

`newE2ETestContext()` handles:
- Starting BuildKit container
- Creating temp directories
- Cleanup after test

### Test Fixtures

Located in `pkg/buildkit/testdata/e2e/`:

```yaml
# 13-fetch-source.yaml
package:
  name: test-package
  version: 1.0.0
  epoch: 0
  description: "Test fetch pipeline"
  copyright:
    - license: MIT

environment:
  contents:
    packages:
      - busybox
      - wget

pipeline:
  - uses: fetch
    with:
      uri: https://example.com/file.tar.gz
      expected-sha256: abc123...

  - runs: |
      cp hello.txt ${{targets.destdir}}/usr/share/
```

## Adding a New E2E Test

### 1. Create Test Fixture

Create `pkg/buildkit/testdata/e2e/XX-descriptive-name.yaml`:

```yaml
package:
  name: test-my-feature
  version: 1.0.0
  epoch: 0
  description: "Test my feature"
  copyright:
    - license: MIT

environment:
  contents:
    packages:
      - busybox

pipeline:
  - runs: |
      # Test your feature
      mkdir -p ${{targets.destdir}}/usr/bin
      echo "test" > ${{targets.destdir}}/usr/bin/test-file
```

### 2. Add Test Function

Add to `pkg/buildkit/e2e_test.go`:

```go
func TestE2E_MyFeature(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping e2e test in short mode")
    }

    e := newE2ETestContext(t)
    cfg := loadTestConfig(t, "XX-descriptive-name.yaml")

    outDir, err := e.buildConfig(cfg)
    require.NoError(t, err)

    // Verify output
    verifyFileExists(t, outDir, "test-my-feature/usr/bin/test-file")
    verifyFileContains(t, outDir, "test-my-feature/usr/bin/test-file", "test")
}
```

### 3. Run and Verify

```bash
go test -v -run TestE2E_MyFeature ./pkg/buildkit/...
```

## Helper Functions

### verifyFileExists

```go
verifyFileExists(t, outDir, "path/to/file")
```

### verifyFileContains

```go
verifyFileContains(t, outDir, "path/to/file", "expected content")
```

### loadTestConfig

```go
cfg := loadTestConfig(t, "XX-name.yaml")
```

## Best Practices

1. **Skip in short mode**: Always check `testing.Short()`
2. **Use cgr.dev images**: Avoid Docker Hub rate limits
3. **Keep tests focused**: One feature per test
4. **Clean up**: The test context handles cleanup automatically
5. **Meaningful names**: `TestE2E_GoCache_PersistsBetweenBuilds`

## Debugging Failed Tests

### Verbose Output

```bash
go test -v -run TestE2E_MyFeature ./pkg/buildkit/...
```

### Keep Output

Modify test to not clean up:

```go
// Temporarily comment out cleanup
// t.Cleanup(func() { os.RemoveAll(outDir) })
```

### Check BuildKit Logs

```bash
docker logs buildkitd
```

### Interactive Debugging

Add debug output to test:

```go
t.Logf("Output directory: %s", outDir)
t.Logf("Files: %v", listFiles(outDir))
```

## Common Issues

### Docker Not Running

```
Error: Cannot connect to Docker daemon
```

Start Docker and try again.

### Rate Limiting

```
Error: toomanyrequests: Rate exceeded
```

Use `cgr.dev/chainguard/wolfi-base` instead of Docker Hub images.

### Permission Errors

```
Error: permission denied
```

Ensure cache mounts have correct ownership (build user UID 1000).
