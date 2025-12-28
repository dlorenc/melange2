# CI Pipeline

melange2 uses GitHub Actions for continuous integration.

## Workflow

The CI workflow is defined in `.github/workflows/ci.yaml`.

## Jobs

| Job | Description | Duration |
|-----|-------------|----------|
| **Build** | Compile all packages and binary | ~30s |
| **Test** | Unit tests with `-short` flag | ~2min |
| **E2E Tests** | BuildKit integration tests | ~2min |
| **Lint** | golangci-lint | ~1min |
| **Verify** | Check go.mod is tidy | ~20s |

## What Each Job Does

### Build

```yaml
- run: go build -v ./...
```

Ensures all code compiles without errors.

### Test

```yaml
- run: go test -short ./...
```

Runs unit tests. The `-short` flag skips E2E tests that require Docker.

### E2E Tests

```yaml
- run: go test -v ./pkg/buildkit/...
```

Runs BuildKit integration tests using testcontainers. Docker is available on GitHub Actions runners.

### Lint

```yaml
- uses: golangci/golangci-lint-action@v6
  with:
    version: latest
```

Runs golangci-lint with the project's configuration.

### Verify

```yaml
- run: |
    go mod tidy
    git diff --exit-code go.mod go.sum
```

Ensures `go.mod` and `go.sum` are up to date.

## Required Checks

All jobs must pass before merging a PR.

## Viewing CI Results

### From Command Line

```bash
# List recent runs
gh run list --limit 5

# View specific run
gh run view <run-id>

# View failed job logs
gh run view <run-id> --log-failed
```

### From GitHub UI

1. Go to the PR
2. Click "Checks" tab
3. Click on the failed job
4. Expand the failed step

## Common Failures

### Build Failure

**Cause:** Syntax error or missing import.

**Fix:** Run `go build ./...` locally before pushing.

### Test Failure

**Cause:** Test assertion failed.

**Fix:**
```bash
go test -v -run TestThatFailed ./pkg/...
```

### Lint Failure

**Cause:** Code style issues.

**Fix:**
```bash
# See what golangci-lint finds
golangci-lint run

# Or use go vet as a quick check
go vet ./...
```

### Verify Failure

**Cause:** `go.mod` not tidy.

**Fix:**
```bash
go mod tidy
git add go.mod go.sum
git commit --amend
```

### E2E Test Failure

**Cause:** BuildKit integration issue.

**Fix:**
```bash
# Run locally with Docker
go test -v -run TestE2E_FailingTest ./pkg/buildkit/...
```

## Running CI Locally

Simulate CI checks before pushing:

```bash
# Build
go build ./...

# Unit tests
go test -short ./...

# E2E tests
go test -v ./pkg/buildkit/...

# Lint
go vet ./...
# or: golangci-lint run

# Verify
go mod tidy && git diff --exit-code go.mod go.sum
```

## Debugging CI

### Re-run Failed Jobs

From GitHub UI: Click "Re-run failed jobs" on the workflow run page.

### SSH Debug (Fork Only)

For debugging on a fork, you can add a debug step:

```yaml
- name: Debug with tmate
  uses: mxschmitt/action-tmate@v3
  if: failure()
```

This opens an SSH session to the runner.

## Performance

CI typically completes in under 5 minutes. If it's slow:

1. Check for flaky tests
2. Ensure tests use proper parallelism
3. Use testcontainers efficiently (reuse containers)
