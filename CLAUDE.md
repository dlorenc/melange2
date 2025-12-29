# CLAUDE.md - AI Agent Guide for melange2

This document is optimized for AI agents working on the melange2 codebase.

## Quick Reference

| Task | Command |
|------|---------|
| Build binary | `go build -o melange2 .` |
| Build server | `go build -o melange-server ./cmd/melange-server/` |
| Unit tests | `go test -short ./...` |
| E2E tests | `go test -v ./pkg/buildkit/...` |
| All tests | `go test ./...` |
| Lint | `go vet ./...` |
| Build package | `./melange2 build pkg.yaml --buildkit-addr tcp://localhost:1234` |
| Debug build | `./melange2 build pkg.yaml --buildkit-addr tcp://localhost:1234 --debug` |
| Deploy to GKE | `KO_DOCKER_REPO=us-central1-docker.pkg.dev/PROJECT/REPO ko apply -f deploy/gke/` |

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
├── cmd/
│   └── melange-server/    # Build service entry point
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
├── pkg/service/           # melange-server components
│   ├── api/               # HTTP API handlers
│   ├── scheduler/         # Job scheduling and execution
│   ├── storage/           # Storage backends (local, GCS)
│   ├── store/             # Job store (memory, future: postgres)
│   └── types/             # Service types
├── deploy/
│   ├── kind/              # Local Kind cluster deployment
│   └── gke/               # GKE deployment with GCS storage
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
| Modify server API | `pkg/service/api/server.go` |
| Modify job scheduling | `pkg/service/scheduler/scheduler.go` |
| Add storage backend | `pkg/service/storage/storage.go` |
| GKE deployment | `deploy/gke/*.yaml`, `deploy/gke/setup.sh` |

## Common Tasks

### Start BuildKit
```bash
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234
```

### Deploy with ko

The project uses [ko](https://ko.build) for building and deploying container images. ko builds Go binaries and packages them into OCI images without Dockerfiles.

**Setup:**
```bash
# Install ko
go install github.com/google/ko@latest

# Set the image registry (required)
export KO_DOCKER_REPO=us-central1-docker.pkg.dev/dlorenc-chainguard/clusterlange
```

**Build and push images:**
```bash
# Build a single binary
ko build ./cmd/melange-server

# Build and get the image reference
ko build ./cmd/melange-server --bare
```

**Deploy to Kubernetes with ko apply:**
```bash
# ko apply builds, pushes, and deploys in one command
# It finds ko:// references in YAML and replaces them with built image refs
ko apply -f deploy/gke/

# Deploy with custom registry
KO_DOCKER_REPO=my-registry.io/images ko apply -f deploy/gke/

# Use with kubectl flags (after --)
ko apply -f deploy/gke/ -- --context=my-cluster
```

**ko:// image references in YAML:**
```yaml
# In Kubernetes manifests, use ko:// prefix for Go import paths
spec:
  containers:
  - name: server
    image: ko://github.com/dlorenc/melange2/cmd/melange-server
```

**Common ko flags:**
| Flag | Description |
|------|-------------|
| `-B, --base-import-paths` | Use base path without hash in image name |
| `--bare` | Use KO_DOCKER_REPO without additional path |
| `-t, --tags` | Set image tags (default: latest) |
| `--platform` | Build for specific platforms (e.g., `linux/amd64,linux/arm64`) |
| `-L, --local` | Load image to local Docker daemon |
| `-R, --recursive` | Process directories recursively |

**GKE Deployment:**
```bash
# Full GKE setup (creates cluster, bucket, deploys)
./deploy/gke/setup.sh

# Manual deployment with ko
export KO_DOCKER_REPO=us-central1-docker.pkg.dev/dlorenc-chainguard/clusterlange
ko apply -f deploy/gke/namespace.yaml
ko apply -f deploy/gke/buildkit.yaml
ko apply -f deploy/gke/configmap.yaml
ko apply -f deploy/gke/melange-server.yaml
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

## CI/CD and Deployment

### Automatic Deployment

The `melange-server` is automatically deployed to GKE when changes are merged to `main`:
- **Workflow**: `.github/workflows/deploy.yaml`
- **Cluster**: `melange-server` in `us-central1-a`
- **Project**: `dlorenc-chainguard`
- **Registry**: `us-central1-docker.pkg.dev/dlorenc-chainguard/clusterlange`
- **Storage**: `gs://dlorenc-chainguard-melange-builds`

### Manual Deployment

```bash
# Get cluster credentials
gcloud container clusters get-credentials melange-server \
    --zone=us-central1-a --project=dlorenc-chainguard

# Deploy with ko
export KO_DOCKER_REPO=us-central1-docker.pkg.dev/dlorenc-chainguard/clusterlange
ko apply -f deploy/gke/

# Check status
kubectl get pods -n melange
```

### Trigger Manual Deploy

```bash
gh workflow run deploy.yaml
```

### Access the Service

```bash
kubectl port-forward -n melange svc/melange-server 8080:8080
curl http://localhost:8080/healthz
```

See `docs/deployment/gke-setup.md` for full documentation.

## Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/moby/buildkit` | BuildKit client and LLB |
| `chainguard.dev/apko` | OCI image building |
| `github.com/testcontainers/testcontainers-go` | E2E test infrastructure |
| `github.com/stretchr/testify` | Test assertions |
| `cloud.google.com/go/storage` | GCS storage backend |
| `github.com/google/ko` | Container image building (dev tool) |

## File Locations

| What | Where |
|------|-------|
| E2E test fixtures | `pkg/buildkit/testdata/e2e/*.yaml` |
| Built-in pipelines | `pkg/build/pipelines/**/*.yaml` |
| CLI commands | `pkg/cli/*.go` |
| Example configs | `examples/*.yaml` |
| User docs | `docs/user-guide/` |
| Dev docs | `docs/development/` |
| Server main | `cmd/melange-server/main.go` |
| Server API | `pkg/service/api/server.go` |
| Storage backends | `pkg/service/storage/*.go` |
| GKE deployment | `deploy/gke/*.yaml` |
| Kind deployment | `deploy/kind/*.yaml` |
| Deployment docs | `docs/deployment/gke-setup.md` |
| Deploy workflow | `.github/workflows/deploy.yaml` |
| CI workflow | `.github/workflows/ci.yaml` |
