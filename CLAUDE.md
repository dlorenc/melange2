# CLAUDE.md - AI Agent Guide for melange2

This document is optimized for AI agents working on the melange2 codebase.

## Quick Reference

| Task | Command |
|------|---------|
| Build binary | `go build -o melange2 .` |
| Build server | `go build -o melange-server ./cmd/melange-server/` |
| Unit tests | `go test -short ./...` |
| E2E tests | `go test -v ./e2e/...` |
| All tests | `go test ./...` |
| Lint | `go vet ./...` |
| Build package | `./melange2 build pkg.yaml --buildkit-addr tcp://localhost:1234` |
| Debug build | `./melange2 build pkg.yaml --buildkit-addr tcp://localhost:1234 --debug` |
| Deploy to GKE | `KO_DOCKER_REPO=us-central1-docker.pkg.dev/PROJECT/REPO ko apply -f deploy/gke/` |
| GKE port forward | `make gke-port-forward` |
| GKE setup | `make gke-setup` |
| Remote build | `./melange2 remote submit pkg.yaml --server http://localhost:8080 --wait` |

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
├── e2e/                   # E2E test framework
│   ├── harness/           # Test infrastructure (BuildKit, registry, server)
│   ├── fixtures/          # Test fixtures (build/, test/, remote/)
│   ├── build_test.go      # Local build E2E tests
│   ├── remote_test.go     # Remote build E2E tests
│   └── test_test.go       # Test pipeline E2E tests
├── pkg/buildkit/          # CORE - BuildKit integration
│   ├── builder.go         # Main Build() method
│   ├── llb.go             # Pipeline → LLB conversion
│   ├── builtin.go         # Native LLB implementations (git-checkout, fetch)
│   ├── cache.go           # Cache mount definitions
│   └── progress.go        # Build progress display
├── pkg/build/             # Build orchestration
│   └── pipelines/         # Built-in pipeline YAMLs
├── pkg/cli/               # CLI commands (build, test, etc.)
├── pkg/config/            # YAML config parsing
├── pkg/service/           # melange-server components
│   ├── api/               # HTTP API handlers
│   ├── scheduler/         # Job scheduling and execution
│   ├── storage/           # Storage backends (local, GCS)
│   ├── store/             # Job store (memory or PostgreSQL)
│   └── types/             # Service types
├── deploy/
│   ├── kind/              # Local Kind cluster deployment
│   └── gke/               # GKE deployment with GCS storage
├── docs/
│   ├── getting-started/   # Installation and first build
│   ├── build-files/       # Build file format documentation
│   ├── cli/               # CLI command reference
│   ├── development/       # Developer documentation
│   ├── pipelines/         # Pipeline documentation
│   ├── remote-builds/     # Remote build server docs
│   ├── signing/           # Package signing docs
│   └── testing/           # Testing documentation
├── examples/              # Example build files
└── test/compare/          # Comparison tests vs Wolfi
```

## Key Files by Task

| Task | Read These Files |
|------|------------------|
| Modify build process | `pkg/buildkit/builder.go`, `pkg/buildkit/llb.go` |
| Add CLI flag | `pkg/cli/build.go` |
| Add built-in pipeline | `pkg/build/pipelines/{category}/{name}.yaml` |
| Add native LLB pipeline | `pkg/buildkit/builtin.go`, `pkg/build/compile.go` |
| Debug test failures | `e2e/*.go`, `e2e/harness/*.go` |
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
ko apply -f deploy/gke/postgres.yaml
ko apply -f deploy/gke/configmap.yaml
ko apply -f deploy/gke/melange-server.yaml
```

**PostgreSQL Secret Setup (one-time, manual):**

The PostgreSQL credentials secret must be created manually before deploying:

```bash
# Generate a secure password
PG_PASSWORD=$(openssl rand -base64 32)

# Create the secret
kubectl create secret generic postgres-credentials -n melange \
  --from-literal=username=melange \
  --from-literal=password="$PG_PASSWORD" \
  --from-literal=dsn="postgres://melange:${PG_PASSWORD}@postgres.melange.svc.cluster.local:5432/melange?sslmode=disable"

# Verify the secret was created
kubectl get secret postgres-credentials -n melange
```

Once created, the CI workflow will automatically deploy PostgreSQL and the melange-server will use it for persistent build history.

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

### Native LLB Pipelines
Some `uses:` pipelines have native LLB implementations for better caching and performance:

| Pipeline | Native Operation | Benefits |
|----------|-----------------|----------|
| `git-checkout` | `llb.Git()` | Content-addressable caching, parallel fetching |
| `fetch` | `llb.HTTP()` | Checksum-based caching, automatic verification |

To add a new native pipeline:
1. Add implementation in `pkg/buildkit/builtin.go`
2. Register in `BuiltinPipelines` map
3. The compile phase (`pkg/build/compile.go`) automatically preserves `Uses` for registered pipelines

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

See `docs/remote-builds/gke-deployment.md` for full documentation.

## Registry Cache

The GKE deployment includes an in-cluster container registry for BuildKit cache-to/cache-from support. This significantly improves build performance by:
- Persisting cache across BuildKit pod restarts
- Sharing cache across multiple BuildKit instances
- Enabling LLB layer cache reuse between builds

**Configuration (server-side only):**

The cache is configured via environment variables on the melange-server:

| Variable | Description | Default |
|----------|-------------|---------|
| `CACHE_REGISTRY` | Registry URL for cache storage | `registry:5000/melange-cache` |
| `CACHE_MODE` | Export mode: `min` or `max` | `max` |

**How it works:**
- BuildKit's content-addressable cache handles deduplication automatically
- No custom cache key logic needed - BuildKit computes keys from LLB graph content
- `max` mode exports all intermediate layers (better cache hit rate)
- `min` mode exports only final layers (smaller, faster export)

**Deployment files:**
- `deploy/gke/registry.yaml` - In-cluster Docker Registry
- `deploy/gke/buildkit.yaml` - BuildKit config for insecure registry access
- `deploy/gke/configmap.yaml` - Cache configuration (CACHE_REGISTRY, CACHE_MODE)

**Note:** Cache is stored in `emptyDir` - it's ephemeral and will be cleared on pod restart. This is intentional as it's just a cache.

## GKE Makefile Targets

The following Makefile targets simplify working with the GKE remote build infrastructure:

| Target | Description |
|--------|-------------|
| `make gke-setup` | Create GKE cluster, GCS bucket, and deploy melange-server from scratch |
| `make gke-port-forward` | Start port forwarding to melange-server in the background |
| `make gke-stop-port-forward` | Stop the background port forwarding |
| `make gke-credentials` | Get GKE cluster credentials (kubeconfig) |
| `make gke-status` | Check status of pods and backends |
| `make gke-deploy` | Deploy/update melange-server using ko |

**Configuration variables:**
```bash
GKE_PROJECT=dlorenc-chainguard  # GCP project ID
GKE_CLUSTER=melange-server      # GKE cluster name
GKE_ZONE=us-central1-a          # GKE zone
GKE_PORT=8080                   # Local port for forwarding
```

**Example workflow:**
```bash
# First time setup (creates cluster, bucket, deploys server)
make gke-setup

# Daily usage - start port forwarding
make gke-port-forward

# Submit builds (see Remote Build Commands below)
./melange2 remote submit mypackage.yaml --server http://localhost:8080 --wait

# When done
make gke-stop-port-forward
```

## Convention-Based Defaults

melange2 uses convention over configuration for common paths. These are automatically detected and used:

| Convention | Location | Description |
|------------|----------|-------------|
| Pipeline directory | `./pipelines/` | Custom pipelines are automatically loaded |
| Source directory | `./$pkgname/` | Source files are loaded from a directory named after the package |
| Signing key | `melange.rsa` or `local-signing.rsa` | First matching key is used for signing |

**Example directory structure:**
```
myproject/
├── curl.yaml              # Package config
├── curl/                  # Source files for curl package (auto-detected)
│   ├── patches/
│   │   └── fix.patch
│   └── config.ini
├── pipelines/             # Custom pipelines (auto-detected)
│   └── custom-build.yaml
└── melange.rsa            # Signing key (auto-detected)
```

With this structure, running `./melange2 build curl.yaml` or `./melange2 remote submit curl.yaml` will automatically:
- Include pipelines from `./pipelines/`
- Include source files from `./curl/`
- Use `melange.rsa` for signing (local builds only)

## Remote Build Commands

The `melange remote` subcommand allows submitting builds to a remote melange-server.

### Submit a Build Job

```bash
# Submit a single package and wait for completion
# (automatically includes ./pipelines/ and ./$pkgname/ source files)
./melange2 remote submit pkg.yaml --server http://localhost:8080 --wait

# Submit with specific architecture
./melange2 remote submit pkg.yaml --server http://localhost:8080 --arch x86_64 --wait

# Submit multiple packages (builds in dependency order)
./melange2 remote submit lib-a.yaml lib-b.yaml app.yaml --server http://localhost:8080 --wait

# Submit from a git repository
./melange2 remote submit --git-repo https://github.com/wolfi-dev/os --git-pattern "*.yaml" --server http://localhost:8080

# Submit with backend selector (for pools with labels)
./melange2 remote submit pkg.yaml --server http://localhost:8080 --backend-selector tier=high-memory
```

### Check Job Status

```bash
# Get status of a specific job
./melange2 remote status <job-id> --server http://localhost:8080

# List all jobs
./melange2 remote list --server http://localhost:8080

# Wait for a job to complete
./melange2 remote wait <job-id> --server http://localhost:8080
```

### Manage Backends

```bash
# List available backends and architectures
./melange2 remote backends list --server http://localhost:8080

# Add a new backend
./melange2 remote backends add tcp://buildkit:1234 --arch x86_64 --server http://localhost:8080

# Add a backend with labels
./melange2 remote backends add tcp://buildkit:1234 --arch x86_64 --label tier=standard --server http://localhost:8080

# Remove a backend
./melange2 remote backends remove tcp://buildkit:1234 --server http://localhost:8080
```

### Common Options

| Flag | Description |
|------|-------------|
| `--server` | melange-server URL (default: http://localhost:8080) |
| `--arch` | Target architecture (e.g., x86_64, aarch64) |
| `--wait` | Wait for job/build to complete before returning |
| `--debug` | Enable debug logging |
| `--backend-selector` | Label selector for backend (key=value) |
| `--test` | Run tests after build |

Note: Pipelines and source files are automatically included by convention (see [Convention-Based Defaults](#convention-based-defaults)).

### Bulk Package Builds

For building large numbers of packages (100+) against the GKE cluster:

```bash
# Submit 500 packages from a package repository (e.g., wolfi-dev/os)
cd /path/to/os
ls *.yaml | head -500 > /tmp/packages.txt
./melange2 remote submit $(cat /tmp/packages.txt | tr '\n' ' ') --server http://localhost:8080

# Monitor build progress
./melange2 remote status <build-id> --server http://localhost:8080

# Get summary counts
./melange2 remote status <build-id> --server http://localhost:8080 2>&1 | \
  grep -oE "(success|failed|running|pending)" | sort | uniq -c
```

**Memory Monitoring:**

The server exposes pprof endpoints for memory profiling during bulk builds:

```bash
# Check current memory usage
kubectl top pod -n melange -l app=melange-server

# Get heap profile summary
curl -s 'http://localhost:8080/debug/pprof/heap?debug=1' | head -5

# View top memory allocators
curl -s 'http://localhost:8080/debug/pprof/heap?debug=1' | \
  grep -E "^[0-9]+: [0-9]+" | sort -t: -k2 -rn | head -10

# Check if memory pools are active (optimization indicator)
curl -s 'http://localhost:8080/debug/pprof/heap?debug=1' | \
  grep -E "(BoundedPool|sync\.\(\*Pool\))"
```

**Expected Memory Usage:**
- Baseline (idle): ~10-20Mi
- Per concurrent build: ~300-400Mi
- 30 concurrent builds: ~10-12Gi (memory stabilizes due to per-build cleanup)
- Memory pools (BoundedPool) recycle bufio writers to prevent unbounded growth

**Scheduling Bulk Builds:**

To schedule recurring bulk builds (e.g., nightly rebuilds of all packages), use a Kubernetes CronJob or standard cron:

```bash
# Example: Submit all packages from wolfi-dev/os at 2am daily
# Create a script: /usr/local/bin/nightly-build.sh
#!/bin/bash
set -euo pipefail

WOLFI_OS_PATH="${WOLFI_OS_PATH:-/path/to/os}"
MELANGE_SERVER="${MELANGE_SERVER:-http://localhost:8080}"
MELANGE_BIN="${MELANGE_BIN:-/usr/local/bin/melange2}"

cd "$WOLFI_OS_PATH"
git pull origin main

# Submit all packages (no --wait to avoid blocking)
BUILD_ID=$("$MELANGE_BIN" remote submit *.yaml --server "$MELANGE_SERVER" 2>&1 | grep "Build submitted" | awk '{print $3}')
echo "$(date): Started build $BUILD_ID with $(ls *.yaml | wc -l) packages" >> /var/log/melange-builds.log
```

```bash
# Add to crontab (run at 2am daily)
0 2 * * * /usr/local/bin/nightly-build.sh >> /var/log/melange-cron.log 2>&1
```

For Kubernetes, create a CronJob:

```yaml
# deploy/gke/cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly-build
  namespace: melange
spec:
  schedule: "0 2 * * *"  # 2am daily
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: submit
            image: ko://github.com/dlorenc/melange2
            command:
            - /bin/sh
            - -c
            - |
              cd /workspace
              git clone --depth 1 https://github.com/wolfi-dev/os .
              melange2 remote submit *.yaml --server http://melange-server:8080
            volumeMounts:
            - name: workspace
              mountPath: /workspace
          volumes:
          - name: workspace
            emptyDir: {}
          restartPolicy: OnFailure
```

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
| E2E test fixtures | `e2e/fixtures/**/*.yaml` |
| Built-in pipelines | `pkg/build/pipelines/**/*.yaml` |
| CLI commands | `pkg/cli/*.go` |
| Example configs | `examples/*.yaml` |
| User docs | `docs/getting-started/`, `docs/build-files/`, `docs/pipelines/` |
| Dev docs | `docs/development/` |
| Remote build docs | `docs/remote-builds/` |
| Server main | `cmd/melange-server/main.go` |
| Server API | `pkg/service/api/server.go` |
| Storage backends | `pkg/service/storage/*.go` |
| GKE deployment | `deploy/gke/*.yaml` |
| Kind deployment | `deploy/kind/*.yaml` |
| Deploy workflow | `.github/workflows/deploy.yaml` |
| CI workflow | `.github/workflows/ci.yaml` |
