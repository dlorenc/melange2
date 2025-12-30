# Development Environment Setup

This guide covers setting up a development environment for melange2.

## Prerequisites

- **Go 1.24.6 or later** (as specified in `go.mod`)
- **Docker** (for running BuildKit)
- **Git**

Optional:
- **ko** (for building and deploying container images)
- **gcloud** (for GKE deployments)
- **kubectl** (for Kubernetes operations)

## Clone the Repository

```bash
git clone https://github.com/dlorenc/melange2.git
cd melange2
```

## Build the CLI

### Basic Build

```bash
go build -o melange2 .
```

### Build with Version Information

The Makefile includes version information in the binary:

```bash
make melange
```

This embeds git version, commit hash, and build date into the binary.

### Build the Server

```bash
go build -o melange-server ./cmd/melange-server/
```

## Start BuildKit

melange2 requires a BuildKit daemon for executing builds.

### Local BuildKit with Docker

```bash
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234
```

### Verify BuildKit is Running

```bash
docker logs buildkitd
# Should show "running server on /run/buildkit/buildkitd.sock"
```

### Common BuildKit Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| "connection reset by peer" | Wrong BuildKit address | Restart with correct `--addr` flag |
| "connection refused" | BuildKit not running | `docker start buildkitd` |
| Timeout | BuildKit unresponsive | `docker restart buildkitd` |

## Verify Installation

### Run Unit Tests

```bash
go test -short ./...
```

### Run E2E Tests

```bash
go test -v ./pkg/buildkit/...
```

### Build a Test Package

```bash
./melange2 build examples/minimal.yaml --buildkit-addr tcp://localhost:1234
```

## IDE Setup

### VS Code

Recommended extensions:
- Go (`golang.go`) - Essential Go support
- YAML (`redhat.vscode-yaml`) - YAML schema validation
- GitLens (`eamodio.gitlens`) - Git integration

`.vscode/settings.json`:
```json
{
  "go.useLanguageServer": true,
  "go.testFlags": ["-v", "-short"],
  "go.lintTool": "golangci-lint",
  "go.lintFlags": ["--fast"],
  "editor.formatOnSave": true,
  "[go]": {
    "editor.defaultFormatter": "golang.go"
  }
}
```

`.vscode/launch.json` (for debugging):
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug Build",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}",
      "args": ["build", "examples/minimal.yaml", "--buildkit-addr", "tcp://localhost:1234", "--debug"]
    },
    {
      "name": "Debug Test",
      "type": "go",
      "request": "launch",
      "mode": "test",
      "program": "${workspaceFolder}/pkg/buildkit",
      "args": ["-test.v", "-test.run", "TestE2E_SimpleRun"]
    }
  ]
}
```

### GoLand / IntelliJ IDEA

1. Open the project directory
2. Wait for indexing to complete
3. Configure the Go SDK (1.24.6+)
4. Set test flags to `-short` for faster iteration
5. Configure Run/Debug configurations similar to the VS Code launch.json above

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BUILDKIT_HOST` | BuildKit daemon address | `tcp://localhost:1234` |
| `KO_DOCKER_REPO` | Container registry for ko | (required for deployment) |
| `GOMODCACHE` | Go module cache location | `$GOPATH/pkg/mod` |
| `GOCACHE` | Go build cache location | `~/.cache/go-build` |

## Installing Development Tools

### golangci-lint

```bash
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
```

Or use the Makefile:

```bash
make setup-golangci-lint
```

### ko (for container image building)

```bash
go install github.com/google/ko@latest
```

### goimports (for code formatting)

```bash
go install golang.org/x/tools/cmd/goimports@latest
```

## Makefile Targets

The Makefile provides convenient targets for common operations:

| Target | Description |
|--------|-------------|
| `make melange` | Build the melange binary with version info |
| `make install` | Install melange to BINDIR (default: /usr/bin) |
| `make lint` | Run linters and format checks |
| `make unit` | Run unit tests with race detection |
| `make test` | Run all tests including integration |
| `make test-e2e` | Run E2E tests (requires kernel setup) |
| `make clean` | Clean build artifacts |
| `make help` | Display all available targets |

## Remote Build Infrastructure

### GKE Setup

For working with the remote build service:

```bash
# Get GKE cluster credentials
make gke-credentials

# Start port forwarding to melange-server
make gke-port-forward

# Check status
make gke-status

# Stop port forwarding
make gke-stop-port-forward
```

### Configuration Variables

```bash
# GKE Configuration
GKE_PROJECT=dlorenc-chainguard  # GCP project ID
GKE_CLUSTER=melange-server      # GKE cluster name
GKE_ZONE=us-central1-a          # GKE zone
GKE_PORT=8080                   # Local port for forwarding
```

## Troubleshooting

### Go Module Issues

```bash
# Clean module cache
go clean -modcache

# Re-download modules
go mod download

# Verify modules are tidy
go mod tidy
```

### BuildKit Container Issues

```bash
# Remove and recreate BuildKit container
docker rm -f buildkitd
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234
```

### Test Container Issues

If testcontainers fail:

```bash
# Clean up orphaned containers
docker ps -a | grep testcontainer | awk '{print $1}' | xargs docker rm -f

# Clean up dangling images
docker image prune -f
```

## Next Steps

- Read [architecture.md](architecture.md) to understand the codebase
- Read [testing.md](testing.md) for testing strategies
- Read [git-workflow.md](git-workflow.md) before making changes
