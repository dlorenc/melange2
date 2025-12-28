# Development Environment

## Prerequisites

- **Go 1.21+** - [Download](https://go.dev/dl/)
- **Docker** - For running BuildKit and testcontainers
- **Git** - Version control
- **golangci-lint** (optional) - For local linting

## Clone the Repository

```bash
git clone https://github.com/dlorenc/melange2.git
cd melange2
```

## Build

```bash
# Build the binary
go build -o melange2 .

# Or install globally
go install .
```

## Verify

```bash
./melange2 version
```

## Start BuildKit

For E2E tests and local builds:

```bash
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234
```

## Run Tests

```bash
# Unit tests only (fast, no Docker)
go test -short ./...

# All tests including E2E
go test ./...

# E2E tests only
go test -v -run "TestE2E" ./pkg/buildkit/...
```

## Development Container (Optional)

Use the provided devenv script for a containerized environment:

```bash
./hack/make-devenv.sh
```

This drops you into a Wolfi-based shell with all dependencies pre-installed.

### Reset Dev Environment

```bash
docker rmi melange-inception:latest
./hack/make-devenv.sh  # Rebuilds fresh
```

## Common Development Tasks

### Rebuild After Changes

```bash
go build -o melange2 . && ./melange2 build test.yaml --buildkit-addr tcp://localhost:1234
```

### Run Specific Tests

```bash
# Single test
go test -v -run TestE2E_FetchSource ./pkg/buildkit/...

# Tests matching pattern
go test -v -run "TestE2E_.*Cache" ./pkg/buildkit/...
```

### Check Coverage

```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Lint

```bash
# Go vet (always works)
go vet ./...

# golangci-lint (if installed)
golangci-lint run
```

## Project Structure

```
melange2/
├── main.go              # Entry point
├── pkg/
│   ├── buildkit/        # BuildKit integration (focus here)
│   ├── build/           # Build orchestration
│   ├── cli/             # CLI commands
│   ├── config/          # YAML configuration
│   └── ...
├── docs/
│   ├── user-guide/      # User documentation
│   └── development/     # Developer documentation
├── examples/            # Example build files
└── e2e-tests/           # E2E test configs
```

## Next Steps

- [IDE Setup](ide-setup.md) - Configure your editor
- [Architecture Overview](../architecture/overview.md) - Understand the codebase
- [Testing Strategy](../testing/testing-strategy.md) - Learn how to test
