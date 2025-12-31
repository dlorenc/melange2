# E2E Test Framework Design

## Overview

This document describes the design of melange2's e2e test framework, built from first principles around the external surface area users interact with.

## External Surface Analysis

### User Entry Points

#### Local CLI
| Command | Description | Key Parameters |
|---------|-------------|----------------|
| `build` | Build a package | config, buildkit-addr, arch, output-dir |
| `test` | Test a package | config, buildkit-addr, arch |
| `keygen` | Generate signing keys | - |
| `sign-index` | Sign package index | key, index |
| `index` | Create repository index | packages, output |
| `query` | Query config with template | config, template |
| `package-version` | Get package version | config |
| `lint` | Lint APK packages | packages |

#### Remote CLI
| Command | Description | Key Parameters |
|---------|-------------|----------------|
| `remote submit` | Submit build to server | config(s), server, arch, wait, mode |
| `remote status` | Get build status | build-id, server |
| `remote list` | List all builds | server |
| `remote wait` | Wait for completion | build-id, server |
| `remote backends list` | List backends | server, arch |
| `remote backends add` | Add backend | addr, arch, labels |
| `remote backends remove` | Remove backend | addr |

#### HTTP API
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/healthz` | GET | Health check |
| `/api/v1/builds` | POST | Create build |
| `/api/v1/builds` | GET | List builds |
| `/api/v1/builds/:id` | GET | Get build details |
| `/api/v1/backends` | GET | List backends |
| `/api/v1/backends` | POST | Add backend |
| `/api/v1/backends` | DELETE | Remove backend |
| `/api/v1/backends/status` | GET | Backend status |

## Key User Flows

### 1. Local Build Flow
```
User -> melange2 build pkg.yaml --buildkit-addr tcp://...
         -> Parse config
         -> Compile pipelines
         -> Generate LLB graph
         -> Send to BuildKit
         -> Export outputs
         -> Generate APK package
         -> Sign package
         -> Update index
```

### 2. Remote Build Flow
```
User -> melange2 remote submit pkg.yaml --server http://...
         -> Parse config locally
         -> POST /api/v1/builds
         -> Server creates build in store
         -> Scheduler picks up build
         -> Scheduler claims packages
         -> BuildKit executes
         -> Storage syncs outputs
         -> User polls for completion
```

### 3. Multi-Package DAG Build
```
User -> melange2 remote submit *.yaml --mode dag --server http://...
         -> Parse all configs
         -> Build dependency graph
         -> Topological sort
         -> POST /api/v1/builds (with ordered packages)
         -> Scheduler builds in order
         -> Dependencies block until predecessors complete
```

## Test Framework Architecture

### Package Structure
```
e2e/
├── DESIGN.md           # This document
├── harness/
│   ├── harness.go      # Test harness (BuildKit, registry, server)
│   ├── buildkit.go     # BuildKit testcontainer management
│   ├── registry.go     # Registry testcontainer management
│   └── assertions.go   # Common test assertions
├── fixtures/
│   ├── build/          # Build test fixtures
│   │   ├── simple.yaml
│   │   ├── variables.yaml
│   │   └── ...
│   ├── test/           # Test pipeline fixtures
│   └── remote/         # Remote build fixtures
├── build_test.go       # Local build tests
├── test_test.go        # Test pipeline tests
├── remote_test.go      # Remote build tests
├── api_test.go         # API tests
└── cli_test.go         # CLI integration tests
```

### Test Harness

The harness provides:
1. **BuildKit container** via testcontainers
2. **Registry container** for cache (optional)
3. **In-process server** for remote tests (enables coverage)
4. **Shared setup/teardown** across tests

```go
type Harness struct {
    BuildKitAddr string
    RegistryAddr string  // optional
    Server       *api.Server
    ServerURL    string
    TempDir      string
}

func NewHarness(t *testing.T, opts ...Option) *Harness
func (h *Harness) Close()
```

### Test Categories

#### 1. Build Tests (`build_test.go`)
Test local build functionality through the build package directly.

| Test | What it validates |
|------|-------------------|
| SimpleRun | Basic shell command execution |
| VariableSubstitution | ${{package.name}}, ${{targets.destdir}}, etc. |
| EnvironmentVars | Environment variable propagation |
| WorkingDirectory | Working directory changes |
| MultiPipeline | Sequential pipeline execution |
| Subpackages | Multiple package output |
| Conditionals | if: conditions |
| GitCheckout | Native git-checkout pipeline |
| Fetch | Native fetch pipeline |
| CacheMounts | Language-specific cache persistence |

#### 2. Remote Tests (`remote_test.go`)
Test remote build submission and execution with in-process server.

| Test | What it validates |
|------|-------------------|
| HealthCheck | Server health endpoint |
| SinglePackageSubmit | Submit and build one package |
| MultiPackageFlat | Parallel multi-package build |
| MultiPackageDAG | Dependency-ordered build |
| BuildStatusPolling | Status updates during build |
| BackendManagement | Add/remove/list backends |
| BackendSelector | Label-based backend selection |

#### 3. Test Pipeline Tests (`test_test.go`)
Test the `melange test` functionality.

| Test | What it validates |
|------|-------------------|
| SimpleTest | Basic test pipeline execution |
| SubpackageIsolation | Tests run in isolation |
| FailureDetection | Test failures are reported |
| TestWithSources | Source files available |

#### 4. API Tests (`api_test.go`)
Test HTTP API directly.

| Test | What it validates |
|------|-------------------|
| CreateBuild | POST /api/v1/builds |
| GetBuild | GET /api/v1/builds/:id |
| ListBuilds | GET /api/v1/builds |
| BackendCRUD | Backend management endpoints |

### Fixture Format

Fixtures are YAML files with optional metadata:

```yaml
# Test metadata (optional, in comments)
# expect-files: [usr/bin/hello, etc/config.conf]
# expect-contains: {etc/config.conf: "version=1.0"}

package:
  name: test-package
  version: 1.0.0

pipeline:
  - runs: |
      mkdir -p ${{targets.destdir}}/usr/bin
      echo "#!/bin/sh" > ${{targets.destdir}}/usr/bin/hello
      chmod +x ${{targets.destdir}}/usr/bin/hello
```

### Running Tests

```bash
# All e2e tests (requires Docker)
go test -v ./e2e/...

# Skip e2e tests (unit tests only)
go test -short ./...

# Specific test category
go test -v ./e2e/... -run TestBuild
go test -v ./e2e/... -run TestRemote

# With verbose BuildKit output
go test -v ./e2e/... -buildkit-debug
```

### Coverage

Running server components in-process allows coverage measurement:

```bash
go test -v -coverprofile=coverage.out ./e2e/... ./pkg/...
go tool cover -html=coverage.out
```

## Design Principles

1. **Test through public interfaces** - Tests exercise CLI, API, and package APIs as users would
2. **In-process where possible** - Server runs in-process for coverage; BuildKit uses containers
3. **Isolated tests** - Each test gets fresh temp dirs; containers are shared for efficiency
4. **Table-driven** - Similar scenarios use table tests
5. **Fast feedback** - Quick tests run with `-short`; full e2e requires Docker
6. **Clear failures** - Assertions provide context on what failed and why

## Migration Path

1. Create new `e2e/` package with harness
2. Implement build tests using new framework
3. Implement remote tests with in-process server
4. Remove old `pkg/buildkit/e2e_test.go`
5. Update CI to run new tests
6. Update documentation
