# Remote Builds with melange-server

melange-server provides a build-as-a-service API for building APK packages remotely using BuildKit. This enables centralized builds, CI/CD integration, and distributed build infrastructure.

## Architecture

```
┌─────────────────┐     ┌─────────────────────────────────────────┐
│                 │     │            melange-server               │
│  melange CLI    │────▶│  ┌─────────┐  ┌───────────┐            │
│  remote submit  │     │  │   API   │  │ Scheduler │            │
│                 │     │  └────┬────┘  └─────┬─────┘            │
└─────────────────┘     │       │             │                   │
                        │       ▼             ▼                   │
                        │  ┌─────────┐  ┌───────────┐            │
                        │  │  Store  │  │  BuildKit │            │
                        │  └─────────┘  └───────────┘            │
                        │       │             │                   │
                        │       ▼             ▼                   │
                        │  ┌─────────────────────────┐           │
                        │  │   Storage (GCS/Local)   │           │
                        │  └─────────────────────────┘           │
                        └─────────────────────────────────────────┘
```

## Current Features

### Job Submission API

Submit build jobs via REST API or CLI:

```bash
# Submit a build job
melange remote submit mypackage.yaml --server http://localhost:8080

# Submit and wait for completion
melange remote submit mypackage.yaml --wait

# Submit with custom pipelines
melange remote submit mypackage.yaml --pipeline-dir ./pipelines

# Submit with options
melange remote submit mypackage.yaml --arch aarch64 --debug
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `POST /api/v1/builds` | POST | Submit a build (single or multi-package) |
| `GET /api/v1/builds` | GET | List all builds |
| `GET /api/v1/builds/:id` | GET | Get build status with per-package details |
| `GET /api/v1/backends` | GET | List available BuildKit backends |
| `GET /api/v1/backends/status` | GET | Get backend status (active jobs, circuit breaker) |
| `POST /api/v1/backends` | POST | Add a new backend |
| `DELETE /api/v1/backends` | DELETE | Remove a backend |
| `GET /healthz` | GET | Health check |

### Job Request Format

**Single package build:**
```json
{
  "config_yaml": "package:\n  name: hello\n  version: 1.0.0\n...",
  "pipelines": {
    "test/docs.yaml": "name: docs\npipeline:\n  - runs: ...",
    "custom/my-pipeline.yaml": "..."
  },
  "arch": "x86_64",
  "backend_selector": {
    "tier": "high-memory"
  },
  "debug": false
}
```

**Multi-package build (inline configs):**
```json
{
  "configs": [
    "package:\n  name: lib-a\n  version: 1.0.0\n...",
    "package:\n  name: lib-b\n  version: 1.0.0\nenvironment:\n  contents:\n    packages:\n      - lib-a\n..."
  ],
  "arch": "x86_64"
}
```

**Multi-package build (git source):**
```json
{
  "git_source": {
    "repository": "https://github.com/wolfi-dev/os",
    "ref": "main",
    "pattern": "*.yaml",
    "path": ""
  },
  "arch": "x86_64"
}
```

### CLI Commands

| Command | Description |
|---------|-------------|
| `melange remote submit <config>` | Submit a single-package build job |
| `melange remote submit <config1> <config2> ...` | Submit multi-package build |
| `melange remote submit --git-repo <url>` | Submit build from git repository |
| `melange remote status <job-id>` | Get job status |
| `melange remote list` | List all jobs |
| `melange remote wait <job-id>` | Wait for job completion |
| `melange remote build-status <build-id>` | Get multi-package build status |
| `melange remote list-builds` | List all multi-package builds |
| `melange remote backends list` | List available BuildKit backends |
| `melange remote backends add` | Add a new backend |
| `melange remote backends remove` | Remove a backend |

### Inline Pipelines

Custom pipelines can be included with the `--pipeline-dir` flag:

```bash
# Include all pipelines from a directory
melange remote submit pkg.yaml --pipeline-dir ./os/pipelines

# Include multiple directories
melange remote submit pkg.yaml \
  --pipeline-dir ./os/pipelines \
  --pipeline-dir ./custom-pipelines
```

Pipelines are sent inline with the request and made available during the build.

### Multi-Package Builds (DAG-Based)

The server supports building multiple interdependent packages with automatic dependency ordering based on `environment.contents.packages`. Packages build in parallel where possible, respecting dependency order.

**How it works:**
1. Configs are parsed to extract package names and dependencies from `environment.contents.packages`
2. A directed acyclic graph (DAG) is constructed
3. Topological sort determines build order
4. Packages with satisfied dependencies build in parallel
5. Failed packages mark their dependents as "skipped"

**Submit multiple configs:**
```bash
# Build multiple packages with automatic dependency resolution
melange remote submit lib-a.yaml lib-b.yaml app.yaml --server http://localhost:8080

# Wait for the entire build to complete
melange remote submit lib-a.yaml lib-b.yaml app.yaml --wait
```

**Submit from git repository:**
```bash
# Build all YAML configs from a git repo
melange remote submit --git-repo https://github.com/wolfi-dev/os --server http://localhost:8080

# Build from specific branch/tag
melange remote submit --git-repo https://github.com/wolfi-dev/os --git-ref v1.0.0

# Build with glob pattern
melange remote submit --git-repo https://github.com/wolfi-dev/os --git-pattern "packages/*.yaml"

# Build from subdirectory
melange remote submit --git-repo https://github.com/wolfi-dev/os --git-path packages/
```

**Check build status:**
```bash
# Get detailed status of a multi-package build
melange remote build-status bld-abc123

# List all builds
melange remote list-builds
```

**Build response:**
```json
{
  "id": "bld-abc123",
  "packages": ["lib-a", "lib-b", "app"]
}
```

**Build status response:**
```json
{
  "id": "bld-abc123",
  "status": "running",
  "packages": [
    {"name": "lib-a", "status": "success", "dependencies": []},
    {"name": "lib-b", "status": "running", "dependencies": ["lib-a"]},
    {"name": "app", "status": "blocked", "dependencies": ["lib-a", "lib-b"]}
  ],
  "created_at": "2024-01-15T10:30:00Z",
  "started_at": "2024-01-15T10:30:01Z"
}
```

**Package statuses:**
| Status | Description |
|--------|-------------|
| `pending` | Package not yet started |
| `blocked` | Waiting for dependencies to complete |
| `running` | Currently building |
| `success` | Build completed successfully |
| `failed` | Build failed |
| `skipped` | Skipped because a dependency failed |

**Build statuses:**
| Status | Description |
|--------|-------------|
| `pending` | Build not yet started |
| `running` | Build in progress |
| `success` | All packages built successfully |
| `failed` | All packages failed |
| `partial` | Some packages succeeded, some failed |

### Storage Backends

**Local Storage** (development):
```bash
melange-server --output-dir /var/lib/melange/output
```

**GCS Storage** (production):
```bash
melange-server --gcs-bucket my-bucket-name
```

Build artifacts, logs, and APK packages are stored in the configured backend.

### Deployment

The server can be deployed to Kubernetes using ko:

```bash
export KO_DOCKER_REPO=your-registry.io/images
ko apply -f deploy/gke/
```

See [GKE Setup Guide](deployment/gke-setup.md) for detailed deployment instructions.

## Configuration

### Server Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--listen-addr` | `:8080` | HTTP listen address |
| `--buildkit-addr` | (none) | BuildKit daemon address (single-backend mode) |
| `--backends-config` | (none) | Path to backends config file (multi-backend mode) |
| `--default-arch` | `x86_64` | Default architecture for single-backend mode |
| `--output-dir` | `/var/lib/melange/output` | Local storage directory |
| `--gcs-bucket` | (none) | GCS bucket for storage |

### Multi-Backend Support

The server supports multiple BuildKit backends with architecture-specific pools and label-based selection.

**Configuration file (`backends.yaml`):**
```yaml
backends:
  # x86_64 backends
  - addr: tcp://amd64-standard:1234
    arch: x86_64
    labels:
      tier: standard
  - addr: tcp://amd64-highmem:1234
    arch: x86_64
    labels:
      tier: high-memory
  # aarch64 backends
  - addr: tcp://arm64-standard:1234
    arch: aarch64
    labels:
      tier: standard
```

**Start server with config:**
```bash
melange-server --backends-config backends.yaml --gcs-bucket my-bucket
```

**Submit jobs with backend selection:**
```bash
# Build for specific architecture
melange remote submit pkg.yaml --arch aarch64

# Build with label requirements
melange remote submit pkg.yaml --backend-selector tier=high-memory

# Combine architecture and label selection
melange remote submit pkg.yaml --arch x86_64 --backend-selector tier=high-memory
```

**List available backends:**
```bash
melange remote backends list

# Filter by architecture
melange remote backends list --arch aarch64
```

**Dynamically add backends:**
```bash
# Add a basic backend
melange remote backends add --addr tcp://new-buildkit:1234 --arch x86_64

# Add a backend with labels
melange remote backends add \
  --addr tcp://high-memory-buildkit:1234 \
  --arch x86_64 \
  --label tier=high-memory \
  --label sandbox=privileged
```

**Remove backends:**
```bash
melange remote backends remove --addr tcp://old-buildkit:1234
```

The scheduler selects backends using:
1. **Architecture matching**: Backend must support the requested architecture
2. **Label matching**: All requested labels must match (AND semantics)
3. **Round-robin**: Among matching backends, selects in round-robin order

### Build Defaults

The server automatically configures builds with:
- Wolfi OS repository and signing key (auto-injected if not specified)
- Signature verification disabled (for MVP)
- `wolfi` namespace for package URLs

Packages without inline repository configuration will automatically use the default Wolfi repos:
```yaml
# These are auto-injected if your config doesn't specify repositories:
environment:
  contents:
    repositories:
      - https://packages.wolfi.dev/os
    keyring:
      - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
```

## Limitations

### Current Limitations

1. **In-memory job store**: Jobs are lost on server restart
2. **Single architecture per job**: No multi-arch builds in one request
3. **No authentication**: API is currently open
4. **No job cancellation**: Running jobs cannot be cancelled
5. **No live log streaming**: Logs available only after completion

---

## Roadmap

### Phase 1: Core Improvements (Next)

- [ ] **PostgreSQL job store** - Persistent job storage across restarts
- [x] **Default repository injection** - Auto-add Wolfi repos for packages without inline repos
- [ ] **Job cancellation** - API endpoint to cancel running jobs
- [ ] **Live log streaming** - WebSocket endpoint for real-time build logs
- [ ] **Authentication** - API key or OAuth2 authentication

### Phase 2: Multi-Package Builds (COMPLETED)

- [x] **Git source support** - Clone repos and build from git
- [x] **DAG-based parallelism** - Build dependency graph, parallel execution
- [x] **Package status tracking** - Per-package status within multi-package builds
- [x] **Glob pattern expansion** - Build multiple packages matching patterns

### Phase 3: Production Features

- [ ] **Multi-architecture builds** - Build for multiple architectures in parallel
- [ ] **Build caching** - Persistent cache across builds
- [ ] **Artifact signing** - Sign packages with configurable keys
- [ ] **Webhook notifications** - Notify external services on job completion
- [ ] **Build quotas/limits** - Resource limits per user/project
- [ ] **Metrics and monitoring** - Prometheus metrics, build dashboards

### Phase 4: Advanced Features

- [ ] **Build queue priorities** - Priority-based job scheduling
- [x] **Multi-backend BuildKit pools** - Multiple BuildKit workers with arch-based selection and labels
- [ ] **Build reproductions** - Re-run builds with same inputs
- [ ] **SBOM generation** - Generate and store SBOMs for builds
- [ ] **Provenance attestations** - SLSA provenance for built packages

## API Evolution

Multi-package builds are now available in the v1 API. Future API versions may include:

```json
// v2 API - Enhanced multi-package builds with additional options
POST /api/v2/builds
{
  "source": {
    "git": {
      "url": "https://github.com/wolfi-dev/os",
      "ref": "main"
    }
  },
  "packages": ["hello-wolfi", "zstd", "brotli"],
  "options": {
    "architectures": ["x86_64", "aarch64"],
    "signing_key": "...",
    "extra_repos": ["https://my-repo.example.com"]
  }
}
```

## Contributing

See the [Development Guide](development/) for information on contributing to melange-server.

Key files:
- `cmd/melange-server/main.go` - Server entry point
- `pkg/service/api/server.go` - HTTP API handlers
- `pkg/service/scheduler/scheduler.go` - Job and build execution
- `pkg/service/store/memory.go` - Job and build stores
- `pkg/service/dag/dag.go` - DAG construction and topological sort
- `pkg/service/git/git.go` - Git source handling
- `pkg/service/types/types.go` - API types
- `pkg/service/storage/` - Storage backends
- `pkg/cli/remote.go` - CLI client
