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
| `POST /api/v1/jobs` | POST | Submit a new build job |
| `GET /api/v1/jobs` | GET | List all jobs |
| `GET /api/v1/jobs/:id` | GET | Get job status and details |
| `GET /healthz` | GET | Health check |

### Job Request Format

```json
{
  "config_yaml": "package:\n  name: hello\n  version: 1.0.0\n...",
  "pipelines": {
    "test/docs.yaml": "name: docs\npipeline:\n  - runs: ...",
    "custom/my-pipeline.yaml": "..."
  },
  "arch": "x86_64",
  "debug": false
}
```

### CLI Commands

| Command | Description |
|---------|-------------|
| `melange remote submit <config>` | Submit a build job |
| `melange remote status <job-id>` | Get job status |
| `melange remote list` | List all jobs |
| `melange remote wait <job-id>` | Wait for job completion |

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
| `--buildkit-addr` | `tcp://localhost:1234` | BuildKit daemon address |
| `--output-dir` | `/var/lib/melange/output` | Local storage directory |
| `--gcs-bucket` | (none) | GCS bucket for storage |

### Build Defaults

The server automatically configures builds with:
- Wolfi OS repository and signing key
- Signature verification disabled (for MVP)
- `wolfi` namespace for package URLs

## Limitations

### Current Limitations

1. **In-memory job store**: Jobs are lost on server restart
2. **Single architecture per job**: No multi-arch builds in one request
3. **No authentication**: API is currently open
4. **No job cancellation**: Running jobs cannot be cancelled
5. **No live log streaming**: Logs available only after completion

### Package Requirements

Packages submitted to the server must include inline repository configuration:

```yaml
environment:
  contents:
    repositories:
      - https://packages.wolfi.dev/os
    keyring:
      - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
    packages:
      - build-base
      - ...
```

---

## Roadmap

### Phase 1: Core Improvements (Next)

- [ ] **PostgreSQL job store** - Persistent job storage across restarts
- [ ] **Default repository injection** - Auto-add Wolfi repos for packages without inline repos
- [ ] **Job cancellation** - API endpoint to cancel running jobs
- [ ] **Live log streaming** - WebSocket endpoint for real-time build logs
- [ ] **Authentication** - API key or OAuth2 authentication

### Phase 2: Multi-Package Builds

- [ ] **Git source support** - Clone repos and build from git
  ```json
  {
    "git_source": {
      "url": "https://github.com/wolfi-dev/os",
      "ref": "main",
      "glob": "*.yaml"
    }
  }
  ```
- [ ] **DAG-based parallelism** - Build dependency graph, parallel execution
- [ ] **Package status tracking** - Per-package status within multi-package jobs
- [ ] **Glob pattern expansion** - Build multiple packages matching patterns

### Phase 3: Production Features

- [ ] **Multi-architecture builds** - Build for multiple architectures in parallel
- [ ] **Build caching** - Persistent cache across builds
- [ ] **Artifact signing** - Sign packages with configurable keys
- [ ] **Webhook notifications** - Notify external services on job completion
- [ ] **Build quotas/limits** - Resource limits per user/project
- [ ] **Metrics and monitoring** - Prometheus metrics, build dashboards

### Phase 4: Advanced Features

- [ ] **Build queue priorities** - Priority-based job scheduling
- [ ] **Distributed BuildKit** - Multiple BuildKit workers for scaling
- [ ] **Build reproductions** - Re-run builds with same inputs
- [ ] **SBOM generation** - Generate and store SBOMs for builds
- [ ] **Provenance attestations** - SLSA provenance for built packages

## API Evolution

Future API versions may include:

```json
// v2 API - Multi-package builds
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

// Response
{
  "build_id": "build-abc123",
  "packages": [
    {"name": "hello-wolfi", "status": "pending", "job_id": "job-1"},
    {"name": "zstd", "status": "pending", "job_id": "job-2"},
    {"name": "brotli", "status": "blocked", "blocked_by": ["zstd"]}
  ]
}
```

## Contributing

See the [Development Guide](development/) for information on contributing to melange-server.

Key files:
- `cmd/melange-server/main.go` - Server entry point
- `pkg/service/api/server.go` - HTTP API handlers
- `pkg/service/scheduler/scheduler.go` - Job execution
- `pkg/service/storage/` - Storage backends
- `pkg/cli/remote.go` - CLI client
