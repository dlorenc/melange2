# melange-server Development Guide

This document describes the melange-server component, a service that provides a REST API for building melange packages using BuildKit.

## Overview

`melange-server` is a single binary that runs:
- An HTTP API server for job submission and status queries
- A scheduler that processes jobs using the existing melange build infrastructure

## Architecture

```
┌─────────────────────────────────────────┐
│             melange-server              │
│  ┌──────────────┐  ┌─────────────────┐  │
│  │  API Server  │  │    Scheduler    │  │
│  │    (HTTP)    │  │  (goroutines)   │  │
│  └──────┬───────┘  └────────┬────────┘  │
│         │                   │           │
│         └─────────┬─────────┘           │
│                   ▼                     │
│            ┌────────────┐               │
│            │  JobStore  │               │
│            └────────────┘               │
└───────────────────────────────────────┬─┘
                    │
          ┌─────────┼─────────┐
          ▼         ▼         ▼
     ┌─────────┐ ┌─────────┐ ┌─────────┐
     │ Storage │ │BuildKit │ │  (DB)   │
     └─────────┘ └─────────┘ └─────────┘
```

## Components

### API Server (`pkg/service/api/`)

HTTP server providing REST endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/healthz` | GET | Health check |
| `/api/v1/jobs` | POST | Create a new build job |
| `/api/v1/jobs` | GET | List all jobs |
| `/api/v1/jobs/:id` | GET | Get job status and details |

### Job Store (`pkg/service/store/`)

Stores job state. Current implementation:
- `MemoryStore`: In-memory storage for development/testing

Future implementations:
- `PostgresStore`: Persistent storage for production

### Scheduler (`pkg/service/scheduler/`)

Processes pending jobs:
1. Polls for pending jobs
2. Claims a job (marks as running)
3. Writes config YAML to temp file
4. Executes build using `pkg/build`
5. Updates job status (success/failed)

### Types (`pkg/service/types/`)

Core data types:
- `Job`: Represents a build job with status, spec, timestamps
- `JobSpec`: Build specification (config YAML, arch, options)
- `JobStatus`: Enum (pending, running, success, failed)

## API Reference

### Create Job

```bash
POST /api/v1/jobs
Content-Type: application/json

{
  "config_yaml": "package:\n  name: hello\n  version: 1.0.0\n...",
  "arch": "aarch64",        # optional, defaults to runtime arch
  "with_test": false,       # optional, run tests after build
  "debug": true             # optional, enable debug logging
}
```

Response:
```json
{"id": "abc12345"}
```

### Get Job Status

```bash
GET /api/v1/jobs/:id
```

Response:
```json
{
  "id": "abc12345",
  "status": "success",
  "spec": {...},
  "created_at": "2025-01-01T00:00:00Z",
  "started_at": "2025-01-01T00:00:01Z",
  "finished_at": "2025-01-01T00:00:30Z",
  "log_path": "/var/lib/melange/output/abc12345/logs/build.log",
  "output_path": "/var/lib/melange/output/abc12345"
}
```

### List Jobs

```bash
GET /api/v1/jobs
```

Response:
```json
[
  {"id": "abc12345", "status": "success", ...},
  {"id": "def67890", "status": "running", ...}
]
```

## Configuration

Command-line flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--listen-addr` | `:8080` | HTTP server listen address |
| `--buildkit-addr` | `tcp://localhost:1234` | BuildKit daemon address |
| `--output-dir` | `/var/lib/melange/output` | Directory for build outputs |

## Config YAML Requirements

The `config_yaml` must include repository and keyring configuration:

```yaml
package:
  name: my-package
  version: 1.0.0
  epoch: 0
  description: My package
  copyright:
    - license: Apache-2.0

environment:
  contents:
    repositories:
      - https://packages.wolfi.dev/os
    keyring:
      - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
    packages:
      - busybox

pipeline:
  - runs: |
      mkdir -p ${{targets.destdir}}/usr/bin
      echo "hello" > ${{targets.destdir}}/usr/bin/hello
```

## Local Development with kind

### Prerequisites

- Docker
- kind
- kubectl

### Setup

```bash
# Create kind cluster and deploy
./deploy/kind/setup.sh

# Port-forward to access the API
kubectl port-forward -n melange svc/melange-server 8080:8080
```

### Test a Build

```bash
# Submit a job
curl -X POST http://localhost:8080/api/v1/jobs \
  -H "Content-Type: application/json" \
  -d @deploy/kind/example-job.json

# Check status (replace with actual job ID)
curl http://localhost:8080/api/v1/jobs/<job-id>

# List all jobs
curl http://localhost:8080/api/v1/jobs
```

### View Build Output

```bash
# List output files
kubectl exec -n melange deployment/melange-server -- \
  ls -la /var/lib/melange/output/<job-id>/

# View the APK
kubectl exec -n melange deployment/melange-server -- \
  ls -la /var/lib/melange/output/<job-id>/aarch64/
```

### Cleanup

```bash
./deploy/kind/teardown.sh
```

## Directory Structure

```
cmd/
└── melange-server/
    └── main.go              # Entry point

pkg/service/
├── api/
│   └── server.go            # HTTP handlers
├── scheduler/
│   └── scheduler.go         # Job processing
├── store/
│   └── memory.go            # In-memory job store
└── types/
    └── types.go             # Shared types

deploy/kind/
├── Dockerfile               # Container image
├── namespace.yaml           # Kubernetes namespace
├── buildkit.yaml            # BuildKit deployment
├── melange-server.yaml      # Server deployment
├── example-job.json         # Example job payload
├── setup.sh                 # Setup script
└── teardown.sh              # Cleanup script
```

## Roadmap

See [Issue #36](https://github.com/dlorenc/melange/issues/36) for the full design and roadmap.

### MVP (Current)
- [x] REST API for job submission
- [x] In-memory job store
- [x] Single BuildKit instance
- [x] Local filesystem output
- [x] kind deployment

### Next Phase
- [ ] GCS storage backend
- [ ] PostgreSQL job store
- [ ] GKE deployment with gVisor sandbox
- [ ] Multiple architecture support

### Future
- [ ] Git source with glob patterns
- [ ] Multi-package DAG execution
- [ ] Live log streaming
- [ ] APK signing
