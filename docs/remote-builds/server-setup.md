# Running melange-server

This guide covers how to run the melange-server for remote builds.

## Quick Start

### 1. Start BuildKit

The server requires a BuildKit daemon for executing builds:

```bash
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234
```

### 2. Build and Run the Server

```bash
# Build the server binary
go build -o melange-server ./cmd/melange-server/

# Run with default settings
./melange-server --buildkit-addr tcp://localhost:1234
```

The server is now listening on `http://localhost:8080`.

### 3. Verify

```bash
curl http://localhost:8080/healthz
# {"status":"ok"}
```

## Server Binary

The server is built from `cmd/melange-server/main.go`:

```bash
go build -o melange-server ./cmd/melange-server/
```

## Command Line Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--listen-addr` | string | `:8080` | HTTP listen address (host:port) |
| `--buildkit-addr` | string | - | BuildKit daemon address for single-backend mode |
| `--backends-config` | string | - | Path to backends YAML config file (multi-backend mode) |
| `--default-arch` | string | `x86_64` | Default architecture for single-backend mode |
| `--output-dir` | string | `/var/lib/melange/output` | Directory for build outputs (local storage) |
| `--gcs-bucket` | string | - | GCS bucket name (enables GCS storage) |

### Usage Examples

**Single Backend (Development)**

```bash
./melange-server \
  --listen-addr :8080 \
  --buildkit-addr tcp://localhost:1234 \
  --default-arch x86_64 \
  --output-dir ./output
```

**Multi-Backend Pool**

```bash
./melange-server \
  --listen-addr :8080 \
  --backends-config /etc/melange/backends.yaml \
  --output-dir /var/lib/melange/output
```

**With GCS Storage (Production)**

```bash
./melange-server \
  --listen-addr :8080 \
  --backends-config /etc/melange/backends.yaml \
  --gcs-bucket my-project-melange-builds
```

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `CACHE_REGISTRY` | Registry URL for BuildKit cache-to/cache-from | `registry:5000/melange-cache` |
| `CACHE_MODE` | Cache export mode | `min` or `max` |

The cache configuration enables BuildKit layer caching across builds:

```bash
export CACHE_REGISTRY="registry:5000/melange-cache"
export CACHE_MODE="max"
./melange-server --backends-config backends.yaml
```

## Storage Backends

### Local Storage

Default mode when `--gcs-bucket` is not set. Artifacts are stored in the local filesystem:

```
/var/lib/melange/output/
  <build-id>-<package-name>/
    logs/
      build.log
    <arch>/
      <package>-<version>.apk
      APKINDEX.tar.gz
```

### GCS Storage

Enabled with `--gcs-bucket`. Artifacts are uploaded to Google Cloud Storage:

```
gs://<bucket>/
  builds/
    <job-id>/
      logs/
        build.log
      artifacts/
        <package>-<version>.apk
```

GCS storage requires appropriate credentials:
- Local development: Use `gcloud auth application-default login`
- GKE: Use Workload Identity (see [GKE Deployment](./gke-deployment.md))

## Backends Configuration

For multi-backend mode, create a YAML configuration file:

```yaml
# backends.yaml
backends:
  - addr: tcp://buildkit-x86:1234
    arch: x86_64
    maxJobs: 4
    labels:
      tier: standard

  - addr: tcp://buildkit-arm:1234
    arch: aarch64
    maxJobs: 2
    labels:
      tier: standard

  - addr: tcp://buildkit-highmem:1234
    arch: x86_64
    maxJobs: 2
    labels:
      tier: high-memory

# Pool-wide settings
defaultMaxJobs: 4        # Default if backend's maxJobs is 0
failureThreshold: 3      # Consecutive failures before circuit opens
recoveryTimeout: 30s     # How long circuit stays open
```

See [Managing Backends](./managing-backends.md) for detailed configuration options.

## HTTP API Endpoints

The server exposes the following REST endpoints:

### Health Check

```
GET /healthz
```

Returns server health status.

**Response:**
```json
{"status": "ok"}
```

### Builds

```
POST /api/v1/builds
```

Create a new build. See [Submitting Builds](./submitting-builds.md) for request format.

**Request Body:**
```json
{
  "config_yaml": "package:\n  name: example\n  ...",
  "arch": "x86_64",
  "debug": false
}
```

**Response (201 Created):**
```json
{
  "id": "bld-abc12345",
  "packages": ["example"]
}
```

---

```
GET /api/v1/builds
```

List all builds.

**Response:**
```json
[
  {
    "id": "bld-abc12345",
    "status": "success",
    "packages": [...],
    "created_at": "2024-01-15T10:30:00Z"
  }
]
```

---

```
GET /api/v1/builds/:id
```

Get a specific build by ID.

**Response:**
```json
{
  "id": "bld-abc12345",
  "status": "running",
  "packages": [
    {
      "name": "lib-a",
      "status": "success",
      "started_at": "2024-01-15T10:30:00Z",
      "finished_at": "2024-01-15T10:31:30Z"
    },
    {
      "name": "app",
      "status": "running",
      "dependencies": ["lib-a"],
      "started_at": "2024-01-15T10:31:35Z"
    }
  ],
  "created_at": "2024-01-15T10:30:00Z",
  "started_at": "2024-01-15T10:30:00Z"
}
```

### Backends

```
GET /api/v1/backends
GET /api/v1/backends?arch=x86_64
```

List backends, optionally filtered by architecture.

**Response:**
```json
{
  "backends": [
    {
      "addr": "tcp://buildkit:1234",
      "arch": "x86_64",
      "labels": {"tier": "standard"}
    }
  ],
  "architectures": ["x86_64", "aarch64"]
}
```

---

```
POST /api/v1/backends
```

Add a new backend dynamically.

**Request Body:**
```json
{
  "addr": "tcp://new-buildkit:1234",
  "arch": "x86_64",
  "labels": {"tier": "standard"}
}
```

**Response (201 Created):**
```json
{
  "addr": "tcp://new-buildkit:1234",
  "arch": "x86_64",
  "labels": {"tier": "standard"}
}
```

---

```
DELETE /api/v1/backends
```

Remove a backend.

**Request Body:**
```json
{
  "addr": "tcp://old-buildkit:1234"
}
```

**Response:** 204 No Content

---

```
GET /api/v1/backends/status
```

Get detailed status of all backends including active jobs and circuit breaker state.

**Response:**
```json
{
  "backends": [
    {
      "addr": "tcp://buildkit:1234",
      "arch": "x86_64",
      "labels": {"tier": "standard"},
      "maxJobs": 4,
      "activeJobs": 2,
      "failures": 0,
      "circuitOpen": false
    }
  ]
}
```

## Scheduler Configuration

The scheduler runs as part of the server process and has the following behavior:

| Setting | Value | Description |
|---------|-------|-------------|
| Poll Interval | 1 second | How often to check for pending builds |
| Max Parallel | CPU count | Maximum concurrent package builds |

The scheduler:
1. Polls the build store for pending/running builds
2. For each build, finds packages whose dependencies are satisfied
3. Acquires a slot on an appropriate backend
4. Executes the package build
5. Updates status and cascades failures to dependents

## Running in Docker

```bash
docker run -d \
  --name melange-server \
  -p 8080:8080 \
  -e CACHE_REGISTRY=registry:5000/melange-cache \
  -v /var/lib/melange:/var/lib/melange \
  your-registry/melange-server:latest \
  --backends-config /etc/melange/backends.yaml
```

## Running in Kubernetes

See [GKE Deployment](./gke-deployment.md) for complete Kubernetes deployment instructions.

## Logging

The server uses structured logging with the following levels:

- **INFO** - Normal operations (build started, completed, etc.)
- **ERROR** - Operation failures (build errors, connection issues)

Logs are written to stderr. In Kubernetes, these are captured by the container runtime.

## Graceful Shutdown

The server handles SIGINT and SIGTERM signals for graceful shutdown:

1. Stop accepting new requests
2. Wait for in-flight requests (up to 10 seconds)
3. Stop scheduler
4. Exit

## Troubleshooting

### Connection Refused

```
error: connection refused
```

The BuildKit daemon is not running or not reachable. Verify:
```bash
docker ps | grep buildkit
curl tcp://localhost:1234  # Should timeout, not refuse
```

### No Available Backend

```
error: no available backend: all backends are at capacity or circuit-open
```

All backends are either:
- At maximum concurrent jobs
- Have open circuit breakers due to failures

Check backend status:
```bash
curl http://localhost:8080/api/v1/backends/status
```

### GCS Permission Denied

```
error: creating GCS storage: googleapi: Error 403: Forbidden
```

The server lacks permission to access the GCS bucket. Ensure:
- Service account has `roles/storage.objectAdmin` on the bucket
- Workload Identity is configured correctly (for GKE)
