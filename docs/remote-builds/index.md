# Remote Builds Architecture

This document provides an overview of the melange2 remote build system, which enables distributed package building using BuildKit backends.

## Overview

The remote build system consists of three main components:

1. **melange-server** - HTTP API server that accepts build requests and orchestrates execution
2. **BuildKit Pool** - Collection of BuildKit daemon backends for executing builds
3. **Storage Backend** - Artifact and log storage (local filesystem or Google Cloud Storage)

## Architecture Diagram

```
                                    +------------------+
                                    |   melange CLI    |
                                    | (remote submit)  |
                                    +--------+---------+
                                             |
                                             | HTTP POST /api/v1/builds
                                             v
+----------------------+            +------------------+
|   Storage Backend    |<---------->|  melange-server  |
| (Local / GCS)        |            |                  |
+----------------------+            +--------+---------+
                                             |
                                             | Schedule & Execute
                                             v
                              +-----------------------------+
                              |      BuildKit Pool          |
                              |                             |
                              |  +--------+    +--------+   |
                              |  |Backend |    |Backend |   |
                              |  |x86_64  |    |aarch64 |   |
                              |  +--------+    +--------+   |
                              +-----------------------------+
```

## Component Responsibilities

### melange-server

The server is the central coordinator for remote builds:

- **HTTP API** - Exposes REST endpoints for build submission, status queries, and backend management
- **Build Store** - Tracks all builds and their package jobs (in-memory, with support for future persistent stores)
- **Scheduler** - Polls for pending builds and dispatches package jobs to backends
- **DAG Processing** - Parses package dependencies and builds in topological order

### BuildKit Pool

The pool manages BuildKit backends with:

- **Multi-Architecture Support** - Route builds to appropriate backends based on target architecture
- **Label-Based Selection** - Filter backends by custom labels (e.g., `tier=high-memory`)
- **Load-Aware Routing** - Select least-loaded backend when multiple are available
- **Per-Backend Throttling** - Limit concurrent jobs per backend (`maxJobs`)
- **Circuit Breaker** - Automatically exclude failing backends after consecutive failures

### Storage Backend

Two storage backends are supported:

| Backend | Use Case | Artifacts Location |
|---------|----------|-------------------|
| **Local** | Development/testing | `/var/lib/melange/output/<job-id>/` |
| **GCS** | Production/GKE | `gs://<bucket>/builds/<job-id>/` |

## Build Lifecycle

1. **Submission** - Client submits build request with one or more package configs
2. **DAG Construction** - Server parses configs and builds dependency graph
3. **Scheduling** - Scheduler picks up pending builds and claims ready packages
4. **Execution** - Package builds execute on selected BuildKit backends
5. **Cascade** - On success, dependent packages become ready; on failure, dependents are skipped
6. **Completion** - Build status updates to success, failed, or partial

## Build Status Values

### Build Status

| Status | Description |
|--------|-------------|
| `pending` | Build created, waiting for scheduler |
| `running` | At least one package is building |
| `success` | All packages built successfully |
| `failed` | All packages failed or were skipped |
| `partial` | Some packages succeeded, some failed |

### Package Status

| Status | Description |
|--------|-------------|
| `pending` | Waiting for dependencies or scheduler |
| `blocked` | Waiting on dependencies (synonym for pending) |
| `running` | Currently building |
| `success` | Build completed successfully |
| `failed` | Build failed |
| `skipped` | Skipped due to dependency failure |

## Data Flow

### Single Package Build

```
Client                    Server                   Scheduler              BuildKit
  |                         |                         |                      |
  |-- POST /api/v1/builds ->|                         |                      |
  |<-- { id: "bld-xxx" } ---|                         |                      |
  |                         |                         |                      |
  |                         |<-- poll for builds -----|                      |
  |                         |--- Build{pending} ----->|                      |
  |                         |                         |                      |
  |                         |                         |-- Select backend --->|
  |                         |                         |<-- BuildKit LLB -----|
  |                         |                         |                      |
  |                         |<-- Update status -------|                      |
  |                         |                         |                      |
  |-- GET /api/v1/builds/id->                         |                      |
  |<-- { status: "success" }|                         |                      |
```

### Multi-Package Build with Dependencies

```
Given packages: A (no deps), B (depends on A), C (depends on A)

Time 0: Build submitted
  - All packages: pending

Time 1: Scheduler claims A (no dependencies)
  - A: running
  - B, C: pending (blocked on A)

Time 2: A completes successfully
  - A: success
  - B, C: ready (dependencies satisfied)

Time 3: Scheduler claims B and C in parallel
  - B: running
  - C: running

Time 4: Both complete
  - All: success
  - Build status: success
```

## Key Configuration

### Server Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--listen-addr` | HTTP listen address | `:8080` |
| `--buildkit-addr` | Single backend address (legacy mode) | - |
| `--backends-config` | Path to backends YAML config | - |
| `--default-arch` | Default architecture | `x86_64` |
| `--output-dir` | Local output directory | `/var/lib/melange/output` |
| `--gcs-bucket` | GCS bucket for artifacts | - |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `CACHE_REGISTRY` | Registry URL for BuildKit cache |
| `CACHE_MODE` | Cache export mode (`min` or `max`) |

## Related Documentation

- [Server Setup](./server-setup.md) - Running melange-server
- [Submitting Builds](./submitting-builds.md) - Using the remote CLI
- [Managing Backends](./managing-backends.md) - Backend pools and configuration
- [GKE Deployment](./gke-deployment.md) - Production deployment guide
