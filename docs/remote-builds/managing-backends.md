# Managing Backends

This guide covers how to configure and manage BuildKit backends in the melange-server pool.

## Overview

The BuildKit pool manages a collection of backends with support for:

- **Multi-architecture** - Route builds to appropriate backends (x86_64, aarch64)
- **Label-based selection** - Filter backends by custom labels
- **Load balancing** - Select least-loaded backend
- **Per-backend throttling** - Limit concurrent jobs
- **Circuit breaker** - Exclude failing backends

## Configuration Methods

### 1. Single Backend Mode (Legacy)

For simple setups with one BuildKit daemon:

```bash
./melange-server \
  --buildkit-addr tcp://localhost:1234 \
  --default-arch x86_64
```

### 2. Multi-Backend Configuration File

For production deployments with multiple backends:

```bash
./melange-server \
  --backends-config /etc/melange/backends.yaml
```

### 3. Dynamic Management via API

Add/remove backends at runtime:

```bash
# Add a backend
melange2 remote backends add \
  --addr tcp://new-buildkit:1234 \
  --arch x86_64 \
  --label tier=standard

# Remove a backend
melange2 remote backends remove --addr tcp://old-buildkit:1234
```

## Configuration File Format

Create a YAML file with your backend pool configuration:

```yaml
# backends.yaml
backends:
  # Standard x86_64 backend
  - addr: tcp://buildkit-x86:1234
    arch: x86_64
    maxJobs: 4
    labels:
      tier: standard
      location: us-central1

  # ARM64 backend
  - addr: tcp://buildkit-arm:1234
    arch: aarch64
    maxJobs: 2
    labels:
      tier: standard

  # High-memory x86_64 backend for large builds
  - addr: tcp://buildkit-highmem:1234
    arch: x86_64
    maxJobs: 2
    labels:
      tier: high-memory
      memory: 64gi

# Pool-wide configuration
defaultMaxJobs: 4        # Default if backend's maxJobs is 0
failureThreshold: 3      # Consecutive failures before circuit opens
recoveryTimeout: 30s     # How long circuit stays open before retry
```

### Backend Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `addr` | string | Yes | BuildKit daemon address (e.g., `tcp://host:1234`) |
| `arch` | string | Yes | Target architecture (`x86_64`, `aarch64`) |
| `maxJobs` | int | No | Max concurrent jobs (default: pool's `defaultMaxJobs`) |
| `labels` | map | No | Key-value pairs for selection |

### Pool Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `defaultMaxJobs` | int | 4 | Default max jobs per backend |
| `failureThreshold` | int | 3 | Failures before opening circuit |
| `recoveryTimeout` | duration | 30s | Time circuit stays open |

## CLI Commands

### backends list

List all backends in the pool.

```
melange2 remote backends list [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--server` | string | `http://localhost:8080` | melange-server URL |
| `--arch` | string | - | Filter by architecture |

**Examples:**

```bash
# List all backends
melange2 remote backends list

# List only x86_64 backends
melange2 remote backends list --arch x86_64
```

**Example Output:**

```
Available architectures: [x86_64 aarch64]

ADDR                          ARCH      LABELS
tcp://buildkit-x86:1234       x86_64    tier=standard,location=us-central1
tcp://buildkit-arm:1234       aarch64   tier=standard
tcp://buildkit-highmem:1234   x86_64    tier=high-memory,memory=64gi
```

### backends add

Add a new backend to the pool.

```
melange2 remote backends add [flags]
```

**Flags:**

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--server` | string | No | melange-server URL |
| `--addr` | string | Yes | BuildKit daemon address |
| `--arch` | string | Yes | Architecture |
| `--label` | strings | No | Labels (`key=value`, repeatable) |

**Examples:**

```bash
# Add a basic backend
melange2 remote backends add \
  --addr tcp://buildkit:1234 \
  --arch x86_64

# Add with labels
melange2 remote backends add \
  --addr tcp://buildkit-special:1234 \
  --arch x86_64 \
  --label tier=high-memory \
  --label sandbox=privileged
```

### backends remove

Remove a backend from the pool.

```
melange2 remote backends remove [flags]
```

**Flags:**

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--server` | string | No | melange-server URL |
| `--addr` | string | Yes | BuildKit daemon address to remove |

**Example:**

```bash
melange2 remote backends remove --addr tcp://old-buildkit:1234
```

**Note:** You cannot remove the last backend in the pool.

## Backend Selection

When scheduling a build, the pool selects a backend based on:

1. **Architecture Match** - Backend must support the target architecture
2. **Label Match** - Backend must have all required labels (if selector specified)
3. **Capacity** - Backend must have available job slots
4. **Circuit State** - Backend's circuit breaker must not be open
5. **Load** - Prefer backend with lowest current load

### Selection Algorithm

```
For each backend:
  1. Skip if arch != target arch
  2. Skip if labels don't match selector
  3. Skip if circuit breaker is open (and not in recovery window)
  4. Skip if activeJobs >= maxJobs
  5. Calculate load = activeJobs / maxJobs
  6. Select backend with lowest load
```

### Using Backend Selectors

Request specific backend characteristics:

```bash
# Require high-memory tier
melange2 remote submit mypackage.yaml \
  --backend-selector tier=high-memory

# Require multiple labels
melange2 remote submit mypackage.yaml \
  --backend-selector tier=high-memory \
  --backend-selector sandbox=privileged
```

Via API:

```json
{
  "config_yaml": "...",
  "backend_selector": {
    "tier": "high-memory",
    "sandbox": "privileged"
  }
}
```

## Throttling

Each backend has a maximum number of concurrent jobs:

```yaml
backends:
  - addr: tcp://buildkit:1234
    arch: x86_64
    maxJobs: 4  # Max 4 concurrent builds
```

When a backend reaches capacity:
- New builds wait for a slot
- If no backends have capacity, the build stays pending
- Scheduler retries on the next poll interval (1 second)

### Acquire/Release Flow

```
1. Scheduler selects backend with capacity
2. Scheduler acquires a slot (atomic increment of activeJobs)
3. Build executes
4. Scheduler releases slot (atomic decrement)
5. Scheduler records success/failure for circuit breaker
```

## Circuit Breaker

The circuit breaker protects the pool from repeatedly using failing backends.

### States

```
         success
CLOSED <---------> HALF-OPEN
   |                   ^
   | failureThreshold  | recoveryTimeout
   |   failures        | elapsed
   v                   |
  OPEN ----------------+
```

| State | Behavior |
|-------|----------|
| **Closed** | Normal operation, accepting jobs |
| **Open** | Excluded from selection, no new jobs |
| **Half-Open** | After recovery timeout, allow one attempt |

### Configuration

```yaml
failureThreshold: 3      # 3 consecutive failures opens circuit
recoveryTimeout: 30s     # Wait 30s before retry
```

### Behavior

1. Each failure increments the failure counter
2. Each success resets the failure counter to 0
3. When failures >= threshold, circuit opens
4. Open circuits are skipped during selection
5. After recovery timeout, one attempt is allowed (half-open)
6. If half-open attempt succeeds, circuit closes
7. If half-open attempt fails, circuit stays open

## Observability

### Backend Status API

Get detailed status of all backends:

```bash
curl http://localhost:8080/api/v1/backends/status
```

Response:

```json
{
  "backends": [
    {
      "addr": "tcp://buildkit-x86:1234",
      "arch": "x86_64",
      "labels": {"tier": "standard"},
      "maxJobs": 4,
      "activeJobs": 2,
      "failures": 0,
      "circuitOpen": false,
      "lastFailure": "0001-01-01T00:00:00Z"
    },
    {
      "addr": "tcp://buildkit-arm:1234",
      "arch": "aarch64",
      "labels": {"tier": "standard"},
      "maxJobs": 2,
      "activeJobs": 0,
      "failures": 2,
      "circuitOpen": false,
      "lastFailure": "2024-01-15T10:30:00Z"
    },
    {
      "addr": "tcp://buildkit-broken:1234",
      "arch": "x86_64",
      "labels": {},
      "maxJobs": 4,
      "activeJobs": 0,
      "failures": 3,
      "circuitOpen": true,
      "lastFailure": "2024-01-15T10:35:00Z"
    }
  ]
}
```

### Status Fields

| Field | Description |
|-------|-------------|
| `activeJobs` | Current number of running jobs |
| `failures` | Consecutive failure count |
| `circuitOpen` | Whether circuit breaker is open |
| `lastFailure` | Timestamp of last failure |

## Best Practices

### 1. Size Your Pool

- At least 2 backends for redundancy
- Consider architecture needs (x86_64 and aarch64)
- Set appropriate `maxJobs` based on backend resources

### 2. Use Labels for Segmentation

```yaml
backends:
  # Standard builds
  - addr: tcp://buildkit-1:1234
    arch: x86_64
    labels:
      tier: standard

  # Resource-intensive builds
  - addr: tcp://buildkit-highmem:1234
    arch: x86_64
    labels:
      tier: high-memory

  # Builds requiring privileged containers
  - addr: tcp://buildkit-privileged:1234
    arch: x86_64
    labels:
      tier: standard
      sandbox: privileged
```

### 3. Monitor Circuit Breaker State

Regularly check `/api/v1/backends/status`:
- Open circuits indicate backend problems
- High failure counts may indicate impending issues
- Use alerting on circuit state changes

### 4. Tune Throttling

```yaml
# For powerful backends
- addr: tcp://buildkit-powerful:1234
  maxJobs: 8

# For smaller backends
- addr: tcp://buildkit-small:1234
  maxJobs: 2
```

### 5. Set Appropriate Recovery Timeout

```yaml
# Shorter for transient failures
recoveryTimeout: 15s

# Longer for backends needing manual intervention
recoveryTimeout: 5m
```

## Kubernetes Backend Discovery

In Kubernetes, you can configure backends using in-cluster DNS:

```yaml
backends:
  - addr: tcp://buildkit.melange.svc.cluster.local:1234
    arch: x86_64
    maxJobs: 4
```

For StatefulSets with multiple replicas:

```yaml
backends:
  - addr: tcp://buildkit-0.buildkit.melange.svc.cluster.local:1234
    arch: x86_64
    maxJobs: 4
  - addr: tcp://buildkit-1.buildkit.melange.svc.cluster.local:1234
    arch: x86_64
    maxJobs: 4
```

## Troubleshooting

### All Backends at Capacity

```
error: no available backend: all backends are at capacity or circuit-open
```

Solutions:
1. Wait for current builds to complete
2. Add more backends
3. Increase `maxJobs` on existing backends

### Circuit Open on All Backends

Check backend status and logs:

```bash
# Check status
curl http://localhost:8080/api/v1/backends/status

# For Kubernetes, check BuildKit pods
kubectl logs -n melange deployment/buildkit
```

Common causes:
- BuildKit daemon crashed
- Network connectivity issues
- Resource exhaustion (disk, memory)

### Backend Not Selected

If builds aren't using a specific backend:

1. Check architecture matches
2. Check labels match selector
3. Check circuit breaker state
4. Verify backend is reachable from server
