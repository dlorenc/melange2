# melange2 remote

Commands for interacting with a remote melange build server.

## Usage

```
melange remote <subcommand> [flags]
```

## Description

The `remote` command group provides subcommands for submitting builds and checking status on a remote melange-server. This enables distributed building of packages across multiple BuildKit backends.

## Subcommands

| Command | Description |
|---------|-------------|
| [`submit`](#submit) | Submit build(s) to the server |
| [`status`](#status) | Get the status of a build |
| [`list`](#list) | List all builds |
| [`wait`](#wait) | Wait for a build to complete |
| [`backends`](#backends) | Manage BuildKit backends |

---

## submit

Submit package configuration file(s) for building on a remote melange-server.

### Usage

```
melange remote submit [config.yaml...] [flags]
```

### Description

Supports three modes:
1. **Single config**: `melange remote submit config.yaml`
2. **Multiple configs**: `melange remote submit pkg1.yaml pkg2.yaml pkg3.yaml`
3. **Git source**: `melange remote submit --git-repo https://github.com/org/packages`

For multi-package builds, packages are built in dependency order based on `environment.contents.packages` declarations.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `http://localhost:8080` | melange-server URL |
| `--arch` | (server decides) | Target architecture |
| `--test` | `false` | Run tests after build |
| `--debug` | `false` | Enable debug logging |
| `--wait` | `false` | Wait for build to complete |
| `--pipeline-dir` | (none) | Directory containing pipeline YAML files (can be specified multiple times) |
| `--backend-selector` | (none) | Backend label selector (key=value, can be specified multiple times) |

#### Git Source Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--git-repo` | (none) | Git repository URL for package configs |
| `--git-ref` | (none) | Git ref (branch/tag/commit) to checkout |
| `--git-pattern` | `*.yaml` | Glob pattern for config files in git repo |
| `--git-path` | (none) | Subdirectory within git repo to search |

### Examples

```bash
# Submit a single build
melange remote submit mypackage.yaml --server http://localhost:8080

# Submit multiple packages (builds in dependency order)
melange remote submit lib-a.yaml lib-b.yaml app.yaml

# Submit from git repository
melange remote submit --git-repo https://github.com/wolfi-dev/os --git-pattern "*.yaml"

# Submit and wait for completion
melange remote submit mypackage.yaml --wait

# Submit with specific architecture
melange remote submit mypackage.yaml --arch aarch64

# Submit with backend selector
melange remote submit mypackage.yaml --backend-selector tier=high-memory

# Submit with custom pipelines
melange remote submit mypackage.yaml --pipeline-dir ./custom-pipelines/
```

---

## status

Get the status of a build.

### Usage

```
melange remote status <build-id> [flags]
```

### Description

Retrieve the current status and per-package details of a build.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `http://localhost:8080` | melange-server URL |

### Examples

```bash
melange remote status bld-abc123
melange remote status bld-abc123 --server http://myserver:8080
```

### Output

The status command displays:
- Build ID
- Overall status (pending, running, completed, failed)
- Creation timestamp
- Architecture
- Start and finish times (if applicable)
- Duration
- Per-package status table with name, status, duration, and error (if any)

---

## list

List all builds on the server.

### Usage

```
melange remote list [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `http://localhost:8080` | melange-server URL |

### Examples

```bash
melange remote list
melange remote list --server http://myserver:8080
```

### Output

Displays a table with columns:
- ID
- STATUS
- PACKAGES (count)
- CREATED

---

## wait

Wait for a build to complete, polling the server at regular intervals.

### Usage

```
melange remote wait <build-id> [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `http://localhost:8080` | melange-server URL |
| `--poll-interval` | `2s` | Interval between status checks |

### Examples

```bash
melange remote wait bld-abc123
melange remote wait bld-abc123 --poll-interval 5s
```

---

## backends

Manage BuildKit backends on the server.

### Usage

```
melange remote backends <subcommand> [flags]
```

### Subcommands

| Command | Description |
|---------|-------------|
| [`list`](#backends-list) | List available BuildKit backends |
| [`add`](#backends-add) | Add a new BuildKit backend |
| [`remove`](#backends-remove) | Remove a BuildKit backend |

---

### backends list

List all available BuildKit backends on the server, with their architectures and labels.

#### Usage

```
melange remote backends list [flags]
```

#### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `http://localhost:8080` | melange-server URL |
| `--arch` | (none) | Filter by architecture |

#### Examples

```bash
# List all backends
melange remote backends list

# List backends for a specific architecture
melange remote backends list --arch aarch64
```

#### Output

Displays:
- Available architectures
- Table with ADDR, ARCH, LABELS columns

---

### backends add

Add a new BuildKit backend to the server's pool.

#### Usage

```
melange remote backends add [flags]
```

#### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `http://localhost:8080` | melange-server URL |
| `--addr` | (required) | BuildKit daemon address (e.g., tcp://buildkit:1234) |
| `--arch` | (required) | Architecture (e.g., x86_64, aarch64) |
| `--label` | (none) | Backend label in key=value format (can be specified multiple times) |

#### Examples

```bash
# Add a basic backend
melange remote backends add --addr tcp://buildkit:1234 --arch x86_64

# Add a backend with labels
melange remote backends add --addr tcp://buildkit:1234 --arch aarch64 \
  --label tier=high-memory --label sandbox=privileged
```

---

### backends remove

Remove a BuildKit backend from the server's pool.

#### Usage

```
melange remote backends remove [flags]
```

#### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `http://localhost:8080` | melange-server URL |
| `--addr` | (required) | BuildKit daemon address to remove |

#### Examples

```bash
# Remove a backend by address
melange remote backends remove --addr tcp://buildkit:1234
```

---

## Server Setup

Before using remote commands, you need a running melange-server. See the deployment documentation for setup instructions.

### Quick Local Setup

```bash
# Start the melange-server
go build -o melange-server ./cmd/melange-server/
./melange-server

# Or use GKE deployment
make gke-setup
make gke-port-forward
```

### GKE Deployment

For production deployments, use the GKE setup:

```bash
# Full GKE setup (creates cluster, bucket, deploys server)
make gke-setup

# Start port forwarding to access the server
make gke-port-forward

# Submit builds
./melange2 remote submit mypackage.yaml --server http://localhost:8080 --wait
```

## Workflow Example

```bash
# 1. Check available backends
./melange2 remote backends list --server http://localhost:8080

# 2. Submit a build
./melange2 remote submit mypackage.yaml --server http://localhost:8080

# Output: Build submitted: bld-abc123

# 3. Check status
./melange2 remote status bld-abc123 --server http://localhost:8080

# 4. Or wait for completion
./melange2 remote wait bld-abc123 --server http://localhost:8080

# 5. Submit and wait in one command
./melange2 remote submit mypackage.yaml --server http://localhost:8080 --wait
```

## See Also

- [build command](build.md) - Local building
- [test command](test.md) - Local testing
