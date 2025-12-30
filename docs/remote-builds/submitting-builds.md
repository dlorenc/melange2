# Submitting Builds

This guide covers how to submit builds to a melange-server using the CLI.

## Prerequisites

- A running melange-server (see [Server Setup](./server-setup.md))
- The `melange2` CLI binary

## Quick Start

```bash
# Submit a single package and wait for completion
./melange2 remote submit mypackage.yaml --server http://localhost:8080 --wait

# Check status of a build
./melange2 remote status bld-abc123 --server http://localhost:8080

# List all builds
./melange2 remote list --server http://localhost:8080
```

## CLI Commands

### remote submit

Submit package configuration(s) for building.

```
melange2 remote submit [config.yaml...] [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--server` | string | `http://localhost:8080` | melange-server URL |
| `--arch` | string | - | Target architecture (e.g., `x86_64`, `aarch64`) |
| `--test` | bool | `false` | Run tests after build |
| `--debug` | bool | `false` | Enable debug logging |
| `--wait` | bool | `false` | Wait for build to complete |
| `--pipeline-dir` | strings | - | Directories containing pipeline YAML files |
| `--backend-selector` | strings | - | Backend label selector (`key=value`) |
| `--git-repo` | string | - | Git repository URL for package configs |
| `--git-ref` | string | - | Git ref (branch/tag/commit) to checkout |
| `--git-pattern` | string | `*.yaml` | Glob pattern for config files in git repo |
| `--git-path` | string | - | Subdirectory within git repo to search |

**Examples:**

```bash
# Submit a single package
melange2 remote submit mypackage.yaml --server http://localhost:8080

# Submit and wait for completion
melange2 remote submit mypackage.yaml --wait

# Submit with specific architecture
melange2 remote submit mypackage.yaml --arch aarch64

# Submit multiple packages (builds in dependency order)
melange2 remote submit lib-a.yaml lib-b.yaml app.yaml --wait

# Submit with custom pipelines
melange2 remote submit mypackage.yaml --pipeline-dir ./pipelines/

# Submit with backend selector
melange2 remote submit mypackage.yaml --backend-selector tier=high-memory

# Submit from git repository
melange2 remote submit \
  --git-repo https://github.com/wolfi-dev/os \
  --git-pattern "*.yaml" \
  --wait
```

### remote status

Get the status of a build.

```
melange2 remote status <build-id> [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--server` | string | `http://localhost:8080` | melange-server URL |

**Example Output:**

```
Build ID:   bld-abc12345
Status:     running
Created:    2024-01-15T10:30:00Z
Arch:       x86_64
Started:    2024-01-15T10:30:05Z

Packages (3):
  NAME     STATUS    DURATION  ERROR
  lib-a    success   1m30s
  lib-b    running   45s
  app      pending   -
```

### remote list

List all builds on the server.

```
melange2 remote list [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--server` | string | `http://localhost:8080` | melange-server URL |

**Example Output:**

```
ID            STATUS    PACKAGES  CREATED
bld-abc123    success   3         2024-01-15T10:30:00Z
bld-def456    running   5         2024-01-15T11:00:00Z
bld-ghi789    failed    2         2024-01-15T11:15:00Z
```

### remote wait

Wait for a build to complete.

```
melange2 remote wait <build-id> [flags]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--server` | string | `http://localhost:8080` | melange-server URL |
| `--poll-interval` | duration | `2s` | Interval between status checks |

**Example:**

```bash
# Wait with custom poll interval
melange2 remote wait bld-abc123 --poll-interval 5s
```

## Build Modes

### Single Package

Submit one package configuration:

```bash
melange2 remote submit mypackage.yaml --wait
```

The server creates a build with one package.

### Multi-Package

Submit multiple package configurations:

```bash
melange2 remote submit lib-a.yaml lib-b.yaml app.yaml --wait
```

The server:
1. Parses all configs
2. Extracts dependencies from `environment.contents.packages`
3. Builds a dependency graph
4. Sorts packages topologically
5. Builds in dependency order with parallelism where possible

### Git Source

Build packages from a git repository:

```bash
melange2 remote submit \
  --git-repo https://github.com/wolfi-dev/os \
  --git-ref main \
  --git-pattern "*.yaml" \
  --git-path "" \
  --wait
```

The server:
1. Clones the repository
2. Finds configs matching the pattern
3. Processes them as a multi-package build

## Request Format (HTTP API)

For direct API integration, the build request format is:

### Single Config

```json
{
  "config_yaml": "package:\n  name: example\n  version: 1.0.0\n...",
  "arch": "x86_64",
  "debug": false,
  "with_test": false
}
```

### Multiple Configs

```json
{
  "configs": [
    "package:\n  name: lib-a\n...",
    "package:\n  name: lib-b\n  ...\nenvironment:\n  contents:\n    packages:\n      - lib-a\n...",
    "package:\n  name: app\n  ...\nenvironment:\n  contents:\n    packages:\n      - lib-b\n..."
  ],
  "arch": "x86_64"
}
```

### Git Source

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

### With Pipelines

Include custom pipelines inline:

```json
{
  "config_yaml": "...",
  "pipelines": {
    "custom/build.yaml": "name: Custom Build\npipeline:\n  - runs: make build",
    "custom/test.yaml": "name: Custom Test\npipeline:\n  - runs: make test"
  }
}
```

### With Backend Selection

Target specific backends:

```json
{
  "config_yaml": "...",
  "arch": "x86_64",
  "backend_selector": {
    "tier": "high-memory",
    "sandbox": "privileged"
  }
}
```

## Response Format

### Create Build Response

```json
{
  "id": "bld-abc12345",
  "packages": ["lib-a", "lib-b", "app"]
}
```

The `packages` array lists packages in build order (topologically sorted).

### Build Status Response

```json
{
  "id": "bld-abc12345",
  "status": "running",
  "packages": [
    {
      "name": "lib-a",
      "status": "success",
      "config_yaml": "...",
      "dependencies": [],
      "started_at": "2024-01-15T10:30:00Z",
      "finished_at": "2024-01-15T10:31:30Z",
      "log_path": "gs://bucket/builds/bld-abc12345-lib-a/logs/build.log",
      "output_path": "gs://bucket/builds/bld-abc12345-lib-a/",
      "backend": {
        "addr": "tcp://buildkit:1234",
        "arch": "x86_64",
        "labels": {"tier": "standard"}
      }
    },
    {
      "name": "lib-b",
      "status": "running",
      "config_yaml": "...",
      "dependencies": ["lib-a"],
      "started_at": "2024-01-15T10:31:35Z",
      "backend": {
        "addr": "tcp://buildkit:1234",
        "arch": "x86_64"
      }
    },
    {
      "name": "app",
      "status": "pending",
      "config_yaml": "...",
      "dependencies": ["lib-b"]
    }
  ],
  "spec": {
    "configs": ["..."],
    "arch": "x86_64"
  },
  "created_at": "2024-01-15T10:30:00Z",
  "started_at": "2024-01-15T10:30:00Z"
}
```

## Dependency Handling

Dependencies are extracted from each package's `environment.contents.packages`:

```yaml
package:
  name: app
  version: 1.0.0

environment:
  contents:
    packages:
      - lib-a
      - lib-b
```

The server:
1. Only considers dependencies that are part of the current build
2. External dependencies (from Wolfi, Alpine, etc.) are ignored for ordering
3. Circular dependencies result in an error
4. Packages with satisfied dependencies build in parallel

## Exit Codes

The CLI returns these exit codes:

| Code | Meaning |
|------|---------|
| 0 | Success (or build completed successfully with `--wait`) |
| 1 | Error (connection, API error, or build failed with `--wait`) |

## Common Patterns

### CI/CD Integration

```bash
#!/bin/bash
set -e

# Submit build and wait
./melange2 remote submit \
  --server "$MELANGE_SERVER" \
  --arch x86_64 \
  --wait \
  mypackage.yaml

echo "Build succeeded!"
```

### Batch Building

```bash
# Build all packages in a directory
./melange2 remote submit \
  --server http://localhost:8080 \
  --wait \
  packages/*.yaml
```

### Using Custom Pipelines

```bash
# Include local pipelines directory
./melange2 remote submit \
  --server http://localhost:8080 \
  --pipeline-dir ./pipelines \
  --wait \
  mypackage.yaml
```

### Targeting High-Memory Backends

```bash
# Use backends with high-memory label
./melange2 remote submit \
  --server http://localhost:8080 \
  --backend-selector tier=high-memory \
  --wait \
  large-package.yaml
```

## Troubleshooting

### Build Not Starting

```
Status: pending (for a long time)
```

Check:
1. Are backends available? `melange2 remote backends list`
2. Is the architecture supported? Check `architectures` in backends list
3. Are backends healthy? `curl http://server:8080/api/v1/backends/status`

### Dependency Not Found

```
error: dependency error: circular dependency detected: A -> B -> A
```

Check your package dependencies for cycles.

### Package Skipped

```
Status: skipped
Error: dependency lib-a failed
```

A dependency failed, so this package was automatically skipped. Check the failing dependency's error message.
