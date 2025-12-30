# Build Environment

The `environment` block defines the build environment configuration, including package repositories, keyring, and packages to install. This configuration follows the apko ImageConfiguration format.

## Basic Structure

```yaml
environment:
  contents:
    repositories:
      - https://packages.wolfi.dev/os
    keyring:
      - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
    packages:
      - build-base
      - busybox
```

## Contents

### repositories

List of APK repository URLs:

```yaml
environment:
  contents:
    repositories:
      - https://packages.wolfi.dev/os
      - https://packages.wolfi.dev/extras
```

### keyring

List of public key URLs for repository signature verification:

```yaml
environment:
  contents:
    keyring:
      - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
```

### packages

List of packages to install in the build environment:

```yaml
environment:
  contents:
    packages:
      - build-base
      - busybox
      - ca-certificates-bundle
      - openssl-dev
      - zlib-dev
```

### build-repositories

Repositories only used during the build phase:

```yaml
environment:
  contents:
    build-repositories:
      - https://packages.wolfi.dev/bootstrap
    repositories:
      - https://packages.wolfi.dev/os
```

## Environment Variables

Set environment variables for the build:

```yaml
environment:
  contents:
    packages:
      - busybox
  environment:
    CFLAGS: "-O2 -pipe"
    LDFLAGS: "-Wl,--as-needed"
    MY_CUSTOM_VAR: "value"
```

### Default Environment Variables

Melange automatically sets these environment variables if not explicitly defined:

| Variable | Default Value |
|----------|---------------|
| `HOME` | `/home/build` |
| `GOPATH` | `/home/build/.cache/go` |
| `GOMODCACHE` | `/var/cache/melange/gomodcache` |

## Accounts

Define users and groups in the build environment:

```yaml
environment:
  contents:
    packages:
      - busybox
  accounts:
    groups:
      - groupname: build
        gid: 1000
    users:
      - username: build
        uid: 1000
        gid: 1000
```

Note: Melange automatically creates a `build` user and group (UID/GID 1000) if not specified.

## Paths

Configure file paths and permissions:

```yaml
environment:
  contents:
    packages:
      - busybox
  paths:
    - path: /var/cache/myapp
      type: directory
      permissions: 0755
      uid: 1000
      gid: 1000
```

## Complete Environment Example

```yaml
environment:
  contents:
    repositories:
      - https://packages.wolfi.dev/os
    keyring:
      - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
    packages:
      - build-base
      - busybox
      - ca-certificates-bundle
      - brotli-dev
      - nghttp2-dev
      - openssl-dev
      - wolfi-base
      - zlib-dev
  environment:
    CFLAGS: "-O2 -pipe"
    HOME: /home/build
  accounts:
    groups:
      - groupname: build
        gid: 1000
    users:
      - username: build
        uid: 1000
        gid: 1000
```

## Variable Substitution

Environment configuration supports variable substitution:

```yaml
vars:
  ssl-version: "3.0.0"

environment:
  contents:
    packages:
      - openssl-dev~${{vars.ssl-version}}
```

## Top-Level Capabilities

The top-level `capabilities` block (separate from `environment`) controls Linux capabilities for the build runner:

```yaml
capabilities:
  add:
    - CAP_NET_ADMIN
  drop:
    - CAP_SYS_ADMIN

environment:
  contents:
    packages:
      - busybox
```

### Supported Capabilities

| Capability | Description |
|------------|-------------|
| `CAP_NET_ADMIN` | Network administration |
| `CAP_NET_BIND_SERVICE` | Bind to privileged ports |
| `CAP_NET_RAW` | Use raw sockets |
| `CAP_IPC_LOCK` | Lock memory |
| `CAP_SYS_ADMIN` | System administration |

## Test Environment

Tests can have their own environment configuration:

```yaml
environment:
  contents:
    packages:
      - build-base
      - busybox

test:
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
        echo "Running tests"
```

Note: The test environment's `packages` list automatically includes the package's runtime dependencies.

## ImageConfiguration Reference

The `environment` block uses the apko `ImageConfiguration` type. Key fields:

```go
type ImageConfiguration struct {
    Contents    ImageContents       // repositories, keyring, packages
    Entrypoint  ImageEntrypoint     // container entrypoint
    Cmd         string              // default command
    StopSignal  string              // signal for stopping
    WorkDir     string              // working directory
    Accounts    ImageAccounts       // users and groups
    Archs       []Architecture      // target architectures
    Environment map[string]string   // environment variables
    Paths       []PathMutation      // path configurations
    VCSUrl      string              // version control URL
    Annotations map[string]string   // metadata annotations
    Volumes     []string            // volume definitions
}
```

## Working with External Environment Files

You can load environment variables from an external file using the `--env-file` flag:

```bash
./melange2 build pkg.yaml --env-file .env
```

The `.env` file format:

```
CFLAGS=-O2 -pipe
LDFLAGS=-Wl,--as-needed
MY_VAR=value
```

Environment variables in the build file override those from the external file.
