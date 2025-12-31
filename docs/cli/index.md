# melange2 CLI Reference

melange2 is a BuildKit-based APK package builder. This reference documents all available commands and their options.

## Installation

```bash
go build -o melange2 .
```

## Usage

```
melange [command] [flags]
```

## Global Flags

These flags are available for all commands:

| Flag | Default | Description |
|------|---------|-------------|
| `--log-level` | (none) | Log level (e.g., debug, info, warn, error) |
| `--gcplog` | `false` | Use GCP logging (hidden flag) |

## Commands

### Package Building

| Command | Description |
|---------|-------------|
| [`build`](build.md) | Build a package from a YAML configuration file |
| [`test`](test.md) | Test a package with a YAML configuration file |
| `compile` | Compile a YAML configuration file |

### Package Signing

| Command | Description |
|---------|-------------|
| [`keygen`](keygen.md) | Generate a key for package signing |
| [`sign`](sign.md) | Sign an APK package |
| [`sign-index`](sign.md#sign-index) | Sign an APK index |

### Remote Builds

| Command | Description |
|---------|-------------|
| [`remote submit`](remote.md#submit) | Submit build(s) to the server |
| [`remote status`](remote.md#status) | Get the status of a build |
| [`remote list`](remote.md#list) | List all builds |
| [`remote wait`](remote.md#wait) | Wait for a build to complete |
| [`remote backends`](remote.md#backends) | Manage BuildKit backends |

### Repository Management

| Command | Description |
|---------|-------------|
| `index` | Create a repository index from a list of package files |
| `lint` | Lint an APK, checking for problems and errors (EXPERIMENTAL) |

### Utilities

| Command | Description |
|---------|-------------|
| `completion` | Generate shell completion script |
| `version` | Print version information |
| `query` | Query package information |
| `scan` | Scan packages |
| `package-version` | Get package version |

## Quick Start

### Build a Package

```bash
# Start BuildKit daemon
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234

# Build a package
./melange2 build mypackage.yaml --buildkit-addr tcp://localhost:1234
```

### Generate Signing Keys

```bash
./melange2 keygen mykey.rsa
```

### Sign Packages

```bash
./melange2 sign --signing-key mykey.rsa packages/x86_64/*.apk
```

### Create Repository Index

```bash
./melange2 index -o APKINDEX.tar.gz packages/x86_64/*.apk
```

### Remote Builds

```bash
# Submit a build to a remote server
./melange2 remote submit mypackage.yaml --server http://localhost:8080 --wait

# Check build status
./melange2 remote status bld-abc123

# List all backends
./melange2 remote backends list
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `HTTP_AUTH` | HTTP authentication in format `basic:REALM:USERNAME:PASSWORD` |

## See Also

- [build command](build.md) - Full build command reference
- [test command](test.md) - Full test command reference
- [sign commands](sign.md) - Package signing reference
- [keygen command](keygen.md) - Key generation reference
- [remote commands](remote.md) - Remote build server reference
