# melange2 test

Test a package with a YAML configuration file containing a test pipeline.

## Usage

```
melange test <test.yaml> [package-name] [flags]
```

## Description

The `test` command runs test pipelines defined in YAML configuration files against built packages. It uses BuildKit as the execution backend, similar to the build command.

## Example

```bash
melange test <test.yaml> [package-name]
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `test.yaml` | Yes | YAML configuration file containing test pipeline |
| `package-name` | No | Specific package name to test (optional) |

## Flags

### Input/Output Options

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--source-dir` | | (none) | Directory used for included sources |
| `--workspace-dir` | | (none) | Directory used for the workspace at /home/build |

### Build Configuration

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--arch` | | (all) | Architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config |

### Pipelines

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--pipeline-dirs` | | `[]` | Directories used to extend defined built-in pipelines |

### Caching

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--cache-dir` | | (none) | Directory used for cached inputs |
| `--apk-cache-dir` | | (system default) | Directory used for cached apk packages |

### Repository Configuration

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--keyring-append` | `-k` | `[]` | Path to extra keys to include in the build environment keyring |
| `--repository-append` | `-r` | `[]` | Path to extra repositories to include in the build environment |
| `--test-package-append` | | `[]` | Extra packages to install for each of the test environments |
| `--ignore-signatures` | | `false` | Ignore repository signature verification |

### Variables and Environment

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--env-file` | | (none) | File to use for preloaded environment variables |

### BuildKit Options

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--buildkit-addr` | | `tcp://localhost:1234` | BuildKit daemon address (e.g., tcp://localhost:1234) |

### Debugging

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--debug` | | `false` | Enables debug logging of test pipelines (sets -x for steps) |

## Examples

### Basic Test

```bash
./melange2 test mypackage-test.yaml --buildkit-addr tcp://localhost:1234
```

### Test Specific Package

```bash
./melange2 test mypackage-test.yaml mypackage --buildkit-addr tcp://localhost:1234
```

### Test with Debug Logging

```bash
./melange2 test mypackage-test.yaml --debug
```

### Test for Specific Architectures

```bash
./melange2 test mypackage-test.yaml --arch x86_64,aarch64
```

### Test with Custom Repositories

```bash
./melange2 test mypackage-test.yaml \
  --repository-append https://packages.wolfi.dev/os \
  --keyring-append /path/to/wolfi-signing.rsa.pub
```

### Test with Extra Test Packages

```bash
./melange2 test mypackage-test.yaml \
  --test-package-append curl \
  --test-package-append jq
```

### Test with Custom Pipeline Directory

```bash
./melange2 test mypackage-test.yaml \
  --pipeline-dirs ./custom-pipelines/
```

## Prerequisites

Before testing packages, you need a running BuildKit daemon:

```bash
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234
```

## Test Configuration File

The test configuration YAML file should define a test pipeline. Example:

```yaml
package:
  name: mypackage-test
  version: 1.0.0

test:
  environment:
    contents:
      packages:
        - mypackage
  pipeline:
    - runs: |
        mypackage --version
        mypackage --help
```

## See Also

- [build command](build.md) - Build packages before testing
- [remote commands](remote.md) - Remote build/test server
