# Testing Packages

melange2 includes built-in support for testing packages after they are built. Tests verify that packages work correctly in a clean environment with only the declared dependencies installed.

## Overview

The test system allows you to define test pipelines that run after a package is built. Tests execute in a separate container environment where:

- The built package is installed
- Any additional test dependencies are installed
- Test commands run to verify functionality

This ensures packages work correctly for end users, not just during the build process.

## Test Block Structure

Tests are defined in a `test:` block at the top level of a configuration file (for the main package) or within subpackage definitions:

```yaml
test:
  environment:
    contents:
      packages:
        - additional-test-dependency
  pipeline:
    - name: verify-installation
      runs: |
        mycommand --version
```

### Test Configuration Fields

| Field | Type | Description |
|-------|------|-------------|
| `environment` | object | Additional environment configuration for tests |
| `environment.contents.packages` | list | Extra packages to install in the test environment |
| `pipeline` | list | Test pipeline steps (same structure as build pipelines) |

The `environment.contents.packages` field automatically includes:
- The package being tested (main package or subpackage)
- Any runtime dependencies declared in `dependencies.runtime`

### Test Pipeline Steps

Test pipelines use the same structure as build pipelines:

```yaml
test:
  pipeline:
    - name: step-name        # Optional: human-readable name
      runs: |                # Shell commands to execute
        command1
        command2
    - uses: pipeline/name    # Can also use reusable pipelines
      with:
        input: value
```

## Execution Environment

### Build User

Tests run as the `build` user (UID 1000, GID 1000), not as root. This matches the build environment and ensures file permissions work correctly.

### Working Directory

The default working directory is `/home/build`. You can specify a different working directory per step:

```yaml
test:
  pipeline:
    - name: run-in-subdir
      working-directory: /tmp/test
      runs: |
        pwd  # outputs /tmp/test
```

### Environment Variables

Tests inherit these environment variables by default:

| Variable | Default Value |
|----------|---------------|
| `HOME` | `/home/build` |
| `PATH` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` |

Additional environment variables from the test environment configuration are merged in:

```yaml
test:
  environment:
    environment:
      MY_VAR: "custom-value"
  pipeline:
    - runs: echo $MY_VAR
```

### Test Isolation

Each package and subpackage test runs in a **fresh container**. This ensures:

- Tests cannot accidentally pass due to artifacts from previous tests
- Missing dependencies are properly detected
- Subpackage tests verify their own declared dependencies

For example, if the main package test creates a file, subpackage tests will not see that file because they run in separate containers.

## Running Tests

### Command Line

Run tests for a package using the `test` command:

```bash
# Basic usage
./melange2 test mypackage.yaml --buildkit-addr tcp://localhost:1234

# Specify architecture
./melange2 test mypackage.yaml --arch x86_64 --buildkit-addr tcp://localhost:1234

# Enable debug mode (shows shell commands)
./melange2 test mypackage.yaml --debug --buildkit-addr tcp://localhost:1234
```

### Test Command Flags

| Flag | Description |
|------|-------------|
| `--arch` | Target architecture(s) to test |
| `--buildkit-addr` | BuildKit daemon address |
| `--debug` | Enable debug logging (sets -x for shell steps) |
| `--keyring-append`, `-k` | Extra keys for the test environment |
| `--repository-append`, `-r` | Extra repositories for the test environment |
| `--test-package-append` | Extra packages to install in test environments |
| `--ignore-signatures` | Ignore repository signature verification |
| `--pipeline-dirs` | Additional directories for custom pipelines |
| `--source-dir` | Directory containing test fixtures |
| `--workspace-dir` | Custom workspace directory |
| `--cache-dir` | Directory for cached inputs |
| `--apk-cache-dir` | Directory for cached APK packages |
| `--env-file` | File with preloaded environment variables |

### Remote Testing

When using remote builds, you can run tests automatically after the build:

```bash
./melange2 remote submit pkg.yaml --server http://localhost:8080 --test --wait
```

## Test Results

### Success

When all tests pass, melange2 outputs:

```
INFO: all tests passed
```

### Failure

When a test fails, the pipeline stops immediately and reports the error:

```
ERROR: main package tests failed: test execution failed: ...
```

The specific failing step is identified in the error message.

### Skipping Tests

Tests are skipped when:

- No `test:` block is defined
- The test pipeline is empty
- The target architecture is not in `target-architecture`

When tests are skipped, you see:

```
INFO: no test pipelines defined, skipping
```

## Test Resources

For packages that need significant resources during testing, you can specify separate test resource requirements:

```yaml
package:
  name: my-package
  version: 1.0.0
  resources:
    cpu: "8"
    memory: "16Gi"
  test-resources:
    cpu: "2"
    memory: "4Gi"
```

The `test-resources` field is used by schedulers (like remote build servers) to provision appropriately-sized environments for test execution. If not specified, tests use the same resources as builds.

## Best Practices

### Test What Users Will See

Tests run in a clean environment with only declared dependencies. This catches:

- Missing runtime dependencies
- Hardcoded paths from the build environment
- Implicit dependencies on build tools

### Keep Tests Fast

Tests run on every build. Focus on:

- Verifying the binary runs (`--version`, `--help`)
- Testing core functionality
- Checking configuration file locations

Avoid:

- Long-running integration tests
- Network-dependent tests (when possible)
- Tests that require significant setup

### Use Named Steps

Name your test steps for better error reporting:

```yaml
test:
  pipeline:
    - name: verify-version-output
      runs: |
        myapp --version | grep "1.0.0"
```

### Test Subpackages Independently

If you split functionality into subpackages, test each one:

```yaml
subpackages:
  - name: myapp-tools
    pipeline:
      - uses: split/bin
    test:
      pipeline:
        - runs: mytool --help
```

## Next Steps

- See [Test Examples](test-examples.md) for common testing patterns
- Learn about [Build Pipelines](../build-files/pipelines.md) used in tests
- Explore [Remote Builds](../remote-builds/index.md) with integrated testing
