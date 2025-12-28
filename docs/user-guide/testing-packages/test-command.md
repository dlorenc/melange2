# Testing Packages

melange provides a `test` command to verify that built packages work correctly.

## Overview

Tests use the same pipeline syntax as builds, making them easy to write:

```yaml
package:
  name: mypackage
  version: 1.0.0

pipeline:
  # ... build steps ...

test:
  environment:
    contents:
      packages:
        - busybox
  pipeline:
    - runs: |
        mypackage --version
        mypackage --help
```

## Running Tests

```bash
# Test using the config file
melange2 test package.yaml --buildkit-addr tcp://localhost:1234

# Test a specific package
melange2 test package.yaml mypackage --buildkit-addr tcp://localhost:1234

# Test a specific version
melange2 test package.yaml mypackage=1.0.0-r0 --buildkit-addr tcp://localhost:1234
```

## Test Environment

Each test runs in a fresh container with:
- The package under test (automatically included)
- Packages specified in `test.environment.contents.packages`
- Transitive dependencies resolved by APK

```yaml
test:
  environment:
    contents:
      packages:
        - busybox     # For shell commands
        - python-3    # If testing Python functionality
```

## Test Configuration

### Basic Test

```yaml
test:
  pipeline:
    - runs: |
        # Verify binary exists and runs
        which myapp
        myapp --version
```

### With Environment Variables

```yaml
test:
  environment:
    environment:
      MY_VAR: "test-value"
  pipeline:
    - runs: |
        test "$MY_VAR" = "test-value"
```

### Using Built-in Pipelines

```yaml
test:
  pipeline:
    - uses: python/import
      with:
        imports: |
          import mypackage
          from mypackage import submodule
```

## Subpackage Tests

Test subpackages independently:

```yaml
subpackages:
  - name: ${{package.name}}-dev
    description: Development headers
    pipeline:
      - uses: split/dev
    test:
      environment:
        contents:
          packages:
            - busybox
      pipeline:
        - runs: |
            test -f /usr/include/mylib.h
```

## Test Workspace

Tests share a workspace mounted at the current directory. Add test fixtures with `--source-dir`:

```bash
# Create test files
mkdir /tmp/test-fixtures
echo "test data" > /tmp/test-fixtures/input.txt

# Run tests with fixtures
melange2 test package.yaml --source-dir /tmp/test-fixtures
```

The files will be available as `./input.txt` in the test.

## Repository Configuration

Configure where to find packages:

```bash
melange2 test package.yaml \
  --repository-append https://packages.wolfi.dev/os \
  --keyring-append https://packages.wolfi.dev/os/wolfi-signing.rsa.pub \
  --repository-append ./packages \
  --keyring-append ./local-melange.rsa.pub
```

## Common Test Patterns

### Binary Execution

```yaml
test:
  pipeline:
    - runs: |
        # Check binary exists
        test -x /usr/bin/myapp

        # Check version output
        myapp --version | grep -q "${{package.version}}"

        # Check help
        myapp --help
```

### Library Presence

```yaml
test:
  pipeline:
    - runs: |
        # Check shared library exists
        test -f /usr/lib/libmylib.so

        # Check it can be loaded
        ldd /usr/bin/myapp | grep -q libmylib
```

### Python Package

```yaml
test:
  environment:
    contents:
      packages:
        - python-3
  pipeline:
    - uses: python/import
      with:
        imports: |
          import mypackage
          print(mypackage.__version__)
```

### Configuration Files

```yaml
test:
  pipeline:
    - runs: |
        # Check config file installed
        test -f /etc/myapp/config.yaml

        # Validate syntax
        myapp validate-config /etc/myapp/config.yaml
```

## Debugging Tests

Run with debug output:

```bash
melange2 test package.yaml --buildkit-addr tcp://localhost:1234 --debug
```

Add verbose output in tests:

```yaml
test:
  pipeline:
    - runs: |
        set -x  # Print commands as they execute
        ls -la /usr/bin/
        which myapp
        myapp --version
```
