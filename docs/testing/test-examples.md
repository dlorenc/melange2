# Test Examples

This page provides practical examples of testing patterns for melange2 packages.

## Basic Version Check

The simplest test verifies that a command runs and reports its version:

```yaml
package:
  name: mytool
  version: 1.0.0
  epoch: 0
  description: My useful tool

pipeline:
  - uses: go/build
    with:
      packages: ./cmd/mytool
      output: mytool

test:
  pipeline:
    - runs: |
        mytool --version
```

## Multiple Verification Steps

Test multiple aspects of a package with named steps:

```yaml
test:
  pipeline:
    - name: verify-version
      runs: |
        output=$(testable --version)
        echo "Version output: $output"
        if [ "$output" != "testable 1.0.0" ]; then
          echo "Version check failed"
          exit 1
        fi

    - name: verify-help
      runs: |
        testable --help | grep -q "Usage:"
        if [ $? -ne 0 ]; then
          echo "Help check failed"
          exit 1
        fi

    - name: verify-config
      runs: |
        if [ ! -f /etc/testable.conf ]; then
          echo "Config file missing"
          exit 1
        fi
        grep -q "enabled=true" /etc/testable.conf
```

## Testing with Additional Packages

Some tests require additional packages beyond runtime dependencies:

```yaml
test:
  environment:
    contents:
      packages:
        - jq
        - curl
  pipeline:
    - name: fetch-and-parse
      runs: |
        myapp fetch-config | jq '.version'
```

## Testing a CLI Tool

Test a command-line tool with various inputs:

```yaml
package:
  name: eza
  version: 0.20.24
  epoch: 1
  description: A modern replacement for ls

pipeline:
  - uses: cargo/build
    with:
      output: eza

test:
  pipeline:
    - runs: |
        eza
        eza --version
```

## Testing a Compiler

For compiler packages, verify compilation works:

```yaml
package:
  name: gcc
  version: 13.2.0

test:
  environment:
    contents:
      packages:
        - build-base
  pipeline:
    - name: Test C compilation
      runs: |
        cat > hello.c << 'EOF'
        #include <stdio.h>
        int main() {
            printf("Hello, World!\n");
            return 0;
        }
        EOF
        gcc hello.c -o hello
        ./hello | grep "Hello, World"

    - name: Test C++ compilation
      runs: |
        cat > hello.cpp << 'EOF'
        #include <iostream>
        int main() {
            std::cout << "Hello, C++!" << std::endl;
            return 0;
        }
        EOF
        g++ hello.cpp -o hello-cpp
        ./hello-cpp | grep "Hello, C++"
```

## Testing with Container Registries

For tools that interact with registries:

```yaml
test:
  environment:
    contents:
      packages:
        - jq
  pipeline:
    - name: Verify installation
      runs: |
        crane version || exit 1
        crane --help

    - name: Fetch and verify manifest
      runs: |
        crane manifest chainguard/static | jq '.schemaVersion' | grep '2' || exit 1

    - name: List tags for a public image
      runs: |
        crane ls chainguard/static | grep -E 'latest|v[0-9]+.[0-9]+.[0-9]+' || exit 1

    - name: Validate image existence
      runs: |
        crane digest chainguard/static:latest && echo "Image exists" || exit 1
```

## Testing Subpackages

Test subpackages independently to ensure their dependencies are correct:

```yaml
package:
  name: myapp
  version: 1.0.0

pipeline:
  - runs: |
      mkdir -p ${{targets.contextdir}}/usr/bin
      # Create main binary
      cat > ${{targets.contextdir}}/usr/bin/myapp << 'EOF'
      #!/bin/sh
      echo "Main application"
      EOF
      chmod 755 ${{targets.contextdir}}/usr/bin/myapp

subpackages:
  - name: myapp-tools
    pipeline:
      - uses: split/bin
        with:
          package: myapp
    test:
      pipeline:
        - runs: |
            # Verify the binary was split correctly
            test -x /usr/bin/myapp

  - name: myapp-extra
    pipeline:
      - runs: |
          mkdir -p ${{targets.contextdir}}/usr/bin
          cat > ${{targets.contextdir}}/usr/bin/myapp-extra << 'EOF'
          #!/bin/sh
          echo "Extra tool"
          EOF
          chmod 755 ${{targets.contextdir}}/usr/bin/myapp-extra
    test:
      pipeline:
        - runs: |
            myapp-extra
```

## Testing Environment Variables

Verify environment is set up correctly:

```yaml
test:
  pipeline:
    - name: verify-environment
      runs: |
        echo "HOME is: $HOME"
        echo "PWD is: $PWD"
        # Verify we're in the workspace
        test -d /home/build
```

## Testing File Permissions

Verify files have correct permissions:

```yaml
test:
  pipeline:
    - name: check-executable
      runs: |
        # Verify binary is executable
        test -x /usr/bin/myapp

    - name: check-config-permissions
      runs: |
        # Config should be readable
        test -r /etc/myapp/config.yaml

    - name: check-data-directory
      runs: |
        # Data dir should be writable by the app user
        test -d /var/lib/myapp
```

## Testing Library Packages

For library packages, verify headers and shared objects:

```yaml
package:
  name: mylib
  version: 1.0.0

test:
  environment:
    contents:
      packages:
        - build-base
  pipeline:
    - name: verify-headers
      runs: |
        test -f /usr/include/mylib.h

    - name: verify-library
      runs: |
        test -f /usr/lib/libmylib.so

    - name: test-compile-against
      runs: |
        cat > test.c << 'EOF'
        #include <mylib.h>
        int main() { return 0; }
        EOF
        gcc test.c -lmylib -o test
```

## Testing with Source Fixtures

When tests need external files, use the `--source-dir` flag:

```yaml
test:
  pipeline:
    - name: verify-test-fixture
      runs: |
        # Expects test files in source directory
        if [ ! -f /home/build/test-fixture.txt ]; then
          echo "ERROR: Test fixture file not found"
          exit 1
        fi

        content=$(cat /home/build/test-fixture.txt)
        if [ "$content" != "expected-content" ]; then
          echo "ERROR: Content mismatch"
          exit 1
        fi
```

Run with:

```bash
./melange2 test mypackage.yaml --source-dir ./test-fixtures/ --buildkit-addr tcp://localhost:1234
```

## Testing Isolation Between Subpackages

This example verifies that subpackage tests run in isolation:

```yaml
package:
  name: isolation-test
  version: 1.0.0

test:
  pipeline:
    - name: create-marker
      runs: |
        # Create a file that should NOT be visible to subpackages
        echo "contamination" > /tmp/main-marker.txt

subpackages:
  - name: isolation-test-sub1
    pipeline: []
    test:
      pipeline:
        - name: check-isolation
          runs: |
            # This file should NOT exist - subpackages run in fresh containers
            if [ -f /tmp/main-marker.txt ]; then
              echo "ERROR: Isolation broken!"
              exit 1
            fi
            echo "Isolation verified"
```

## Using Pipeline Assertions in Tests

Tests can use pipeline assertions to verify specific behaviors:

```yaml
test:
  pipeline:
    - name: run-checks
      runs: |
        echo "Running diagnostic checks"
        myapp check-system
      assertions:
        required-steps: 1
```

## Testing with Debug Mode

Enable debug mode for troubleshooting:

```bash
./melange2 test mypackage.yaml --debug --buildkit-addr tcp://localhost:1234
```

This adds `set -x` to shell scripts, showing each command as it executes.

## Testing Failures

Tests fail immediately on any non-zero exit code:

```yaml
test:
  pipeline:
    - name: must-succeed
      runs: |
        # If this fails, the entire test fails
        myapp --validate-config

    - name: after-failure
      runs: |
        # This won't run if the previous step fails
        echo "Config is valid"
```

## Complete Example: Go Application

A complete example for a Go application:

```yaml
package:
  name: mygoapp
  version: 1.2.3
  epoch: 0
  description: My Go application
  copyright:
    - license: Apache-2.0
  dependencies:
    runtime:
      - ca-certificates-bundle

environment:
  contents:
    packages:
      - build-base
      - busybox
      - ca-certificates-bundle
      - go
  environment:
    CGO_ENABLED: "0"

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/mygoapp
      tag: v${{package.version}}
      expected-commit: abc123...

  - uses: go/build
    with:
      packages: ./cmd/mygoapp
      output: mygoapp
      ldflags: -X main.Version=${{package.version}}

test:
  environment:
    contents:
      packages:
        - jq
  pipeline:
    - name: verify-version
      runs: |
        mygoapp --version | grep "1.2.3"

    - name: verify-help
      runs: |
        mygoapp --help

    - name: test-json-output
      runs: |
        mygoapp status --format=json | jq '.status' | grep -q "ok"

    - name: test-config
      runs: |
        mygoapp config validate
```

## See Also

- [Testing Overview](index.md) - Test block structure and execution environment
- [Build Pipelines](../build-files/pipelines.md) - Pipeline syntax used in tests
- [Variable Substitution](../build-files/variables.md) - Variables available in tests
