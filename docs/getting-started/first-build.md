# First Build

This tutorial walks through building a simple APK package with melange2.

## Prerequisites

- melange2 installed ([Installation](installation.md))
- BuildKit daemon running ([BuildKit Setup](buildkit-setup.md))

## Build File Structure

melange2 uses YAML configuration files that define:

- **package**: Package metadata (name, version, description)
- **environment**: Build environment (repositories, packages to install)
- **pipeline**: Build steps to execute

## Minimal Example

Create a file called `hello.yaml`:

```yaml
package:
  name: hello
  version: 1.0.0
  epoch: 0
  description: "Hello world package"

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
      mkdir -p "${{targets.destdir}}/usr/bin"
      cat > "${{targets.destdir}}/usr/bin/hello" <<'EOF'
      #!/bin/sh
      echo "Hello, World!"
      EOF
      chmod +x "${{targets.destdir}}/usr/bin/hello"
```

## Run the Build

```shell
melange2 build hello.yaml --buildkit-addr tcp://localhost:1234
```

### Expected Output

```
INFO melange version ... with buildkit@tcp://localhost:1234 building ...
INFO loading 1 apko layer(s) into BuildKit
INFO building LLB graph with 1 layer(s)
INFO running main pipelines
INFO solving build graph
INFO [1/5] local://apko-hello
INFO   -> local://apko-hello (0.1s) [done]
INFO [3/5] copy apko rootfs
INFO   -> copy apko rootfs (0.0s) [CACHED]
INFO [5/5] run: mkdir -p "${{targets.destdir}}/usr/bin"...
INFO   -> run: mkdir -p (0.2s) [done]
INFO exporting workspace
INFO build completed successfully
```

## Build Output

The build creates APK packages in the `packages/` directory:

```
packages/
  x86_64/
    APKINDEX.tar.gz
    hello-1.0.0-r0.apk
```

## Build File Reference

### Package Section

```yaml
package:
  name: hello           # Package name (required)
  version: 1.0.0        # Package version (required)
  epoch: 0              # Monotonic version counter (required)
  description: "..."    # Human-readable description
  copyright:            # License information
    - license: Apache-2.0
  dependencies:
    runtime:            # Runtime dependencies
      - busybox
```

### Environment Section

```yaml
environment:
  contents:
    repositories:       # APK repositories to use
      - https://packages.wolfi.dev/os
    keyring:            # Repository signing keys
      - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
    packages:           # Packages to install in build environment
      - busybox
      - build-base
```

### Pipeline Section

Pipeline steps execute in order. Each step can be:

**Inline script (`runs`):**
```yaml
pipeline:
  - runs: |
      echo "Hello"
      make install
```

**Built-in pipeline (`uses`):**
```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/source.tar.gz
      expected-sha256: abc123...

  - uses: autoconf/configure

  - uses: autoconf/make

  - uses: autoconf/make-install
```

### Variable Substitution

Use `${{...}}` for variable substitution:

| Variable | Description |
|----------|-------------|
| `${{package.name}}` | Package name |
| `${{package.version}}` | Package version |
| `${{targets.destdir}}` | Output directory for package files |
| `${{targets.contextdir}}` | Context directory for subpackages |
| `${{build.arch}}` | Target architecture |

## Common Build Flags

| Flag | Description |
|------|-------------|
| `--buildkit-addr` | BuildKit daemon address |
| `--arch` | Target architecture(s) (e.g., `x86_64,aarch64`) |
| `--out-dir` | Output directory (default: `./packages/`) |
| `--debug` | Enable debug logging |
| `--signing-key` | Key file for signing packages |

## Debug Mode

Enable debug mode to see detailed build output:

```shell
melange2 build hello.yaml --buildkit-addr tcp://localhost:1234 --debug
```

Debug mode adds `set -x` to shell scripts, showing each command as it executes.

## Building for Multiple Architectures

Build for specific architectures:

```shell
# Single architecture
melange2 build hello.yaml --arch x86_64

# Multiple architectures
melange2 build hello.yaml --arch x86_64,aarch64

# All supported architectures
melange2 build hello.yaml
```

## Real-World Example: GNU Hello

Build the GNU hello program using autotools:

```yaml
package:
  name: hello
  version: 2.12
  epoch: 0
  description: "The GNU hello world program"
  copyright:
    - license: GPL-3.0-or-later

environment:
  contents:
    repositories:
      - https://packages.wolfi.dev/os
    keyring:
      - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
    packages:
      - build-base
      - busybox

pipeline:
  - uses: fetch
    with:
      uri: https://ftp.gnu.org/gnu/hello/hello-${{package.version}}.tar.gz
      expected-sha256: cf04af86dc085268c5f4470fbae49b18afbc221b78096aab842d934a76bad0ab

  - uses: autoconf/configure

  - uses: autoconf/make

  - uses: autoconf/make-install

  - uses: strip
```

## Next Steps

- Explore the `examples/` directory for more build configurations
- Learn about [built-in pipelines](../pipelines.md) like `go/build`, `fetch`, `git-checkout`
- Set up [remote builds](../remote-builds.md) with melange-server
