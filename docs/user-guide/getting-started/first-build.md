# Build Your First Package

This tutorial walks through building a simple package with melange2.

## Prerequisites

- [melange2 installed](installation.md)
- [BuildKit running](buildkit-setup.md)

## Step 1: Create a Build File

Create `hello.yaml`:

```yaml
package:
  name: hello
  version: 1.0.0
  epoch: 0
  description: "A simple hello world package"
  copyright:
    - license: MIT

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
      mkdir -p ${{targets.destdir}}/usr/bin
      cat > ${{targets.destdir}}/usr/bin/hello << 'EOF'
      #!/bin/sh
      echo "Hello from melange2!"
      EOF
      chmod +x ${{targets.destdir}}/usr/bin/hello
```

## Step 2: Build the Package

```bash
melange2 build hello.yaml --buildkit-addr tcp://localhost:1234
```

You'll see progress output:

```
INFO solving build graph
INFO [1/5] local://apko-hello
INFO   -> local://apko-hello (0.0s) [done]
INFO [3/5] copy apko rootfs
INFO   -> copy apko rootfs (0.2s) [CACHED]
INFO [5/5] Build hello world script
INFO   -> Build hello world script (0.1s) [done]

Build summary:
  Total steps:  5
  Cached:       2
  Executed:     3
  Duration:     1.2s
```

## Step 3: Examine the Output

The package is created in `./packages/`:

```bash
ls -la packages/x86_64/
# hello-1.0.0-r0.apk
# APKINDEX.tar.gz
```

Inspect the package contents:

```bash
tar -tvzf packages/x86_64/hello-1.0.0-r0.apk
```

## Step 4: Add Debug Output

For more detailed logs, use `--debug`:

```bash
melange2 build hello.yaml --buildkit-addr tcp://localhost:1234 --debug
```

This shows the actual commands being executed in each pipeline step.

## Understanding the Build File

| Section | Purpose |
|---------|---------|
| `package` | Metadata: name, version, description, license |
| `environment.contents` | Build-time dependencies from APK repositories |
| `pipeline` | Ordered list of build steps |
| `${{targets.destdir}}` | Output directory for package contents |

## Next Steps

- [Build file reference](../building-packages/build-file-reference.md) - Complete YAML schema
- [Using pipelines](../built-in-pipelines/overview.md) - Built-in build helpers
- [Caching](../caching/buildkit-cache.md) - Speed up rebuilds
