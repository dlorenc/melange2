# melange2 User Guide

melange2 is an experimental fork of [melange](https://github.com/chainguard-dev/melange) that uses [BuildKit](https://github.com/moby/buildkit) as the execution backend for building APK packages.

## What is melange2?

melange2 builds APK packages using declarative YAML pipelines. It converts your build configuration into BuildKit LLB (Low-Level Build) operations, providing:

- **BuildKit-native execution** - Leverages BuildKit's content-addressable cache for efficient, reproducible builds
- **Better caching** - Fine-grained layer caching means faster rebuilds
- **Progress visibility** - Real-time build progress with step timing and cache hit information
- **Simplified architecture** - Single execution backend instead of multiple runners

## When to Use melange2

Use melange2 when you want to:

- Build APK packages for Wolfi or Alpine-based systems
- Leverage BuildKit's advanced caching capabilities
- Get detailed build progress and timing information
- Experiment with BuildKit-based package building

## Documentation Structure

### [Getting Started](getting-started/installation.md)
Install melange2, set up BuildKit, and build your first package.

### [Building Packages](building-packages/build-file-reference.md)
Complete reference for the melange YAML build file format.

### [Built-in Pipelines](built-in-pipelines/overview.md)
Use pre-built pipelines for Go, Python, Rust, and other languages.

### [Testing Packages](testing-packages/test-command.md)
Write and run tests for your packages.

### [Caching](caching/buildkit-cache.md)
Understand and optimize build caching.

### [Deployment](deployment/signing.md)
Sign packages and create repositories.

### [Reference](reference/cli.md)
CLI reference and troubleshooting guide.

## Quick Example

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
      mkdir -p ${{targets.destdir}}/usr/bin
      echo '#!/bin/sh' > ${{targets.destdir}}/usr/bin/hello
      echo 'echo Hello World' >> ${{targets.destdir}}/usr/bin/hello
      chmod +x ${{targets.destdir}}/usr/bin/hello
```

Build it:

```bash
melange2 build hello.yaml --buildkit-addr tcp://localhost:1234
```
