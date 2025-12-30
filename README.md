# melange2

> **EXPERIMENTAL** - This is an experimental fork of [melange](https://github.com/chainguard-dev/melange) that uses [BuildKit](https://github.com/moby/buildkit) as the execution backend.

Build apk packages using declarative pipelines, powered by BuildKit.

## What is melange2?

melange2 is an experimental reimplementation of melange's build execution layer using BuildKit instead of the traditional runner-based approach (bubblewrap, Docker, QEMU). This provides:

- **BuildKit-native execution** - Leverages BuildKit's LLB (Low-Level Build) for efficient, cacheable builds
- **Better caching** - BuildKit's content-addressable cache provides fine-grained layer caching
- **Progress visibility** - Real-time build progress with step timing and cache hit information
- **Simplified architecture** - Single execution backend instead of multiple runners

## Key Differences from melange

| Feature | melange | melange2 |
|---------|---------|----------|
| Execution backend | bubblewrap/Docker/QEMU | BuildKit |
| Multi-arch support | QEMU emulation | BuildKit cross-compilation |
| Build caching | Limited | BuildKit content-addressable cache |
| Progress output | Basic logging | Step-by-step with cache status |

## Status

This project is **experimental** and not intended for production use. It exists to explore BuildKit as an alternative execution backend for melange builds.

Current status:
- Both `build` and `test` commands use BuildKit
- Legacy runner code has been removed
- Actively being validated against upstream melange (see [#32](https://github.com/dlorenc/melange2/issues/32))

Current limitations:
- Some edge cases may not be fully supported
- API and behavior may change without notice

## Installation

```shell
go install github.com/dlorenc/melange2@latest
```

## Prerequisites

melange2 requires a running BuildKit daemon:

```shell
# Start BuildKit with Docker
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234

# Or use a local buildkitd
buildkitd --addr tcp://0.0.0.0:1234
```

## Usage

```shell
# Build a package
melange2 build package.yaml --buildkit-addr tcp://localhost:1234

# Build with debug output (shows build logs)
melange2 build package.yaml --buildkit-addr tcp://localhost:1234 --debug

# Build for a specific architecture
melange2 build package.yaml --buildkit-addr tcp://localhost:1234 --arch x86_64
```

### Example Output

```
INFO solving build graph
INFO [1/12] local://apko-mypackage
INFO   -> local://apko-mypackage (0.0s) [done]
INFO [3/12] copy apko rootfs
INFO   -> copy apko rootfs (0.0s) [CACHED]
INFO [7/12] uses: go/build
INFO     | go build -o /home/build/output ./cmd/...
INFO   -> uses: go/build (18.3s) [done]
INFO
INFO Build summary:
INFO   Total steps:  12
INFO   Cached:       5
INFO   Executed:     7
INFO   Duration:     45.2s
```

## Build File Format

melange2 uses the same build file format as melange:

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
      - build-base

pipeline:
  - runs: |
      echo "Hello from BuildKit!"
      mkdir -p ${{targets.destdir}}/usr/bin
      echo '#!/bin/sh' > ${{targets.destdir}}/usr/bin/hello
      echo 'echo Hello World' >> ${{targets.destdir}}/usr/bin/hello
      chmod +x ${{targets.destdir}}/usr/bin/hello
```

## Architecture

melange2 converts melange pipelines to BuildKit LLB operations:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  melange.yaml   │────▶│   LLB Builder   │────▶│    BuildKit     │
│  (pipelines)    │     │  (pkg/buildkit) │     │    Daemon       │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                        ┌─────────────────┐            │
                        │   APK Output    │◀───────────┘
                        │  (packages/)    │
                        └─────────────────┘
```

The build process:
1. **apko** creates the build environment as an OCI layer
2. **LLB Builder** converts pipeline steps to BuildKit operations
3. **BuildKit** executes the build with caching and exports results
4. **melange** packages the output as APK files

## Remote Build Server

melange2 includes `melange-server`, a remote build service for distributing builds across multiple BuildKit backends.

```shell
# Build and run the server
go build -o melange-server ./cmd/melange-server/
./melange-server --buildkit-addr tcp://localhost:1234

# Submit a remote build
melange2 remote submit package.yaml --server http://localhost:8080 --wait
```

Key features:
- **Multi-backend support** - Route builds to different BuildKit instances by architecture
- **Job scheduling** - Queue and execute builds with configurable concurrency
- **GCS storage** - Store build artifacts in Google Cloud Storage for production deployments
- **Backend pools** - Manage pools of BuildKit backends with labels and health checks

See [docs/remote-builds/](docs/remote-builds/) for detailed documentation.

## Development

### Running Tests

```shell
# Unit tests
go test -short ./...

# E2E tests (requires Docker for testcontainers)
go test -v ./pkg/buildkit/...
```

### Comparing Against Upstream Melange

melange2 includes a comparison test harness to validate builds against upstream melange:

```shell
# Clone wolfi-dev/os and build upstream melange
git clone https://github.com/wolfi-dev/os /tmp/wolfi-os
git clone https://github.com/chainguard-dev/melange /tmp/upstream-melange
cd /tmp/upstream-melange && go build -o /tmp/melange-upstream .

# Run comparison (from melange2 repo)
make compare \
  WOLFI_REPO=/tmp/wolfi-os \
  BASELINE_MELANGE=/tmp/melange-upstream \
  PACKAGES="jq xz zstd"
```

See `make help` for all available options.

## Upstream

This is a fork of [chainguard-dev/melange](https://github.com/chainguard-dev/melange). For production use, please use the upstream project.

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.
