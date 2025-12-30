# melange2 Documentation

melange2 is an experimental APK package builder that uses [BuildKit](https://github.com/moby/buildkit) as its execution backend. It converts YAML pipeline definitions into BuildKit LLB operations for efficient, cacheable package builds.

## Documentation Sections

### Getting Started

New to melange2? Start here:

| Document | Description |
|----------|-------------|
| [What is melange2?](getting-started/index.md) | Overview and comparison with melange |
| [Installation](getting-started/installation.md) | Install melange2 from source |
| [BuildKit Setup](getting-started/buildkit-setup.md) | Configure the BuildKit daemon |
| [First Build](getting-started/first-build.md) | Build your first package |

### Build Files

Learn how to write package build configurations:

| Document | Description |
|----------|-------------|
| [Build File Overview](build-files/index.md) | YAML file structure overview |
| [Package Metadata](build-files/package-metadata.md) | name, version, dependencies, copyright |
| [Environment](build-files/environment.md) | Build environment configuration |
| [Pipeline](build-files/pipeline.md) | Build step syntax and execution |
| [Subpackages](build-files/subpackages.md) | Creating multiple packages from one build |
| [Variables](build-files/variables.md) | Built-in and custom variables |
| [Options](build-files/options.md) | Build option variants |

### Built-in Pipelines

Pre-configured build pipelines for common languages and tools:

| Document | Description |
|----------|-------------|
| [Pipeline Overview](pipelines/index.md) | How built-in pipelines work |
| [fetch](pipelines/fetch.md) | Download and extract source archives |
| [Build Systems](pipelines/build-systems.md) | autoconf, cmake, meson, make |
| [Go](pipelines/go.md) | go/build, go/install pipelines |
| [Python](pipelines/python.md) | python/build, python/pip-build pipelines |
| [Rust](pipelines/rust.md) | cargo/build pipeline |
| [Other Pipelines](pipelines/other.md) | strip, patch, git-checkout, and more |

### CLI Reference

Command-line interface documentation:

| Document | Description |
|----------|-------------|
| [CLI Overview](cli/index.md) | All commands at a glance |
| [build](cli/build.md) | Build packages |
| [test](cli/test.md) | Test packages |
| [keygen](cli/keygen.md) | Generate signing keys |
| [sign](cli/sign.md) | Sign packages and indexes |
| [remote](cli/remote.md) | Remote build server commands |

### Package Signing

Cryptographic signing for packages and repositories:

| Document | Description |
|----------|-------------|
| [Signing Overview](signing/index.md) | APK signing concepts |
| [Key Generation](signing/keygen.md) | Generate RSA signing keys |
| [Repository Management](signing/repositories.md) | Create and sign APKINDEX |

### Testing

Test your packages after building:

| Document | Description |
|----------|-------------|
| [Testing Overview](testing/index.md) | How package testing works |
| [Test Examples](testing/test-examples.md) | Common test patterns |

### Remote Builds

Distributed building with melange-server:

| Document | Description |
|----------|-------------|
| [Remote Builds Overview](remote-builds/index.md) | Remote build architecture |
| [Server Setup](remote-builds/server-setup.md) | Deploy melange-server locally |
| [Submitting Builds](remote-builds/submitting-builds.md) | Submit builds to the server |
| [Managing Backends](remote-builds/managing-backends.md) | Add and configure BuildKit backends |
| [GKE Deployment](remote-builds/gke-deployment.md) | Production deployment on GKE |

### Advanced Topics

| Document | Description |
|----------|-------------|
| [Caching](advanced/caching.md) | BuildKit cache configuration |
| [Registry Authentication](advanced/registry-auth.md) | Authenticate with private registries |
| [Troubleshooting](advanced/troubleshooting.md) | Common issues and solutions |

### Development

Contributing to melange2:

| Document | Description |
|----------|-------------|
| [Development Overview](development/index.md) | Contributing guide |
| [Development Setup](development/setup.md) | Set up your development environment |
| [Architecture](development/architecture.md) | Codebase structure and design |
| [Testing](development/testing.md) | Running and writing tests |
| [Adding Pipelines](development/adding-pipelines.md) | Create new built-in pipelines |
| [Git Workflow](development/git-workflow.md) | Branching and PR conventions |

## Quick Start

```bash
# Install melange2
go build -o melange2 .

# Start BuildKit
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234

# Build a package
./melange2 build examples/hello.yaml --buildkit-addr tcp://localhost:1234
```

## Project Status

melange2 is **experimental**. It is a fork of [chainguard-dev/melange](https://github.com/chainguard-dev/melange) that replaces traditional runners (bubblewrap, Docker, QEMU) with BuildKit. For production use, see the upstream project.

## Links

- [GitHub Repository](https://github.com/dlorenc/melange2)
- [Upstream melange](https://github.com/chainguard-dev/melange)
- [BuildKit](https://github.com/moby/buildkit)
- [Wolfi](https://github.com/wolfi-dev)
