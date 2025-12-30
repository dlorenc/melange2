# What is melange2?

melange2 is an experimental APK package builder that uses [BuildKit](https://github.com/moby/buildkit) as its execution backend. It builds APK packages from declarative YAML configuration files.

## How it Works

melange2 converts YAML pipeline definitions into BuildKit LLB (Low-Level Build) operations:

1. **apko** creates the build environment as OCI layers
2. **LLB Builder** converts pipeline steps to BuildKit operations
3. **BuildKit** executes the build with caching and exports results
4. **melange** packages the output as APK files

```
melange.yaml ──> LLB Builder ──> BuildKit ──> APK Output
 (pipelines)    (pkg/buildkit)    Daemon     (packages/)
```

## Key Features

- **BuildKit-native execution**: Uses BuildKit's LLB for efficient, cacheable builds
- **Content-addressable caching**: Fine-grained layer caching based on content
- **Real-time progress**: Step-by-step build progress with cache hit information
- **Multi-architecture support**: Build for x86_64, aarch64, and other architectures

## When to Use melange2

Use melange2 when you need to:

- Build APK packages from source code
- Create reproducible package builds
- Leverage BuildKit's caching for faster iteration
- Build packages for multiple architectures

## Project Status

melange2 is **experimental**. It is a fork of [chainguard-dev/melange](https://github.com/chainguard-dev/melange) that replaces the traditional runner-based approach (bubblewrap, Docker, QEMU) with BuildKit.

Current limitations:

- Some edge cases may not be fully supported
- API and behavior may change without notice
- Not intended for production use

For production workloads, use the upstream [melange](https://github.com/chainguard-dev/melange) project.

## Comparison with melange

| Feature | melange | melange2 |
|---------|---------|----------|
| Execution backend | bubblewrap/Docker/QEMU | BuildKit |
| Multi-arch support | QEMU emulation | BuildKit cross-compilation |
| Build caching | Limited | BuildKit content-addressable cache |
| Progress output | Basic logging | Step-by-step with cache status |

## Next Steps

- [Installation](installation.md) - Install melange2
- [BuildKit Setup](buildkit-setup.md) - Configure the BuildKit daemon
- [First Build](first-build.md) - Build your first package
