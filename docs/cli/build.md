# melange2 build

Build a package from a YAML configuration file.

## Usage

```
melange build [config.yaml] [flags]
```

## Description

The `build` command compiles APK packages from YAML configuration files using BuildKit as the build backend. It converts YAML pipelines to BuildKit LLB operations for efficient, cacheable builds.

## Example

```bash
melange build [config.yaml]
```

## Flags

### Input/Output Options

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--out-dir` | | `./packages/` | Directory where packages will be output |
| `--source-dir` | | (auto-detect) | Directory used for included sources |
| `--workspace-dir` | | (none) | Directory used for the workspace at /home/build |
| `--empty-workspace` | | `false` | Whether the build workspace should be empty |

**Convention**: If `./$pkgname/` exists (where `$pkgname` is the package name from the config), it is automatically used as the source directory. The flag is only needed to override.

### Build Configuration

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--arch` | | (all) | Architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config |
| `--build-option` | | `[]` | Build options to enable |
| `--build-date` | | (none) | Date used for the timestamps of the files inside the image |
| `--override-host-triplet-libc-substitution-flavor` | | `gnu` | Override the flavor of libc for ${{host.triplet.*}} substitutions (e.g., gnu, musl) |

### Pipelines

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--pipeline-dir` | | (auto-detect) | Directory used to extend defined built-in pipelines |

**Convention**: If `./pipelines/` exists, it is automatically used. The flag is only needed to override.

### Caching

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--cache-dir` | | `./melange-cache/` | Directory used for cached inputs |
| `--apk-cache-dir` | | (system default) | Directory used for cached apk packages |

### Repository Configuration

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--keyring-append` | `-k` | `[]` | Path to extra keys to include in the build environment keyring |
| `--repository-append` | `-r` | `[]` | Path to extra repositories to include in the build environment |
| `--package-append` | | `[]` | Extra packages to install for each of the build environments |
| `--ignore-signatures` | | `false` | Ignore repository signature verification |

### Signing

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--signing-key` | | (auto-detect) | Key to use for signing |
| `--generate-index` | | `true` | Whether to generate APKINDEX.tar.gz |

**Convention**: If `melange.rsa` or `local-signing.rsa` exists in the current directory, it is automatically used for signing. The flag is only needed to override or to use a key in a different location.

### Variables and Environment

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--env-file` | | (none) | File to use for preloaded environment variables |
| `--vars-file` | | (none) | File to use for preloaded build configuration variables |

### BuildKit Options

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--buildkit-addr` | | `tcp://localhost:1234` | BuildKit daemon address (e.g., tcp://localhost:1234) |
| `--max-layers` | | `50` | Maximum number of layers for build environment (1 for single layer, higher for better cache efficiency) |
| `--apko-registry` | | (none) | Registry URL for caching apko base images (e.g., registry:5000/apko-cache) |
| `--apko-registry-insecure` | | `false` | Allow insecure (HTTP) connection to apko registry |

### Linting

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--lint-require` | | (default required linters) | Linters that must pass |
| `--lint-warn` | | (default warn linters) | Linters that will generate warnings |
| `--persist-lint-results` | | `false` | Persist lint results to JSON files in packages/{arch}/ directory |

### Logging and Debugging

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--debug` | | `false` | Enables debug logging of build pipelines |
| `--trace` | | (none) | Where to write trace output |
| `--create-build-log` | | `false` | Creates a package.log file containing a list of packages that were built by the command |
| `--dependency-log` | | (none) | Log dependencies to a specified file |

### Cleanup

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--rm` | | `true` | Clean up intermediate artifacts (e.g., container images, temp dirs) |
| `--cleanup` | | `true` | When enabled, the temp dir used for the guest will be cleaned up after completion |

### Provenance and SBOM

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--namespace` | | `unknown` | Namespace to use in package URLs in SBOM (e.g., wolfi, alpine) |
| `--generate-provenance` | | `false` | Generate SLSA provenance for builds (included in a separate .attest.tar.gz file next to the APK) |
| `--git-commit` | | (auto-detect) | Commit hash of the git repository containing the build config file |
| `--git-repo-url` | | (auto-detect) | URL of the git repository containing the build config file |
| `--license` | | `NOASSERTION` | License to use for the build config file itself |

### Debug Export

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--export-on-failure` | | `none` | Export build environment on failure: none, tarball, docker, or registry (registry requires docker login) |
| `--export-ref` | | (none) | Path (for tarball) or image reference (for docker/registry) for debug image export |

### Other

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--strip-origin-name` | | `false` | Whether origin names should be stripped (for bootstrap) |

## Examples

### Basic Build

```bash
./melange2 build mypackage.yaml --buildkit-addr tcp://localhost:1234
```

### Build with Debug Logging

```bash
./melange2 build mypackage.yaml --buildkit-addr tcp://localhost:1234 --debug
```

### Build for Specific Architectures

```bash
./melange2 build mypackage.yaml --arch x86_64,aarch64
```

### Build with Custom Repositories

```bash
./melange2 build mypackage.yaml \
  --repository-append https://packages.wolfi.dev/os \
  --keyring-append /path/to/wolfi-signing.rsa.pub
```

### Build with Signing

```bash
./melange2 build mypackage.yaml --signing-key mykey.rsa
```

### Build with Custom Output Directory

```bash
./melange2 build mypackage.yaml --out-dir ./output/packages/
```

### Build with Cache Configuration

```bash
./melange2 build mypackage.yaml \
  --cache-dir /var/cache/melange \
  --apk-cache-dir /var/cache/apk
```

### Build with Provenance

```bash
./melange2 build mypackage.yaml \
  --generate-provenance \
  --git-repo-url https://github.com/myorg/packages \
  --namespace myorg
```

### Build with Debug Export on Failure

```bash
# Export to tarball on failure
./melange2 build mypackage.yaml \
  --export-on-failure tarball \
  --export-ref /tmp/debug-env.tar

# Export to Docker on failure
./melange2 build mypackage.yaml \
  --export-on-failure docker \
  --export-ref debug-env:latest
```

### Build with Maximum Layer Optimization

```bash
# Single layer (faster export, less cache reuse)
./melange2 build mypackage.yaml --max-layers 1

# Many layers (slower export, better cache reuse)
./melange2 build mypackage.yaml --max-layers 100
```

## Prerequisites

Before building packages, you need a running BuildKit daemon:

```bash
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234
```

## Convention-Based Defaults

melange2 uses convention over configuration to simplify common workflows. The following conventions are automatically applied:

| Convention | Location | What it does |
|------------|----------|--------------|
| Pipeline directory | `./pipelines/` | Custom pipelines are automatically loaded |
| Source directory | `./$pkgname/` | Source files are loaded from a directory named after the package |
| Signing key | `melange.rsa` or `local-signing.rsa` | First matching key is used for signing |

### Example

Given a directory structure:

```
myproject/
├── curl.yaml              # Package config (package.name: curl)
├── curl/                  # Source files (auto-detected)
│   └── patches/
│       └── fix.patch
├── pipelines/             # Custom pipelines (auto-detected)
│   └── custom-build.yaml
└── melange.rsa            # Signing key (auto-detected)
```

Running `melange2 build curl.yaml` will automatically:
- Load pipelines from `./pipelines/`
- Use source files from `./curl/`
- Sign packages with `melange.rsa`

No additional flags are needed.

## See Also

- [test command](test.md) - Test packages after building
- [sign command](sign.md) - Sign built packages
- [remote commands](remote.md) - Remote build server
