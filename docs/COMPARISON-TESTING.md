# Comparison Testing

This document describes the comparison test harness for validating melange2 builds against packages in the Wolfi APK repository.

## Overview

The comparison test harness builds packages using melange2 and compares the resulting APK files against the corresponding pre-built packages from the Wolfi APK repository (https://packages.wolfi.dev/os/). This approach:

- **Is faster**: No need to build with upstream melange (halves build time)
- **Has simpler setup**: No need to install/manage upstream melange binary
- **Uses production baseline**: Compares against actual packages in production use
- **Requires less infrastructure**: Single melange binary, single build process

## Prerequisites

### 1. BuildKit

Start BuildKit with the correct command:

```bash
# CORRECT - pass args only (entrypoint already includes buildkitd)
docker run -d --name buildkitd --privileged -p 8372:8372 \
  moby/buildkit:latest --addr tcp://0.0.0.0:8372

# Verify it's working
docker exec buildkitd buildctl --addr tcp://127.0.0.1:8372 debug workers
```

> **Warning**: Do NOT use `buildkitd --addr ...` as the command - the entrypoint already includes `buildkitd`. Using it twice causes silent failures.

### 2. Wolfi Package Repository (Build Configs)

Clone the wolfi-dev/os repository for build configurations:

```bash
git clone --depth 1 https://github.com/wolfi-dev/os /tmp/melange-compare/os
```

## Running Comparisons

### Basic Usage

```bash
go test -v -tags=compare ./test/compare/... \
  -timeout 60m \
  -wolfi-os-path="/tmp/melange-compare/os" \
  -buildkit-addr="tcp://localhost:8372" \
  -arch="aarch64" \
  -packages="pkgconf,scdoc,jq" \
  -keep-outputs
```

### Using Make

```bash
make compare \
  WOLFI_OS_PATH=/tmp/melange-compare/os \
  PACKAGES="pkgconf scdoc jq" \
  BUILD_ARCH=aarch64 \
  KEEP_OUTPUTS=1
```

### Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-wolfi-os-path` | Path to wolfi-dev/os repository (for build configs) | (required) |
| `-wolfi-repo-url` | URL to Wolfi APK repository | `https://packages.wolfi.dev/os` |
| `-buildkit-addr` | BuildKit daemon address | `tcp://localhost:8372` |
| `-arch` | Architecture to build for | `x86_64` |
| `-packages` | Comma-separated list of packages | (required) |
| `-packages-file` | File with package names (one per line) | - |
| `-keep-outputs` | Keep output directories after test | `false` |
| `-melange2-args` | Additional args for melange2 | - |

## Architecture Considerations

On ARM Macs (M1/M2/M3), use `aarch64` to avoid slow QEMU emulation:

```bash
-arch="aarch64"   # Fast, native builds
-arch="x86_64"    # Slow, requires emulation
```

## Interpreting Results

### Result Categories

| Symbol | Meaning |
|--------|---------|
| IDENTICAL | Packages match perfectly |
| DIFFERENT | Packages differ (may be expected) |
| MELANGE2_FAILED | Melange2 build failed |
| WOLFI_DOWNLOAD_FAILED | Could not download from Wolfi repo |

### Version Mismatches

The test harness tracks version mismatches between:
- The config in wolfi-dev/os (may have been updated)
- The package in the Wolfi repository (built from an earlier config)

Results will be annotated with "(version mismatch)" when versions differ. This is expected when configs have been updated but new packages haven't been published yet.

### Expected Differences

Some differences are expected and not bugs:

1. **Binary hashes**: Compiled code (C, Go, Rust) may have non-deterministic hashes due to:
   - Build timestamps embedded in binaries
   - Memory layout differences
   - Compiler optimizations

2. **File permissions**: Melange2 correctly preserves explicit permissions (e.g., `install -m444`), while production builds may differ.

3. **File ownership**: Melange2 normalizes ownership to root (0:0).

4. **Non-deterministic files**: The following are automatically excluded from comparison:
   - `.PKGINFO` - Contains build timestamp
   - `.SIGN.*` - Signature files (different signing keys)
   - `.spdx.json` / `.cdx.json` - SBOMs with timestamps
   - `buildinfo` - Build info with timestamps

## Debugging Differences

### Find Output Directory

```bash
COMPARE_DIR=$(find /var/folders -name "melange-compare-*" -type d | head -1)
```

### Compare APK Contents

```bash
# List files in each APK
tar -tvzf "$COMPARE_DIR/wolfi/PACKAGE/PACKAGE-*.apk"
tar -tvzf "$COMPARE_DIR/melange2/PACKAGE/ARCH/PACKAGE-*.apk"
```

### Compare Package Metadata

```bash
# Extract and compare PKGINFO
tar -xzf "$COMPARE_DIR/wolfi/PACKAGE/PACKAGE-*.apk" -O .PKGINFO
tar -xzf "$COMPARE_DIR/melange2/PACKAGE/ARCH/PACKAGE-*.apk" -O .PKGINFO
```

### Key PKGINFO Fields

| Field | Description |
|-------|-------------|
| `size` | Installed size - large differences indicate missing files |
| `depend` | Runtime dependencies detected by SCA |
| `provides` | Shared libraries provided by package |

## Common Issues

### Connection Reset by Peer

**Symptom:**
```
rpc error: code = Unavailable desc = connection error: desc = "error reading server preface: read tcp ... connection reset by peer"
```

**Cause:** BuildKit container started with wrong command (double `buildkitd`).

**Fix:** Recreate the container:
```bash
docker rm -f buildkitd
docker run -d --name buildkitd --privileged -p 8372:8372 \
  moby/buildkit:latest --addr tcp://0.0.0.0:8372
```

### Cache Directory Not Found

**Symptom:**
```
lstat melange-cache: no such file or directory
```

**Fix:** Either create the directory or pass an empty cache dir:
```bash
mkdir -p ./melange-cache
# or
-melange2-args="--cache-dir="
```

### Package Not Found in Repository

If a package exists in wolfi-dev/os but not in the Wolfi repository, it will be skipped. This can happen for:
- New packages not yet published
- Packages that have been removed

### Version Drift

When the wolfi-dev/os config has been updated but new packages haven't been built yet, you'll see version mismatches. The comparison still runs but results should be interpreted with caution.

## Test File Locations

The comparison test implementation is at:
- `test/compare/compare_test.go` - Main test logic
- `test/compare/apkindex.go` - APKINDEX parsing
- `test/compare/fetch.go` - Package downloading from Wolfi repo

## Tracking Progress

See [GitHub Issue #32](https://github.com/dlorenc/melange2/issues/32) for ongoing comparison testing progress and results.
