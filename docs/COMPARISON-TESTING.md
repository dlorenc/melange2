# Comparison Testing

This document describes the comparison test harness for validating melange2 builds against upstream melange.

## Overview

The comparison test harness builds packages using both upstream melange and melange2, then compares the resulting APK files to identify differences. This helps ensure melange2's BuildKit-based approach produces equivalent (or better) results.

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

### 2. Wolfi Package Repository

Clone the wolfi-dev/os repository:

```bash
git clone --depth 1 https://github.com/wolfi-dev/os /tmp/melange-compare/os
```

### 3. Upstream Melange Binary

Build the upstream melange for comparison:

```bash
git clone https://github.com/chainguard-dev/melange /tmp/upstream-melange
cd /tmp/upstream-melange && go build -o /tmp/melange-compare/melange-upstream .
```

## Running Comparisons

### Basic Usage

```bash
go test -v -tags=compare ./test/compare/... \
  -timeout 60m \
  -wolfi-repo="/tmp/melange-compare/os" \
  -baseline-melange="/tmp/melange-compare/melange-upstream" \
  -buildkit-addr="tcp://localhost:8372" \
  -arch="aarch64" \
  -packages="pkgconf,scdoc,jq" \
  -keep-outputs
```

### Using Make

```bash
make compare \
  WOLFI_REPO=/tmp/melange-compare/os \
  BASELINE_MELANGE=/tmp/melange-compare/melange-upstream \
  PACKAGES="pkgconf scdoc jq" \
  BUILD_ARCH=aarch64 \
  KEEP_OUTPUTS=1
```

### Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-wolfi-repo` | Path to wolfi-dev/os repository | (required) |
| `-baseline-melange` | Path to upstream melange binary | (required) |
| `-buildkit-addr` | BuildKit daemon address | `tcp://localhost:8372` |
| `-arch` | Architecture to build for | `x86_64` |
| `-packages` | Comma-separated list of packages | (required) |
| `-packages-file` | File with package names (one per line) | - |
| `-keep-outputs` | Keep output directories after test | `false` |
| `-baseline-args` | Additional args for baseline melange | - |
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
| ✅ IDENTICAL | Packages match perfectly |
| ⚠️ DIFFERENT | Packages differ (may be expected) |
| ❌ MELANGE2_FAILED | Melange2 build failed |
| 🔶 BASELINE_FAILED | Upstream melange build failed |

### Expected Differences

Some differences are expected and not bugs:

1. **Binary hashes**: Compiled code (C, Go, Rust) may have non-deterministic hashes due to:
   - Build timestamps embedded in binaries
   - Memory layout differences
   - Compiler optimizations

2. **File permissions**: Melange2 correctly preserves explicit permissions (e.g., `install -m444`), while baseline may modify them.

3. **File ownership**: Melange2 normalizes ownership to root (0:0), while baseline may leak build user IDs.

## Debugging Differences

### Find Output Directory

```bash
COMPARE_DIR=$(find /var/folders -name "melange-compare-*" -type d | head -1)
```

### Compare APK Contents

```bash
# List files in each APK
tar -tvzf "$COMPARE_DIR/baseline/PACKAGE/aarch64/PACKAGE-*.apk"
tar -tvzf "$COMPARE_DIR/melange2/PACKAGE/aarch64/PACKAGE-*.apk"
```

### Compare Package Metadata

```bash
# Extract and compare PKGINFO
tar -xzf "$COMPARE_DIR/baseline/PACKAGE/aarch64/PACKAGE-*.apk" -O .PKGINFO
tar -xzf "$COMPARE_DIR/melange2/PACKAGE/aarch64/PACKAGE-*.apk" -O .PKGINFO
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

### Empty Packages from Baseline

If baseline produces empty packages (only SBOM, no actual files), this is a baseline runner issue, not a melange2 bug. Compare PKGINFO `size` fields to verify.

## Test File Location

The comparison test implementation is at:
- `test/compare/compare_test.go` - Main test logic
- `test/compare/run-comparison.sh` - Helper script

## Tracking Progress

See [GitHub Issue #32](https://github.com/dlorenc/melange2/issues/32) for ongoing comparison testing progress and results.
