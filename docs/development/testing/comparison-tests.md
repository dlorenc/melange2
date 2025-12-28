# Comparison Tests

Comparison tests validate melange2 builds against packages in the Wolfi APK repository.

## Overview

The comparison test harness:
1. Builds packages using melange2
2. Downloads the same packages from Wolfi (packages.wolfi.dev)
3. Compares the results

This validates that melange2 produces correct packages.

## Prerequisites

### 1. BuildKit

```bash
docker run -d --name buildkitd --privileged -p 8372:8372 \
  moby/buildkit:latest --addr tcp://0.0.0.0:8372
```

### 2. Wolfi Package Configs

```bash
git clone --depth 1 https://github.com/wolfi-dev/os /tmp/wolfi-os
```

## Running Comparisons

### Basic Usage

```bash
go test -v -tags=compare ./test/compare/... \
  -timeout 60m \
  -wolfi-os-path="/tmp/wolfi-os" \
  -buildkit-addr="tcp://localhost:8372" \
  -arch="aarch64" \
  -packages="pkgconf,scdoc,jq"
```

### Using Make

```bash
make compare \
  WOLFI_OS_PATH=/tmp/wolfi-os \
  PACKAGES="pkgconf scdoc jq" \
  BUILD_ARCH=aarch64
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-wolfi-os-path` | Path to wolfi-dev/os repo | Required |
| `-wolfi-repo-url` | Wolfi APK repository URL | `https://packages.wolfi.dev/os` |
| `-buildkit-addr` | BuildKit address | `tcp://localhost:8372` |
| `-arch` | Target architecture | `x86_64` |
| `-packages` | Packages to compare (comma-separated) | Required |
| `-keep-outputs` | Keep output directories | `false` |

## Interpreting Results

### Result Categories

| Symbol | Meaning |
|--------|---------|
| IDENTICAL | Packages match |
| DIFFERENT | Packages differ (may be expected) |
| MELANGE2_FAILED | melange2 build failed |
| WOLFI_DOWNLOAD_FAILED | Could not download from Wolfi |

### Expected Differences

Some differences are expected:

1. **Binary hashes** - Compiled code may differ due to timestamps
2. **SBOMs** - Contain build timestamps
3. **Signatures** - Different signing keys
4. **Permissions** - Minor permission differences

Automatically excluded from comparison:
- `.PKGINFO`
- `.SIGN.*`
- `.spdx.json` / `.cdx.json`
- `buildinfo`

## Debugging Differences

### Find Output Directory

```bash
COMPARE_DIR=$(find /var/folders -name "melange-compare-*" -type d | head -1)
```

### Compare APK Contents

```bash
# List files in Wolfi package
tar -tvzf "$COMPARE_DIR/wolfi/PACKAGE/PACKAGE-*.apk"

# List files in melange2 package
tar -tvzf "$COMPARE_DIR/melange2/PACKAGE/ARCH/PACKAGE-*.apk"
```

### Compare Metadata

```bash
# Extract PKGINFO from both
tar -xzf "$COMPARE_DIR/wolfi/PACKAGE/PACKAGE-*.apk" -O .PKGINFO > wolfi-pkginfo
tar -xzf "$COMPARE_DIR/melange2/PACKAGE/ARCH/PACKAGE-*.apk" -O .PKGINFO > melange2-pkginfo
diff wolfi-pkginfo melange2-pkginfo
```

## Architecture Considerations

On ARM Macs, use native architecture for speed:

```bash
# Fast (native)
-arch="aarch64"

# Slow (QEMU emulation)
-arch="x86_64"
```

## Implementation

### Key Files

| File | Purpose |
|------|---------|
| `test/compare/compare_test.go` | Main test logic |
| `test/compare/apkindex.go` | APKINDEX parsing |
| `test/compare/fetch.go` | Package downloading |

### How It Works

1. Parse the melange YAML config from wolfi-dev/os
2. Build with melange2
3. Download corresponding package from Wolfi repository
4. Compare APK contents (excluding non-deterministic files)
5. Report results

## Progress Tracking

See [GitHub Issue #32](https://github.com/dlorenc/melange2/issues/32) for ongoing validation progress.

## Troubleshooting

### Package Not Found in Repository

If a package exists in wolfi-dev/os but not in the Wolfi repository:
- New packages not yet published
- Package was removed

### Version Mismatch

When config version differs from repository version:
- Config was updated but new package not built yet
- Results annotated with "(version mismatch)"

### BuildKit Connection Issues

```bash
docker rm -f buildkitd
docker run -d --name buildkitd --privileged -p 8372:8372 \
  moby/buildkit:latest --addr tcp://0.0.0.0:8372
```
