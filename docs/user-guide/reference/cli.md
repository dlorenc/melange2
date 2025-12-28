# CLI Reference

## melange2

```
melange2 [command] [flags]
```

### Global Flags

| Flag | Description |
|------|-------------|
| `--log-level` | Log level: debug, info, warn, error (default: info) |
| `-h, --help` | Help for any command |

### Commands

| Command | Description |
|---------|-------------|
| `build` | Build a package from YAML configuration |
| `test` | Test a package with YAML configuration |
| `keygen` | Generate a signing key pair |
| `sign` | Sign an APK package |
| `sign-index` | Sign an APK index |
| `index` | Create repository index from packages |
| `bump` | Update package version |
| `lint` | Lint an APK for problems |
| `version` | Print version information |

---

## melange2 build

Build a package from a YAML configuration file.

```bash
melange2 build [config.yaml] [flags]
```

### Key Flags

| Flag | Description |
|------|-------------|
| `--buildkit-addr` | BuildKit daemon address (e.g., `tcp://localhost:1234`) |
| `--arch` | Target architectures (comma-separated) |
| `--out-dir` | Output directory (default: `./packages/`) |
| `--signing-key` | Key for signing packages |
| `--cache-dir` | Host cache directory |
| `--source-dir` | Source directory |
| `--debug` | Enable debug logging |

### Repository Flags

| Flag | Description |
|------|-------------|
| `-r, --repository-append` | Additional APK repositories |
| `-k, --keyring-append` | Additional repository keys |
| `--ignore-signatures` | Skip signature verification |

### Build Options

| Flag | Description |
|------|-------------|
| `--pipeline-dir` | Directory for custom pipelines |
| `--build-option` | Enable build options |
| `--vars-file` | Variables file |
| `--env-file` | Environment file |
| `--empty-workspace` | Start with empty workspace |

### Output Options

| Flag | Description |
|------|-------------|
| `--generate-index` | Generate APKINDEX.tar.gz (default: true) |
| `--generate-provenance` | Generate SLSA provenance |
| `--create-build-log` | Create package.log file |

### Examples

```bash
# Basic build
melange2 build package.yaml --buildkit-addr tcp://localhost:1234

# Build with signing
melange2 build package.yaml \
  --buildkit-addr tcp://localhost:1234 \
  --signing-key melange.rsa

# Build specific architecture
melange2 build package.yaml \
  --buildkit-addr tcp://localhost:1234 \
  --arch aarch64

# Build with debug output
melange2 build package.yaml \
  --buildkit-addr tcp://localhost:1234 \
  --debug

# Build with cache
melange2 build package.yaml \
  --buildkit-addr tcp://localhost:1234 \
  --cache-dir ./melange-cache
```

---

## melange2 test

Test a package using YAML configuration.

```bash
melange2 test [config.yaml] [package-name] [flags]
```

### Key Flags

| Flag | Description |
|------|-------------|
| `--buildkit-addr` | BuildKit daemon address |
| `--arch` | Target architecture |
| `--source-dir` | Test fixtures directory |
| `--debug` | Enable debug logging |

### Repository Flags

| Flag | Description |
|------|-------------|
| `-r, --repository-append` | Additional APK repositories |
| `-k, --keyring-append` | Additional repository keys |
| `--test-package-append` | Extra packages for test environment |

### Examples

```bash
# Test package
melange2 test package.yaml --buildkit-addr tcp://localhost:1234

# Test specific package name
melange2 test package.yaml mypackage --buildkit-addr tcp://localhost:1234

# Test specific version
melange2 test package.yaml mypackage=1.0.0-r0 --buildkit-addr tcp://localhost:1234

# Test with local repository
melange2 test package.yaml \
  --buildkit-addr tcp://localhost:1234 \
  --repository-append ./packages \
  --keyring-append ./melange.rsa.pub
```

---

## melange2 keygen

Generate a key pair for package signing.

```bash
melange2 keygen [flags]
```

### Flags

| Flag | Description |
|------|-------------|
| `--keyname` | Base name for key files (default: `melange`) |

### Example

```bash
melange2 keygen --keyname myproject
# Creates myproject.rsa and myproject.rsa.pub
```

---

## melange2 sign

Sign an APK package.

```bash
melange2 sign [flags] [package.apk...]
```

### Flags

| Flag | Description |
|------|-------------|
| `--key` | Private key for signing |

### Example

```bash
melange2 sign --key melange.rsa packages/x86_64/mypackage-1.0.0-r0.apk
```

---

## melange2 sign-index

Sign an APK index.

```bash
melange2 sign-index [flags] [APKINDEX.tar.gz]
```

### Flags

| Flag | Description |
|------|-------------|
| `--key` | Private key for signing |

### Example

```bash
melange2 sign-index --key melange.rsa packages/x86_64/APKINDEX.tar.gz
```

---

## melange2 index

Create a repository index from APK packages.

```bash
melange2 index [flags] [packages...]
```

### Flags

| Flag | Description |
|------|-------------|
| `--output` | Output file (default: `APKINDEX.tar.gz`) |

### Example

```bash
melange2 index --output packages/x86_64/APKINDEX.tar.gz packages/x86_64/*.apk
```

---

## melange2 bump

Update a package to a new version.

```bash
melange2 bump [config.yaml] [version] [flags]
```

### Example

```bash
melange2 bump package.yaml 1.2.3
```

---

## melange2 version

Print version information.

```bash
melange2 version
```
