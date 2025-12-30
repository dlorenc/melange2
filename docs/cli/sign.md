# melange2 sign / sign-index

Sign APK packages and repository indexes.

## sign

Sign an APK package on disk with a provided key.

### Usage

```
melange sign [flags] <package.apk> [package.apk...]
```

### Description

Signs one or more APK packages on disk with the provided signing key. The package files are replaced with the APK containing the new signature. Multiple packages can be signed in parallel.

### Example

```bash
melange sign [--signing-key=key.rsa] package.apk

melange sign [--signing-key=key.rsa] *.apk
```

### Flags

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--signing-key` | `-k` | `local-melange.rsa` | The signing key to use |

### Examples

#### Sign a Single Package

```bash
./melange2 sign --signing-key mykey.rsa packages/x86_64/mypackage-1.0.0-r0.apk
```

#### Sign Multiple Packages

```bash
./melange2 sign --signing-key mykey.rsa packages/x86_64/*.apk
```

#### Sign with Default Key

```bash
# Uses local-melange.rsa by default
./melange2 sign packages/x86_64/mypackage-1.0.0-r0.apk
```

---

## sign-index

Sign an APK repository index.

### Usage

```
melange sign-index [flags] <APKINDEX.tar.gz>
```

### Description

Signs an APK repository index file (APKINDEX.tar.gz) with the provided signing key. By default, it re-signs an existing signed index with the same signature. Use `--force` to create a new signature.

### Example

```bash
# Re-sign an index with the same signature
melange sign-index [--signing-key=key.rsa] <APKINDEX.tar.gz>

# Sign a new index with a new signature
melange sign-index [--signing-key=key.rsa] <APKINDEX.tar.gz> --force
```

### Flags

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--signing-key` | | `melange.rsa` | The signing key to use |
| `--force` | `-f` | `false` | When toggled, overwrites the specified index with a new index using the provided signature |

### Examples

#### Re-sign an Existing Index

```bash
./melange2 sign-index --signing-key mykey.rsa packages/x86_64/APKINDEX.tar.gz
```

#### Force Sign with New Signature

```bash
./melange2 sign-index --signing-key mykey.rsa packages/x86_64/APKINDEX.tar.gz --force
```

#### Sign with Default Key

```bash
# Uses melange.rsa by default
./melange2 sign-index packages/x86_64/APKINDEX.tar.gz
```

---

## Workflow

A typical signing workflow:

```bash
# 1. Generate signing keys
./melange2 keygen mykey.rsa

# 2. Build packages (with or without signing during build)
./melange2 build mypackage.yaml --buildkit-addr tcp://localhost:1234

# 3. Sign packages
./melange2 sign --signing-key mykey.rsa packages/x86_64/*.apk

# 4. Create repository index
./melange2 index -o packages/x86_64/APKINDEX.tar.gz packages/x86_64/*.apk

# 5. Sign the index
./melange2 sign-index --signing-key mykey.rsa packages/x86_64/APKINDEX.tar.gz
```

## See Also

- [keygen command](keygen.md) - Generate signing keys
- [build command](build.md) - Build packages (can sign during build)
