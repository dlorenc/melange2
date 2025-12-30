# Creating APK Repositories

This guide covers creating APK repository indexes and signing them for distribution.

## Repository Structure

An APK repository consists of:

```
packages/
  x86_64/
    APKINDEX.tar.gz       # Signed package index
    package-1.0.0-r0.apk  # Signed packages
    another-2.0.0-r0.apk
  aarch64/
    APKINDEX.tar.gz
    package-1.0.0-r0.apk
    another-2.0.0-r0.apk
```

The `APKINDEX.tar.gz` file contains metadata about all packages in the repository, allowing package managers to query available packages without downloading each one.

## The index Command

The `melange index` command creates an `APKINDEX.tar.gz` from a list of APK packages.

### Basic Usage

```bash
melange index -o APKINDEX.tar.gz *.apk
```

### Command Reference

```
melange index [flags] <package.apk...>

Creates a repository index from a list of package files.

Arguments:
  package.apk    One or more APK package files to include in the index

Flags:
  -o, --output string        Output generated index to FILE (default "APKINDEX.tar.gz")
  -s, --source string        Source FILE to use for pre-existing index entries (default "APKINDEX.tar.gz")
  -a, --arch string          Index only packages which match the expected architecture
  -m, --merge                Merge pre-existing index entries
      --signing-key string   Key to use for signing the index (optional)
```

### Creating a Signed Index

Sign the index during creation:

```bash
melange index \
    -o APKINDEX.tar.gz \
    --signing-key melange.rsa \
    packages/x86_64/*.apk
```

### Filtering by Architecture

Index only packages matching a specific architecture:

```bash
melange index \
    -o packages/x86_64/APKINDEX.tar.gz \
    --arch x86_64 \
    packages/x86_64/*.apk
```

### Merging with Existing Index

Add new packages to an existing index:

```bash
melange index \
    -o APKINDEX.tar.gz \
    --source APKINDEX.tar.gz \
    --merge \
    --signing-key melange.rsa \
    new-package-1.0.0-r0.apk
```

## The sign-index Command

The `melange sign-index` command signs an existing APK index.

### Basic Usage

```bash
melange sign-index APKINDEX.tar.gz
```

### Command Reference

```
melange sign-index [flags] <APKINDEX.tar.gz>

Sign an APK index.

Arguments:
  APKINDEX.tar.gz    The index file to sign

Flags:
      --signing-key string   the signing key to use (default "melange.rsa")
  -f, --force                when toggled, overwrites the specified index with a new
                             index using the provided signature
```

### Re-signing an Index

If an index is already signed, `sign-index` does nothing by default:

```bash
melange sign-index APKINDEX.tar.gz
# INFO index APKINDEX.tar.gz is already signed, doing nothing
```

Use `--force` to replace the existing signature:

```bash
melange sign-index --force --signing-key new-key.rsa APKINDEX.tar.gz
# INFO Replacing existing signed index (APKINDEX.tar.gz) with signed index with key new-key.rsa
```

## The sign Command

The `melange sign` command signs individual APK packages.

### Basic Usage

```bash
melange sign package.apk
```

### Command Reference

```
melange sign [flags] <package.apk...>

Signs an APK package on disk with the provided key. The package is replaced
with the APK containing the new signature.

Arguments:
  package.apk    One or more APK package files to sign

Flags:
  -k, --signing-key string   The signing key to use (default "local-melange.rsa")
```

### Signing Multiple Packages

Sign all packages in a directory:

```bash
melange sign --signing-key melange.rsa packages/x86_64/*.apk
```

Packages are signed in parallel for efficiency.

## Complete Repository Workflow

### 1. Generate Signing Keys

```bash
melange keygen repository.rsa
```

### 2. Build Packages with Signing

```bash
# Build packages (automatically signed and indexed)
melange build package.yaml \
    --signing-key repository.rsa \
    --out-dir packages/ \
    --buildkit-addr tcp://localhost:1234
```

The build command with `--signing-key`:
- Signs each built package
- Generates `APKINDEX.tar.gz` in each architecture directory
- Signs the generated index

### 3. Verify the Repository

```bash
# Check package signature
tar -tzf packages/x86_64/mypackage-1.0.0-r0.apk | head -1
# .SIGN.RSA256.repository.rsa.pub

# Check index signature
tar -tzf packages/x86_64/APKINDEX.tar.gz | head -1
# .SIGN.RSA256.repository.rsa.pub
```

### 4. Add More Packages

Build additional packages and merge into existing index:

```bash
# Build new package
melange build another-package.yaml \
    --signing-key repository.rsa \
    --out-dir packages/ \
    --buildkit-addr tcp://localhost:1234

# Or manually merge if needed
melange index \
    -o packages/x86_64/APKINDEX.tar.gz \
    --source packages/x86_64/APKINDEX.tar.gz \
    --merge \
    --signing-key repository.rsa \
    packages/x86_64/another-package-*.apk
```

## Multi-Architecture Repositories

Create indexes for each architecture:

```bash
# Create indexes for each architecture
for arch in x86_64 aarch64; do
    melange index \
        -o packages/${arch}/APKINDEX.tar.gz \
        --arch ${arch} \
        --signing-key repository.rsa \
        packages/${arch}/*.apk
done
```

## Index Contents

The `APKINDEX.tar.gz` contains:

| File | Description |
|------|-------------|
| `.SIGN.RSA256.<key>.pub` | Digital signature (if signed) |
| `DESCRIPTION` | Repository description |
| `APKINDEX` | Package metadata in APK index format |

### APKINDEX Format

Each package entry in APKINDEX includes:

```
C:Q1abc123...=
P:package-name
V:1.0.0-r0
A:x86_64
S:12345
I:67890
T:Package description
U:https://example.com
L:Apache-2.0
o:origin-package
m:Maintainer <maintainer@example.com>
t:1703952000
c:abc123def456
D:dependency1 dependency2
p:provides1 provides2

```

## Serving Repositories

### Local File Server

```bash
# Serve packages directory
cd packages
python3 -m http.server 8080
```

Configure clients:
```
https://localhost:8080/x86_64
```

### Cloud Storage

Upload to cloud storage (S3, GCS, etc.):

```bash
# AWS S3
aws s3 sync packages/ s3://my-bucket/packages/ --acl public-read

# Google Cloud Storage
gsutil -m rsync -r packages/ gs://my-bucket/packages/
```

### Container Registry (OCI)

Use tools like ORAS to push to OCI registries:

```bash
oras push registry.example.com/packages:latest \
    packages/x86_64/APKINDEX.tar.gz:application/vnd.apk.index.v2+tar+gzip
```

## Troubleshooting

### "index is already signed"

The index already has a signature. Use `--force` to replace it:

```bash
melange sign-index --force --signing-key new-key.rsa APKINDEX.tar.gz
```

### "could not open signing key"

Verify the key file exists and is readable:

```bash
ls -la melange.rsa
# Should show the private key file
```

### Package not appearing in index

1. Verify the package architecture matches the `--arch` filter
2. Check that the package was included in the command arguments
3. Look for errors in the command output

### Signature verification fails

1. Ensure the public key matches the private key used for signing
2. Verify the package/index was not modified after signing
3. Check that the key name in the signature matches the installed public key
