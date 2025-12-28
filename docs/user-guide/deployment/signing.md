# Package Signing

melange packages should be signed for secure distribution.

## Generate a Signing Key

```bash
melange2 keygen
```

This creates:
- `melange.rsa` - Private key (keep secure!)
- `melange.rsa.pub` - Public key (distribute to users)

### Custom Key Name

```bash
melange2 keygen --keyname myproject
# Creates myproject.rsa and myproject.rsa.pub
```

## Sign During Build

Use `--signing-key` to sign packages as they're built:

```bash
melange2 build package.yaml \
  --buildkit-addr tcp://localhost:1234 \
  --signing-key melange.rsa
```

The APKINDEX will also be signed automatically.

## Sign Existing Packages

Sign a package after building:

```bash
melange2 sign --key melange.rsa packages/x86_64/mypackage-1.0.0-r0.apk
```

## Sign an Index

Sign or re-sign an APKINDEX:

```bash
melange2 sign-index --key melange.rsa packages/x86_64/APKINDEX.tar.gz
```

## Distributing Public Keys

Users need your public key to verify packages:

```yaml
# In user's melange config
environment:
  contents:
    keyring:
      - https://example.com/keys/melange.rsa.pub
      # Or local path
      - /path/to/melange.rsa.pub
```

## Repository Structure

A signed repository looks like:

```
packages/
├── x86_64/
│   ├── APKINDEX.tar.gz      # Signed index
│   ├── mypackage-1.0.0-r0.apk
│   └── other-package-2.0.0-r0.apk
└── aarch64/
    ├── APKINDEX.tar.gz
    └── ...
```

## Creating a Repository

### Generate Index

```bash
melange2 index \
  --output packages/x86_64/APKINDEX.tar.gz \
  packages/x86_64/*.apk
```

### Sign Index

```bash
melange2 sign-index \
  --key melange.rsa \
  packages/x86_64/APKINDEX.tar.gz
```

### Or Do Both During Build

```bash
melange2 build package.yaml \
  --buildkit-addr tcp://localhost:1234 \
  --signing-key melange.rsa \
  --generate-index
```

## Hosting Repositories

### Static File Server

Any HTTP server works:

```bash
# Simple Python server
cd packages
python -m http.server 8080

# Nginx, Apache, S3, GCS, etc.
```

### S3/GCS Bucket

```bash
# Upload to S3
aws s3 sync packages/ s3://my-bucket/packages/

# Users can then use:
# https://my-bucket.s3.amazonaws.com/packages/
```

## Security Best Practices

1. **Protect private keys** - Never commit to version control
2. **Use separate keys** - Different keys for different environments
3. **Rotate keys** - Periodically generate new keys
4. **Verify signatures** - Always enable signature verification

## Ignoring Signatures (Development Only)

For local development, you can skip verification:

```bash
melange2 build package.yaml \
  --buildkit-addr tcp://localhost:1234 \
  --ignore-signatures
```

**Never use `--ignore-signatures` in production!**
