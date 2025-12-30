# Generating Signing Keys

This guide covers generating RSA key pairs for signing APK packages and repository indexes.

## The keygen Command

The `melange keygen` command generates an RSA key pair for package signing.

### Basic Usage

```bash
melange keygen
```

This generates a 4096-bit RSA key pair with the default names:
- `melange.rsa` - Private key (for signing)
- `melange.rsa.pub` - Public key (for verification)

### Custom Key Name

Specify a custom name for the key files:

```bash
melange keygen my-signing-key.rsa
```

This generates:
- `my-signing-key.rsa` - Private key
- `my-signing-key.rsa.pub` - Public key

### Command Reference

```
melange keygen [key.rsa]

Generate a key for package signing.

Arguments:
  key.rsa    Name for the generated key file (default: melange.rsa)

Flags:
  --key-size int   the size of the prime to calculate (in bits) (default 4096)
```

## Key Size

The `--key-size` flag controls the RSA key size in bits:

```bash
# Default 4096-bit key (recommended)
melange keygen

# 2048-bit key (minimum allowed)
melange keygen --key-size 2048

# 8192-bit key (slower but more secure)
melange keygen --key-size 8192
```

**Important**: Key sizes below 2048 bits are rejected as insecure.

```bash
# This will fail with an error
melange keygen --key-size 1024
# Error: key size is less than 2048 bits, this is not considered safe
```

## Key Format

### Private Key

The private key is stored in PEM-encoded PKCS#1 format:

```
-----BEGIN RSA PRIVATE KEY-----
MIIJKQIBAAKCAgEA...
...
-----END RSA PRIVATE KEY-----
```

### Public Key

The public key is stored in PEM-encoded PKIX format:

```
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA...
...
-----END PUBLIC KEY-----
```

## Complete Example

Generate keys and use them for building and signing:

```bash
# 1. Generate a new key pair
melange keygen prod-signing.rsa

# Output:
# INFO generating keypair with a 4096 bit prime, please wait...
# INFO wrote private key to prod-signing.rsa
# INFO wrote public key to prod-signing.rsa.pub

# 2. Verify the keys were created
ls -la prod-signing.rsa*
# -rw-------  1 user  staff  3247 Dec 30 10:00 prod-signing.rsa
# -rw-r--r--  1 user  staff   800 Dec 30 10:00 prod-signing.rsa.pub

# 3. Use the key for building
melange build package.yaml \
    --signing-key prod-signing.rsa \
    --buildkit-addr tcp://localhost:1234
```

## Key Management Best Practices

### Secure Storage

1. **Never commit private keys to version control**

   Add to `.gitignore`:
   ```
   *.rsa
   !*.rsa.pub
   ```

2. **Set restrictive permissions**
   ```bash
   chmod 600 melange.rsa
   chmod 644 melange.rsa.pub
   ```

3. **Use secure key storage for production**
   - Hardware Security Modules (HSMs)
   - Cloud key management services (AWS KMS, GCP KMS, etc.)
   - Encrypted storage with access controls

### Key Rotation

Periodically rotate signing keys:

```bash
# 1. Generate new keys
melange keygen melange-2025.rsa

# 2. Update your build process to use the new key
melange build package.yaml --signing-key melange-2025.rsa

# 3. Distribute the new public key to users
# Users should add melange-2025.rsa.pub to their trusted keys

# 4. After a transition period, retire the old key
```

### Environment-Specific Keys

Use different keys for different environments:

```bash
# Development
melange keygen dev.rsa

# Staging
melange keygen staging.rsa

# Production
melange keygen prod.rsa
```

## Distributing Public Keys

Users need your public key to verify packages. Common distribution methods:

1. **Include in repository**
   ```bash
   # Copy public key to a served location
   cp melange.rsa.pub /var/www/packages/keys/
   ```

2. **Add to container images**
   ```yaml
   # In apko configuration
   contents:
     keyring:
       - https://example.com/keys/melange.rsa.pub
   ```

3. **Package manager configuration**
   ```bash
   # On Alpine-based systems
   wget -O /etc/apk/keys/melange.rsa.pub https://example.com/keys/melange.rsa.pub
   ```

## Verifying Keys

Inspect the generated keys:

```bash
# View public key details
openssl rsa -pubin -in melange.rsa.pub -text -noout

# Verify private key
openssl rsa -in melange.rsa -check
# RSA key ok
```

## Troubleshooting

### "key size is less than 2048 bits"

The minimum key size is 2048 bits. Use a larger key size:
```bash
melange keygen --key-size 4096
```

### "unable to open private key for writing"

Check write permissions in the current directory:
```bash
ls -la .
chmod u+w .
```

### Key generation is slow

Large key sizes (e.g., 8192 bits) require more computation:
- 2048-bit: ~1 second
- 4096-bit: ~5-10 seconds
- 8192-bit: ~30-60 seconds

For faster generation during development, use 2048-bit keys. For production, use 4096-bit or larger.
