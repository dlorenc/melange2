# Package Signing in melange2

This section covers cryptographic signing of APK packages and repository indexes in melange2.

## Why Signing Matters

Package signing is a critical security mechanism that ensures:

1. **Authenticity**: Packages come from a trusted source
2. **Integrity**: Packages have not been tampered with since they were built
3. **Trust Chain**: Users can verify packages before installation

When you install an APK package, the package manager verifies the signature against known public keys. If the signature is invalid or missing (when signatures are required), the installation is rejected.

## How APK Signing Works

APK packages use RSA digital signatures. The signing process works as follows:

1. A **private key** is used to sign packages during the build process
2. The corresponding **public key** is distributed to users
3. When installing, the package manager uses the public key to verify the signature

melange2 signs packages by:
1. Computing a SHA-256 hash of the package's control section (containing `.PKGINFO`)
2. Signing this hash with RSA using the private key
3. Prepending the signature as a `.SIGN.RSA256.<keyname>.pub` entry in the package

## Signing Components

melange2 provides several commands for signing:

| Command | Purpose |
|---------|---------|
| `melange keygen` | Generate RSA key pairs for signing |
| `melange sign` | Sign existing APK packages |
| `melange sign-index` | Sign APK repository indexes |
| `melange index` | Create (and optionally sign) repository indexes |

## Signing During Builds

You can sign packages automatically during the build process by providing the `--signing-key` flag:

```bash
melange build package.yaml --signing-key melange.rsa --buildkit-addr tcp://localhost:1234
```

When a signing key is provided:
1. Each built package is signed with the specified key
2. The generated APKINDEX.tar.gz is also signed (if `--generate-index` is enabled, which is the default)

## Key Files

melange2 generates and uses two files for signing:

| File | Type | Purpose |
|------|------|---------|
| `melange.rsa` | RSA Private Key | Used to sign packages (keep secret) |
| `melange.rsa.pub` | RSA Public Key | Distributed to users for verification |

The private key is in PKCS#1 format (PEM-encoded), and the public key is in PKIX format (PEM-encoded).

## Signature Format

Package signatures follow the APK signature format:

- Signature file name: `.SIGN.RSA256.<keyname>.pub`
- Hash algorithm: SHA-256
- Signature algorithm: RSA with SHA-256

For example, if signing with `melange.rsa`, the signature entry will be named `.SIGN.RSA256.melange.rsa.pub`.

## Security Best Practices

1. **Protect Private Keys**: Store private keys securely and never commit them to version control
2. **Use Strong Keys**: melange2 defaults to 4096-bit RSA keys (minimum 2048-bit required)
3. **Rotate Keys**: Periodically generate new keys and update your distribution
4. **Separate Keys**: Use different keys for different purposes (development, production, etc.)
5. **Verify Signatures**: Always verify package signatures in production environments

## Next Steps

- [Generating Signing Keys](keygen.md) - Create RSA key pairs
- [Creating Repositories](repositories.md) - Build and sign APK indexes
