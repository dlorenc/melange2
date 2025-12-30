# melange2 keygen

Generate a key for package signing.

## Usage

```
melange keygen [key.rsa] [flags]
```

## Description

The `keygen` command generates an RSA key pair for signing APK packages and repository indexes. It creates two files:
- A private key file (e.g., `melange.rsa`)
- A public key file (e.g., `melange.rsa.pub`)

The private key is used for signing packages and indexes. The public key is distributed to users who need to verify signatures.

## Example

```bash
melange keygen [key.rsa]
```

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `key.rsa` | No | `melange.rsa` | Name of the private key file to generate |

## Flags

| Flag | Shorthand | Default | Description |
|------|-----------|---------|-------------|
| `--key-size` | | `4096` | The size of the prime to calculate (in bits) |

## Examples

### Generate Default Key

```bash
# Creates melange.rsa and melange.rsa.pub
./melange2 keygen
```

### Generate Named Key

```bash
# Creates mykey.rsa and mykey.rsa.pub
./melange2 keygen mykey.rsa
```

### Generate Key with Custom Size

```bash
# Create a 2048-bit key (minimum allowed)
./melange2 keygen mykey.rsa --key-size 2048

# Create an 8192-bit key (more secure, slower)
./melange2 keygen mykey.rsa --key-size 8192
```

## Security Notes

- The minimum key size is 2048 bits. Keys smaller than 2048 bits are rejected as insecure.
- The default key size of 4096 bits provides a good balance of security and performance.
- Keep the private key file (`.rsa`) secure and never share it.
- The public key file (`.rsa.pub`) can be distributed freely.

## Output Files

When you run `melange keygen mykey.rsa`, two files are created:

| File | Format | Purpose |
|------|--------|---------|
| `mykey.rsa` | PKCS#1 RSA Private Key (PEM) | Sign packages and indexes |
| `mykey.rsa.pub` | PKIX Public Key (PEM) | Verify signatures |

## Using Generated Keys

### Sign Packages

```bash
./melange2 sign --signing-key mykey.rsa packages/x86_64/*.apk
```

### Sign During Build

```bash
./melange2 build mypackage.yaml --signing-key mykey.rsa
```

### Sign Repository Index

```bash
./melange2 sign-index --signing-key mykey.rsa packages/x86_64/APKINDEX.tar.gz
```

### Distribute Public Key

Users who want to verify packages need the public key:

```bash
# Add public key to apk keyring
cp mykey.rsa.pub /etc/apk/keys/

# Or specify in melange build
./melange2 build otherpackage.yaml --keyring-append ./mykey.rsa.pub
```

## See Also

- [sign command](sign.md) - Sign packages with generated keys
- [build command](build.md) - Use signing key during build
