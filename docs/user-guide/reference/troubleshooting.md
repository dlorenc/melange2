# Troubleshooting

Common issues and solutions when using melange2.

## BuildKit Connection Issues

### Connection Reset by Peer

**Error:**
```
rpc error: code = Unavailable desc = connection error: desc = "error reading server preface: read tcp ... connection reset by peer"
```

**Cause:** BuildKit container started with wrong command.

**Fix:**
```bash
docker rm -f buildkitd
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234
```

Don't include `buildkitd` in the command - the entrypoint already has it.

### Connection Refused

**Error:**
```
error: failed to dial: dial tcp 127.0.0.1:1234: connect: connection refused
```

**Cause:** BuildKit not running.

**Fix:**
```bash
# Check if running
docker ps | grep buildkitd

# Start if needed
docker start buildkitd
# Or create new
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234
```

### Context Deadline Exceeded

**Error:**
```
context deadline exceeded
```

**Cause:** Build taking too long, or BuildKit unresponsive.

**Fix:**
```bash
# Increase timeout
melange2 build package.yaml --timeout 30m

# Or restart BuildKit
docker restart buildkitd
```

## Package Resolution Issues

### Package Not Found

**Error:**
```
ERROR: unable to select packages: mypackage-1.0.0-r0: package 'mypackage-1.0.0-r0' not found
```

**Cause:** Package not in configured repositories.

**Fix:**
```bash
# Add repository containing the package
melange2 build package.yaml \
  --repository-append https://packages.wolfi.dev/os \
  --keyring-append https://packages.wolfi.dev/os/wolfi-signing.rsa.pub

# For local packages
melange2 build package.yaml \
  --repository-append ./packages \
  --keyring-append ./melange.rsa.pub
```

### Signature Verification Failed

**Error:**
```
ERROR: UNTRUSTED signature
```

**Cause:** Missing or wrong keyring.

**Fix:**
```bash
# Add the correct public key
melange2 build package.yaml \
  --keyring-append https://packages.wolfi.dev/os/wolfi-signing.rsa.pub

# For development only
melange2 build package.yaml --ignore-signatures
```

## Build Failures

### Permission Denied

**Error:**
```
/bin/sh: can't create /some/path: Permission denied
```

**Cause:** Trying to write outside allowed directories.

**Fix:** Write to `${{targets.destdir}}`:
```yaml
pipeline:
  - runs: |
      # Wrong
      echo "data" > /usr/share/myfile

      # Correct
      mkdir -p ${{targets.destdir}}/usr/share
      echo "data" > ${{targets.destdir}}/usr/share/myfile
```

### Command Not Found

**Error:**
```
/bin/sh: go: not found
```

**Cause:** Required package not in build environment.

**Fix:**
```yaml
environment:
  contents:
    packages:
      - go  # Add required packages
      - build-base
```

### Source Fetch Failed

**Error:**
```
wget: server returned error: HTTP/1.1 404 Not Found
```

**Cause:** Source URL incorrect or unavailable.

**Fix:**
- Verify URL is correct
- Check if version matches upstream releases
- Try alternate mirror

### Checksum Mismatch

**Error:**
```
SHA256 checksum mismatch
```

**Cause:** Downloaded file differs from expected.

**Fix:**
- Re-download and get new checksum
- Update `expected-sha256` in config
- Check if upstream released updated tarball

## Test Failures

### Test Package Not Found

**Error:**
```
package 'mypackage' not found
```

**Cause:** Package not built or not in repository.

**Fix:**
```bash
# Build first
melange2 build package.yaml --buildkit-addr tcp://localhost:1234

# Then test with local repo
melange2 test package.yaml \
  --repository-append ./packages \
  --keyring-append ./melange.rsa.pub
```

### Test Environment Issues

**Error:**
```
/bin/sh: test: not found
```

**Cause:** Missing basic utilities in test environment.

**Fix:**
```yaml
test:
  environment:
    contents:
      packages:
        - busybox  # Provides basic utilities
```

## Linter Errors

### setuidgid

**Error:**
```
LINT ERROR: setuidgid: found setuid/setgid files
```

**Cause:** Files have setuid/setgid bits set.

**Fix:**
```yaml
package:
  checks:
    disabled:
      - setuidgid  # Only if intentional
```

### usrlocal

**Error:**
```
LINT ERROR: usrlocal: files found in /usr/local
```

**Cause:** Package installs to non-standard location.

**Fix:** Use a `-compat` subpackage or install to `/usr` instead.

### strip

**Error:**
```
LINT ERROR: strip: unstripped binary found
```

**Cause:** Debug symbols not removed.

**Fix:**
```yaml
pipeline:
  - uses: strip  # Add strip step
```

## Performance Issues

### Slow Builds on ARM Mac

**Cause:** QEMU emulation for x86_64.

**Fix:**
```bash
# Build for native architecture
melange2 build package.yaml --arch aarch64
```

### Cache Not Working

**Symptoms:** Builds always re-execute everything.

**Causes:**
- Timestamps in build commands
- Random values in scripts
- Environment changes

**Fix:** Make builds deterministic:
```yaml
pipeline:
  - runs: |
      # Avoid timestamps
      # Use ${{package.version}} instead of $(date)
```

## Getting Help

1. Run with `--debug` for detailed logs
2. Check BuildKit logs: `docker logs buildkitd`
3. File issues at: https://github.com/dlorenc/melange2/issues
