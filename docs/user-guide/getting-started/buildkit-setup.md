# BuildKit Setup

melange2 requires a running BuildKit daemon to execute builds. This guide covers the most common setup options.

## Option 1: Docker Container (Recommended)

Start BuildKit as a Docker container:

```bash
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234
```

Verify it's running:

```bash
docker exec buildkitd buildctl --addr tcp://127.0.0.1:1234 debug workers
```

Use with melange2:

```bash
melange2 build package.yaml --buildkit-addr tcp://localhost:1234
```

### Stopping and Restarting

```bash
# Stop
docker stop buildkitd

# Start again
docker start buildkitd

# Remove and recreate
docker rm -f buildkitd
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234
```

## Option 2: Local Daemon

If you have buildkitd installed locally:

```bash
# Start the daemon
sudo buildkitd --addr tcp://0.0.0.0:1234
```

## Common Issues

### Connection Reset by Peer

**Symptom:**
```
rpc error: code = Unavailable desc = connection error: desc = "error reading server preface: read tcp ... connection reset by peer"
```

**Cause:** BuildKit container started with wrong command (double `buildkitd`).

**Fix:** The entrypoint already includes `buildkitd`, so only pass arguments:

```bash
# WRONG - causes silent failures
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest buildkitd --addr tcp://0.0.0.0:1234

# CORRECT - just pass the args
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234
```

### Permission Denied

BuildKit requires privileged mode for container operations:

```bash
docker run -d --name buildkitd --privileged ...
```

## Architecture Considerations

On ARM Macs (M1/M2/M3), builds run natively for `aarch64`. Building for `x86_64` requires QEMU emulation and is significantly slower:

```bash
# Fast on ARM Mac
melange2 build package.yaml --buildkit-addr tcp://localhost:1234 --arch aarch64

# Slow on ARM Mac (QEMU emulation)
melange2 build package.yaml --buildkit-addr tcp://localhost:1234 --arch x86_64
```

## Next Steps

- [Build your first package](first-build.md)
