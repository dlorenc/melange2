# Troubleshooting

This document covers common issues and their solutions when using melange2.

## BuildKit Connection Issues

### Connection Refused

**Symptom:**
```
error: connecting to buildkit at tcp://localhost:1234: connection refused
```

**Cause:** BuildKit daemon is not running or not listening on the specified address.

**Solutions:**

1. **Start BuildKit:**
   ```bash
   docker run -d --name buildkitd --privileged -p 1234:1234 \
     moby/buildkit:latest --addr tcp://0.0.0.0:1234
   ```

2. **Check if BuildKit is running:**
   ```bash
   docker ps | grep buildkit
   ```

3. **Restart BuildKit if it exists but is stopped:**
   ```bash
   docker start buildkitd
   ```

### Connection Reset by Peer

**Symptom:**
```
error: connection reset by peer
```

**Cause:** BuildKit was started with incorrect command-line arguments, typically missing `--addr tcp://0.0.0.0:1234`.

**Solution:**

Remove and restart BuildKit with correct arguments:
```bash
docker rm -f buildkitd
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234
```

### BuildKit Has No Workers

**Symptom:**
```
error: pinging buildkit: buildkit has no workers
```

**Cause:** BuildKit started but failed to initialize workers, usually due to container runtime issues.

**Solutions:**

1. **Check BuildKit logs:**
   ```bash
   docker logs buildkitd
   ```

2. **Restart with fresh state:**
   ```bash
   docker rm -f buildkitd
   docker run -d --name buildkitd --privileged -p 1234:1234 \
     moby/buildkit:latest --addr tcp://0.0.0.0:1234
   ```

3. **Ensure privileged mode is enabled** (required for BuildKit):
   ```bash
   docker run -d --name buildkitd --privileged ...
   ```

### Test Timeout

**Symptom:**
- Tests hang or timeout
- E2E tests fail with context deadline exceeded

**Cause:** BuildKit is unresponsive or overloaded.

**Solution:**

Restart BuildKit:
```bash
docker restart buildkitd
```

## Cache Issues

### Permission Denied in Cache

**Symptom:**
```
error: permission denied: /home/build/.cache/go-build/...
```

**Cause:** Cache mount ownership mismatch with build user.

**Explanation:** Cache mounts in melange2 are created with build user ownership (UID/GID 1000). If previous builds ran as root or a different user, cache files may have incorrect ownership.

**Solutions:**

1. **Clear the BuildKit cache:**
   ```bash
   docker exec buildkitd rm -rf /var/lib/buildkit/cache
   docker restart buildkitd
   ```

2. **Use a fresh BuildKit instance:**
   ```bash
   docker rm -f buildkitd
   docker run -d --name buildkitd --privileged -p 1234:1234 \
     moby/buildkit:latest --addr tcp://0.0.0.0:1234
   ```

### Cache Not Being Used

**Symptom:**
- Builds redownload dependencies every time
- No cache hits in progress output

**Causes:**
1. Cache mounts not enabled
2. Environment variables not set correctly
3. Cache directory path mismatch

**Solutions:**

1. **Enable default cache mounts:**
   ```go
   builder.WithDefaultCacheMounts()
   ```

2. **Verify environment variables are set:**
   Check that `GOMODCACHE`, `GOCACHE`, etc. are set to the cache mount paths.

3. **Check cache mount paths:**
   All paths should use `/home/build` (not `/root`):
   - `/home/build/go/pkg/mod` (Go modules)
   - `/home/build/.cache/pip` (pip)
   - `/home/build/.npm` (npm)

### Registry Cache Failures

**Symptom:**
```
error: failed to push cache to registry
```

**Causes:**
1. Registry not accessible from BuildKit
2. Registry requires authentication
3. Insecure registry not configured

**Solutions:**

1. **For in-cluster registry, configure insecure access:**

   Create `/etc/buildkit/buildkit.toml`:
   ```toml
   [registry."registry:5000"]
     http = true
     insecure = true
   ```

2. **Check registry connectivity:**
   ```bash
   docker exec buildkitd wget -q -O- http://registry:5000/v2/
   ```

3. **Verify cache configuration:**
   ```yaml
   # deploy/gke/configmap.yaml
   data:
     cache-registry: "registry:5000/melange-cache"
     cache-mode: "max"
   ```

## Build Failures

### Pipeline Step Failed

**Symptom:**
```
error: pipeline 0: exit code: 1
```

**Diagnosis:**

1. **Enable debug mode:**
   ```bash
   ./melange2 build pkg.yaml --debug
   ```
   This adds `set -x` to all shell scripts for verbose output.

2. **Export debug image on failure:**
   ```bash
   ./melange2 build pkg.yaml \
     --export-on-failure=docker \
     --export-ref=debug:failed-build
   ```
   Then inspect the container:
   ```bash
   docker run -it debug:failed-build /bin/sh
   ```

### Workspace Permission Issues

**Symptom:**
```
error: permission denied: /home/build/melange-out/...
```

**Cause:** Workspace directories not created with correct ownership.

**Explanation:** melange2 creates workspace directories with build user ownership (UID/GID 1000). Issues can occur if:
- The base image creates `/home/build` with root ownership
- The base image creates `/home/build` with restricted permissions (700)

**Solution:** melange2 automatically fixes workspace permissions during `PrepareWorkspace()`:
```bash
mkdir -p /home/build
chown 1000:1000 /home/build
chmod 755 /home/build
```

If issues persist, check that the build user (UID 1000) exists in your base image.

### /tmp Permission Issues

**Symptom:**
```
error: mktemp: cannot create temp file: Permission denied
```

**Cause:** `/tmp` directory missing or has incorrect permissions.

**Solution:** melange2 automatically creates `/tmp` with world-writable permissions (1777) during workspace preparation. If issues persist, the base image may have a read-only `/tmp`.

## Test Failures

### E2E Tests Skipped

**Symptom:**
```
skipping e2e test in short mode
```

**Cause:** Tests run with `-short` flag.

**Solution:** Remove `-short` to run E2E tests:
```bash
# Run all tests including E2E
go test ./pkg/buildkit/...

# Unit tests only (skips E2E)
go test -short ./pkg/buildkit/...
```

### Test Layer Has No Real Binaries

**Symptom:**
```
Expected error (test layer has no real binaries)
```

**Cause:** Unit tests use fake layers without actual binaries.

**Explanation:** This is expected behavior in unit tests. The test verifies LLB structure without actually executing commands. E2E tests use real base images (`cgr.dev/chainguard/wolfi-base`) for full execution testing.

## Rate Limiting

### Docker Hub Rate Limits

**Symptom:**
```
error: toomanyrequests: You have reached your pull rate limit
```

**Cause:** Docker Hub rate limits anonymous/free pulls.

**Solutions:**

1. **Use cgr.dev images instead of Docker Hub:**
   ```yaml
   # Use this
   image: cgr.dev/chainguard/wolfi-base:latest

   # Instead of this
   image: alpine:latest
   ```

2. **Authenticate with Docker Hub:**
   ```bash
   docker login
   ```

3. **Use a registry mirror:**
   Configure BuildKit to use a local registry mirror.

## Debugging Tips

### Enable Verbose Logging

```bash
./melange2 build pkg.yaml --debug
```

### View Build Progress

The progress display shows:
- Completed steps count
- Cached steps count
- Current step name
- Total build time

Progress modes:
- `auto` - Automatically detects TTY
- `plain` - Plain text output (for logs)
- `tty` - Interactive terminal UI
- `quiet` - Suppress progress output

### Export Failed Build Environment

```bash
# Export as Docker image
./melange2 build pkg.yaml \
  --export-on-failure=docker \
  --export-ref=debug:mybuild

# Export as tarball
./melange2 build pkg.yaml \
  --export-on-failure=tarball \
  --export-ref=/tmp/debug.tar

# Export to registry
./melange2 build pkg.yaml \
  --export-on-failure=registry \
  --export-ref=myregistry/debug:mybuild
```

### Check BuildKit Status

```bash
# List workers
docker exec buildkitd buildctl debug workers

# Check disk usage
docker exec buildkitd buildctl du

# Prune cache
docker exec buildkitd buildctl prune --all
```

### GKE Deployment Status

```bash
# Check pod status
kubectl get pods -n melange

# Check backend health
make gke-status

# View server logs
kubectl logs -n melange deployment/melange-server

# View BuildKit logs
kubectl logs -n melange deployment/buildkit
```

## Common Error Reference

| Error | Cause | Solution |
|-------|-------|----------|
| `connection refused` | BuildKit not running | Start BuildKit |
| `connection reset by peer` | Wrong BuildKit args | Restart with `--addr tcp://0.0.0.0:1234` |
| `buildkit has no workers` | BuildKit init failed | Restart with `--privileged` |
| `permission denied` in cache | Cache ownership mismatch | Clear BuildKit cache |
| `toomanyrequests` | Docker Hub rate limit | Use cgr.dev images |
| `exit code: 1` | Pipeline step failed | Use `--debug` flag |
| `test skipped in short mode` | `-short` flag used | Remove `-short` flag |

## Getting Help

If you encounter issues not covered here:

1. Check the debug output with `--debug` flag
2. Export the failed build environment for inspection
3. Review BuildKit logs: `docker logs buildkitd`
4. Open an issue with:
   - Full error message
   - Build configuration (sanitized)
   - BuildKit version: `docker exec buildkitd buildctl --version`
   - melange2 version
