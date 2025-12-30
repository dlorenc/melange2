# BuildKit Setup

melange2 requires a running BuildKit daemon. BuildKit handles the actual execution of build steps.

## Connection Details

By default, melange2 connects to BuildKit at `tcp://localhost:1234`. You can override this with the `--buildkit-addr` flag:

```shell
melange2 build package.yaml --buildkit-addr tcp://buildkit.example.com:1234
```

## Option 1: Docker (Recommended)

Start BuildKit using Docker with TCP access enabled:

```shell
docker run -d \
  --name buildkitd \
  --privileged \
  -p 1234:1234 \
  moby/buildkit:latest \
  --addr tcp://0.0.0.0:1234
```

This starts BuildKit listening on port 1234.

### Managing the Container

```shell
# Check if BuildKit is running
docker ps | grep buildkitd

# View logs
docker logs buildkitd

# Stop BuildKit
docker stop buildkitd

# Restart BuildKit
docker start buildkitd

# Remove and recreate (if issues occur)
docker rm -f buildkitd
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234
```

## Option 2: Native buildkitd

If you have buildkitd installed locally:

```shell
buildkitd --addr tcp://0.0.0.0:1234
```

## Verify Connection

After starting BuildKit, verify the connection works:

```shell
# Using buildctl (if installed)
buildctl --addr tcp://localhost:1234 debug workers

# Or run a test build
melange2 build examples/minimal.yaml --buildkit-addr tcp://localhost:1234
```

## Troubleshooting

### Connection refused

BuildKit is not running or not listening on the expected port.

```shell
# Check if container is running
docker ps | grep buildkitd

# If not running, start it
docker start buildkitd
```

### Connection reset by peer

Usually indicates BuildKit was started without the `--addr` flag or with the wrong address.

```shell
# Remove and recreate with correct flags
docker rm -f buildkitd
docker run -d --name buildkitd --privileged -p 1234:1234 \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234
```

### BuildKit has no workers

BuildKit is running but not properly initialized. Restart the daemon:

```shell
docker restart buildkitd
```

### Permission denied

Ensure the BuildKit container is running with `--privileged` flag.

## Alternative Addresses

melange2 supports different BuildKit connection types:

| Address Format | Description |
|----------------|-------------|
| `tcp://localhost:1234` | TCP connection (default) |
| `unix:///run/buildkit/buildkitd.sock` | Unix socket |
| `docker-container://buildkitd` | Docker container name |

Example with Unix socket:

```shell
melange2 build package.yaml --buildkit-addr unix:///run/buildkit/buildkitd.sock
```

## Next Steps

With BuildKit running, you can build your first package:

- [First Build](first-build.md) - Build a hello world package
