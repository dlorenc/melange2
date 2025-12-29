# Running BuildKit in GKE Sandbox (gVisor)

BuildKit can run in GKE sandbox nodes using gVisor, providing an additional layer of isolation for container builds.

## Cluster Setup

Create a GKE cluster with a gVisor-enabled node pool:

```bash
# Create cluster
gcloud container clusters create buildkit-sandbox-test \
  --zone=us-central1-a \
  --num-nodes=1 \
  --machine-type=n1-standard-2 \
  --cluster-version=1.31 \
  --project=YOUR_PROJECT

# Add sandbox node pool
gcloud container node-pools create sandbox-pool \
  --cluster=buildkit-sandbox-test \
  --zone=us-central1-a \
  --machine-type=n1-standard-4 \
  --num-nodes=1 \
  --sandbox type=gvisor
```

## BuildKit Deployment

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: buildkit-sandbox
spec:
  runtimeClassName: gvisor
  containers:
  - name: buildkit
    image: moby/buildkit:latest
    args:
    - --oci-worker-snapshotter=native
    securityContext:
      runAsUser: 0
      capabilities:
        add:
        - SYS_ADMIN
        - NET_ADMIN
        - SETUID
        - SETGID
    volumeMounts:
    - name: buildkit-data
      mountPath: /var/lib/buildkit
  volumes:
  - name: buildkit-data
    emptyDir: {}
```

**Key configuration notes:**
- `runtimeClassName: gvisor` - runs the pod in the gVisor sandbox
- `--oci-worker-snapshotter=native` - use native snapshotter (overlayfs doesn't work well in gVisor)
- Capabilities `SYS_ADMIN`, `NET_ADMIN`, `SETUID`, `SETGID` are required
- Do NOT use `privileged: true` (not supported in gVisor sandbox)
- Do NOT use `--oci-worker-no-process-sandbox` (requires rootless mode which has user namespace issues in gVisor)

## Testing

```bash
# Deploy
kubectl apply -f buildkit-sandbox.yaml

# Verify running
kubectl get pods
kubectl logs buildkit-sandbox

# Test a simple build
kubectl exec buildkit-sandbox -- sh -c 'mkdir -p /tmp/test && echo "FROM alpine:latest
RUN echo hello > /hello.txt" > /tmp/test/Dockerfile'

kubectl exec buildkit-sandbox -- buildctl build \
  --frontend dockerfile.v0 \
  --local context=/tmp/test \
  --local dockerfile=/tmp/test \
  --output type=oci,dest=/tmp/image.tar \
  --progress=plain
```

## Tests Performed

1. **Simple Dockerfile build** - Successfully built alpine-based image with RUN command
2. **OCI tarball export** - Successfully exported built image to OCI tarball format
3. **Multi-stage build** - Successfully built Go application with multi-stage Dockerfile (golang:1.21-alpine builder stage, alpine runtime stage)

## Limitations

- Cannot use `privileged: true` in gVisor sandbox
- Rootless mode (`moby/buildkit:rootless`) doesn't work due to user namespace mapping issues
- Must use `native` snapshotter instead of `overlayfs`
- BuildKit runs with its internal process sandbox (not `--oci-worker-no-process-sandbox`)

## Cleanup

```bash
gcloud container clusters delete buildkit-sandbox-test --zone=us-central1-a --quiet
```
