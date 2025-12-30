# GKE Deployment Guide

This guide covers deploying the melange-server to Google Kubernetes Engine (GKE) with GCS storage.

## Architecture

```
                    Internet
                        |
                        v
                +---------------+
                |  GKE Cluster  |
                |   (melange)   |
                +-------+-------+
                        |
        +---------------+---------------+
        |               |               |
        v               v               v
+---------------+ +-------------+ +-----------+
|melange-server | |  BuildKit   | | Registry  |
|   (ko://)     | | (Deployment)| |  (cache)  |
+-------+-------+ +------+------+ +-----+-----+
        |                |              |
        v                +--------------+
+---------------+               |
|   GCS Bucket  |<--------------+
|(artifacts/logs)|    cache-to/cache-from
+---------------+
```

## Prerequisites

- Google Cloud SDK (`gcloud`)
- Kubernetes CLI (`kubectl`)
- [ko](https://ko.build) for building images
- A GCP project with billing enabled

## Quick Start

Use the automated setup script:

```bash
# Set environment variables (optional, defaults shown)
export PROJECT_ID="your-project"
export CLUSTER_NAME="melange-server"
export REGION="us-central1"

# Run setup
./deploy/gke/setup.sh
```

This script:
1. Creates a GCS bucket for artifacts
2. Creates a GKE cluster with Workload Identity
3. Sets up IAM service accounts
4. Deploys all components

## Deployment Files

The GKE deployment consists of these manifests:

| File | Description |
|------|-------------|
| `deploy/gke/namespace.yaml` | Creates the `melange` namespace |
| `deploy/gke/buildkit.yaml` | BuildKit daemon deployment and service |
| `deploy/gke/registry.yaml` | In-cluster registry for BuildKit cache |
| `deploy/gke/configmap.yaml` | Server configuration |
| `deploy/gke/melange-server.yaml` | Server deployment, service, and service account |

## Namespace

```yaml
# deploy/gke/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: melange
```

All resources are deployed to the `melange` namespace.

## BuildKit Deployment

```yaml
# deploy/gke/buildkit.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: buildkit-config
  namespace: melange
data:
  buildkit.toml: |
    # Allow insecure access to in-cluster registry for cache
    [registry."registry:5000"]
      http = true
      insecure = true
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: buildkit
  namespace: melange
spec:
  replicas: 1
  selector:
    matchLabels:
      app: buildkit
  template:
    metadata:
      labels:
        app: buildkit
    spec:
      containers:
      - name: buildkit
        image: moby/buildkit:latest
        args:
        - --addr
        - tcp://0.0.0.0:1234
        - --config
        - /etc/buildkit/buildkit.toml
        ports:
        - containerPort: 1234
          name: buildkit
        securityContext:
          privileged: true
        volumeMounts:
        - name: buildkit-data
          mountPath: /var/lib/buildkit
        - name: buildkit-config
          mountPath: /etc/buildkit
          readOnly: true
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "8Gi"
            cpu: "4000m"
      volumes:
      - name: buildkit-data
        emptyDir: {}
      - name: buildkit-config
        configMap:
          name: buildkit-config
---
apiVersion: v1
kind: Service
metadata:
  name: buildkit
  namespace: melange
spec:
  selector:
    app: buildkit
  ports:
  - port: 1234
    targetPort: 1234
    name: buildkit
```

Key points:
- BuildKit runs in privileged mode (required for container builds)
- Configured to allow insecure access to in-cluster cache registry
- Uses `emptyDir` for build cache (ephemeral but fast)

## In-Cluster Registry

```yaml
# deploy/gke/registry.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: registry
  namespace: melange
spec:
  replicas: 1
  selector:
    matchLabels:
      app: registry
  template:
    metadata:
      labels:
        app: registry
    spec:
      containers:
      - name: registry
        image: registry:2
        ports:
        - containerPort: 5000
          name: registry
        volumeMounts:
        - name: registry-data
          mountPath: /var/lib/registry
        env:
        - name: REGISTRY_STORAGE_DELETE_ENABLED
          value: "true"
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /v2/
            port: 5000
          initialDelaySeconds: 5
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /v2/
            port: 5000
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      - name: registry-data
        emptyDir:
          sizeLimit: 50Gi
---
apiVersion: v1
kind: Service
metadata:
  name: registry
  namespace: melange
spec:
  selector:
    app: registry
  ports:
  - port: 5000
    targetPort: 5000
    name: registry
```

The registry:
- Provides BuildKit cache-to/cache-from storage
- Uses `emptyDir` (cache is ephemeral but rebuilds quickly)
- Sized at 50Gi limit

## Configuration

```yaml
# deploy/gke/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: melange-config
  namespace: melange
data:
  # GCS bucket for build artifacts and logs
  gcs-bucket: "melange-builds"

  # Registry cache configuration
  cache-registry: "registry:5000/melange-cache"
  cache-mode: "max"

  # BuildKit backends configuration
  backends.yaml: |
    backends:
      - addr: tcp://buildkit:1234
        arch: x86_64
        maxJobs: 4
        labels:
          tier: standard
    defaultMaxJobs: 4
    failureThreshold: 3
    recoveryTimeout: 30s
```

Configuration values:

| Key | Description |
|-----|-------------|
| `gcs-bucket` | GCS bucket name for artifacts |
| `cache-registry` | BuildKit cache registry URL |
| `cache-mode` | Cache export mode (`min` or `max`) |
| `backends.yaml` | Backend pool configuration |

## Server Deployment

```yaml
# deploy/gke/melange-server.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: melange-server
  namespace: melange
spec:
  replicas: 1
  selector:
    matchLabels:
      app: melange-server
  template:
    metadata:
      labels:
        app: melange-server
    spec:
      serviceAccountName: melange-server
      containers:
      - name: melange-server
        image: ko://github.com/dlorenc/melange2/cmd/melange-server
        args:
        - --listen-addr=:8080
        - --backends-config=/etc/melange/backends.yaml
        - --gcs-bucket=$(GCS_BUCKET)
        env:
        - name: GCS_BUCKET
          valueFrom:
            configMapKeyRef:
              name: melange-config
              key: gcs-bucket
        - name: CACHE_REGISTRY
          valueFrom:
            configMapKeyRef:
              name: melange-config
              key: cache-registry
        - name: CACHE_MODE
          valueFrom:
            configMapKeyRef:
              name: melange-config
              key: cache-mode
        ports:
        - containerPort: 8080
          name: http
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: backends-config
          mountPath: /etc/melange
          readOnly: true
      volumes:
      - name: backends-config
        configMap:
          name: melange-config
          items:
          - key: backends.yaml
            path: backends.yaml
---
apiVersion: v1
kind: Service
metadata:
  name: melange-server
  namespace: melange
spec:
  selector:
    app: melange-server
  ports:
  - port: 8080
    targetPort: 8080
    name: http
  type: ClusterIP
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: melange-server
  namespace: melange
  annotations:
    iam.gke.io/gcp-service-account: ""
```

Key points:
- Uses `ko://` image reference (built by ko apply)
- Mounts backends config from ConfigMap
- Uses Workload Identity for GCS access
- ClusterIP service (use port-forward for access)

## Manual Deployment Steps

### 1. Configure Environment

```bash
export PROJECT_ID="your-project"
export GCS_BUCKET="${PROJECT_ID}-melange-builds"
export KO_DOCKER_REPO="us-central1-docker.pkg.dev/${PROJECT_ID}/melange"
export CLUSTER_NAME="melange-server"
export ZONE="us-central1-a"
```

### 2. Create GCS Bucket

```bash
gcloud storage buckets create "gs://${GCS_BUCKET}" \
  --location=us-central1 \
  --uniform-bucket-level-access
```

### 3. Create GKE Cluster

```bash
gcloud container clusters create "${CLUSTER_NAME}" \
  --zone="${ZONE}" \
  --num-nodes=2 \
  --machine-type=e2-standard-4 \
  --enable-ip-alias \
  --workload-pool="${PROJECT_ID}.svc.id.goog"

gcloud container clusters get-credentials "${CLUSTER_NAME}" --zone="${ZONE}"
```

### 4. Set Up Workload Identity

```bash
# Create GCP service account
gcloud iam service-accounts create melange-server \
  --display-name="Melange Server Service Account"

# Grant GCS permissions
gcloud storage buckets add-iam-policy-binding "gs://${GCS_BUCKET}" \
  --member="serviceAccount:melange-server@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/storage.objectAdmin"

# Bind to Kubernetes service account
gcloud iam service-accounts add-iam-policy-binding \
  "melange-server@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/iam.workloadIdentityUser" \
  --member="serviceAccount:${PROJECT_ID}.svc.id.goog[melange/melange-server]"
```

### 5. Create Artifact Registry

```bash
gcloud artifacts repositories create melange \
  --repository-format=docker \
  --location=us-central1
```

### 6. Deploy with ko

```bash
# Apply namespace
kubectl apply -f deploy/gke/namespace.yaml

# Create configmap with actual bucket name
kubectl create configmap melange-config \
  --namespace=melange \
  --from-literal=gcs-bucket="${GCS_BUCKET}" \
  --from-literal=cache-registry="registry:5000/melange-cache" \
  --from-literal=cache-mode="max" \
  --from-file=backends.yaml=deploy/gke/backends.yaml \
  --dry-run=client -o yaml | kubectl apply -f -

# Deploy components
kubectl apply -f deploy/gke/registry.yaml
kubectl apply -f deploy/gke/buildkit.yaml

# Update service account annotation and deploy server
cat deploy/gke/melange-server.yaml | \
  sed "s|iam.gke.io/gcp-service-account: \"\"|iam.gke.io/gcp-service-account: melange-server@${PROJECT_ID}.iam.gserviceaccount.com|" | \
  ko apply -f -
```

### 7. Verify Deployment

```bash
# Check pods
kubectl get pods -n melange

# Check logs
kubectl logs -n melange deployment/melange-server
kubectl logs -n melange deployment/buildkit

# Port forward
kubectl port-forward -n melange svc/melange-server 8080:8080

# Test health
curl http://localhost:8080/healthz
```

## Makefile Targets

The project includes Makefile targets for common operations:

| Target | Description |
|--------|-------------|
| `make gke-setup` | Full cluster and deployment setup |
| `make gke-credentials` | Get cluster credentials |
| `make gke-deploy` | Deploy/update using ko |
| `make gke-port-forward` | Start port forwarding (background) |
| `make gke-stop-port-forward` | Stop port forwarding |
| `make gke-status` | Check pod and backend status |

Example workflow:

```bash
# Initial setup
make gke-setup

# Start port forwarding
make gke-port-forward

# Submit builds
./melange2 remote submit mypackage.yaml --server http://localhost:8080 --wait

# When done
make gke-stop-port-forward
```

## CI/CD Integration

### GitHub Actions Deployment

```yaml
# .github/workflows/deploy.yaml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v4

      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{ secrets.WIF_PROVIDER }}
          service_account: ${{ secrets.WIF_SERVICE_ACCOUNT }}

      - uses: google-github-actions/setup-gcloud@v2

      - uses: google-github-actions/get-gke-credentials@v2
        with:
          cluster_name: melange-server
          location: us-central1-a

      - uses: ko-build/setup-ko@v0.6

      - name: Deploy
        env:
          KO_DOCKER_REPO: us-central1-docker.pkg.dev/${{ secrets.PROJECT_ID }}/melange
        run: ko apply -f deploy/gke/
```

## Scaling

### Horizontal Scaling

**BuildKit**: Add more replicas or backends:

```yaml
# Option 1: Multiple BuildKit deployments
backends:
  - addr: tcp://buildkit-0.buildkit.melange.svc:1234
    arch: x86_64
    maxJobs: 4
  - addr: tcp://buildkit-1.buildkit.melange.svc:1234
    arch: x86_64
    maxJobs: 4
```

**Server**: The server is stateless and can be scaled:

```bash
kubectl scale deployment/melange-server -n melange --replicas=3
```

### Resource Tuning

For larger builds, increase BuildKit resources:

```yaml
resources:
  requests:
    memory: "4Gi"
    cpu: "2000m"
  limits:
    memory: "16Gi"
    cpu: "8000m"
```

## Monitoring

### Check Pod Status

```bash
kubectl get pods -n melange
kubectl describe pod -n melange -l app=melange-server
```

### View Logs

```bash
# Server logs
kubectl logs -n melange deployment/melange-server -f

# BuildKit logs
kubectl logs -n melange deployment/buildkit -f
```

### Check Backend Status

```bash
kubectl port-forward -n melange svc/melange-server 8080:8080 &
curl http://localhost:8080/api/v1/backends/status | jq
```

## Troubleshooting

### Pods Not Starting

```bash
kubectl describe pod -n melange -l app=buildkit
```

Common issues:
- Insufficient resources
- Image pull failures
- Privileged security context denied

### GCS Permission Denied

```
error: creating GCS storage: googleapi: Error 403
```

Check Workload Identity:
```bash
# Verify annotation
kubectl get serviceaccount melange-server -n melange -o yaml

# Check IAM binding
gcloud iam service-accounts get-iam-policy \
  melange-server@${PROJECT_ID}.iam.gserviceaccount.com
```

### BuildKit Connection Failed

```
error: connection reset by peer
```

Check BuildKit status:
```bash
kubectl logs -n melange deployment/buildkit
kubectl exec -n melange deployment/buildkit -- buildctl debug workers
```

### Cache Registry Not Working

Check registry is accessible from BuildKit:
```bash
kubectl exec -n melange deployment/buildkit -- \
  wget -q -O - http://registry:5000/v2/
```

## Cleanup

Remove all resources:

```bash
# Delete Kubernetes resources
kubectl delete namespace melange

# Delete GKE cluster
gcloud container clusters delete melange-server --zone=us-central1-a

# Delete GCS bucket (warning: deletes all artifacts)
gcloud storage rm -r "gs://${GCS_BUCKET}"

# Delete service account
gcloud iam service-accounts delete \
  melange-server@${PROJECT_ID}.iam.gserviceaccount.com
```
