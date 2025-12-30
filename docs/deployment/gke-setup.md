# GKE Deployment Guide

This guide covers deploying melange-server to Google Kubernetes Engine (GKE) with Google Cloud Storage (GCS) for artifact storage.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         GKE Cluster                         │
│  ┌─────────────────────┐    ┌─────────────────────────────┐ │
│  │   melange-server    │───▶│        BuildKit             │ │
│  │   (API + Scheduler) │    │   (privileged container)    │ │
│  └──────────┬──────────┘    └─────────────────────────────┘ │
└─────────────┼───────────────────────────────────────────────┘
              │
              │ Workload Identity
              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Google Cloud Storage                      │
│  gs://PROJECT-melange-builds/                               │
│    └── builds/{job-id}/                                     │
│          ├── artifacts/                                     │
│          │     ├── {package}-{version}.apk                  │
│          │     └── APKINDEX.tar.gz                          │
│          └── logs/                                          │
│                └── build.log                                │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

- Google Cloud SDK (`gcloud`) installed and configured
- `kubectl` installed
- `ko` installed (`go install github.com/google/ko@latest`)
- Access to the `dlorenc-chainguard` GCP project (or your own project)

## Quick Start

### Automated Setup

```bash
# Run the setup script (creates everything)
./deploy/gke/setup.sh
```

### Manual Setup

1. **Set environment variables:**
   ```bash
   export PROJECT_ID=dlorenc-chainguard
   export CLUSTER_NAME=melange-server
   export REGION=us-central1
   export ZONE=us-central1-a
   export GCS_BUCKET=${PROJECT_ID}-melange-builds
   export AR_REPO=clusterlange
   export KO_DOCKER_REPO=${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}
   ```

2. **Create GCS bucket:**
   ```bash
   gcloud storage buckets create gs://${GCS_BUCKET} \
       --location=${REGION} \
       --uniform-bucket-level-access
   ```

3. **Create GKE cluster:**
   ```bash
   gcloud container clusters create ${CLUSTER_NAME} \
       --zone=${ZONE} \
       --num-nodes=2 \
       --machine-type=e2-standard-4 \
       --enable-ip-alias \
       --workload-pool=${PROJECT_ID}.svc.id.goog
   ```

4. **Set up Workload Identity:**
   ```bash
   # Create GCP service account
   gcloud iam service-accounts create melange-server \
       --display-name="Melange Server Service Account"

   # Grant GCS permissions
   gcloud storage buckets add-iam-policy-binding gs://${GCS_BUCKET} \
       --member="serviceAccount:melange-server@${PROJECT_ID}.iam.gserviceaccount.com" \
       --role="roles/storage.objectAdmin"

   # Bind Workload Identity
   gcloud iam service-accounts add-iam-policy-binding \
       melange-server@${PROJECT_ID}.iam.gserviceaccount.com \
       --role="roles/iam.workloadIdentityUser" \
       --member="serviceAccount:${PROJECT_ID}.svc.id.goog[melange/melange-server]"
   ```

5. **Deploy with ko:**
   ```bash
   kubectl apply -f deploy/gke/namespace.yaml
   kubectl apply -f deploy/gke/configmap.yaml
   kubectl apply -f deploy/gke/buildkit.yaml
   ko apply -f deploy/gke/melange-server.yaml
   ```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROJECT_ID` | `dlorenc-chainguard` | GCP project ID |
| `CLUSTER_NAME` | `melange-server` | GKE cluster name |
| `REGION` | `us-central1` | GCP region |
| `ZONE` | `us-central1-a` | GKE zone |
| `GCS_BUCKET` | `${PROJECT_ID}-melange-builds` | GCS bucket for artifacts |
| `AR_REPO` | `clusterlange` | Artifact Registry repository |
| `KO_DOCKER_REPO` | `${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}` | ko image registry |

### Server Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--listen-addr` | `:8080` | HTTP listen address |
| `--buildkit-addr` | `tcp://buildkit:1234` | BuildKit daemon address |
| `--gcs-bucket` | (none) | GCS bucket for storage (enables GCS mode) |
| `--output-dir` | `/var/lib/melange/output` | Local output directory (when not using GCS) |

## Accessing the Service

### Port Forward (Development)

```bash
kubectl port-forward -n melange svc/melange-server 8080:8080
```

### Test Health Endpoint

```bash
curl http://localhost:8080/healthz
# {"status":"ok"}
```

### Submit a Build

```bash
curl -X POST http://localhost:8080/api/v1/builds \
  -H "Content-Type: application/json" \
  -d '{
    "config_yaml": "package:\n  name: hello\n  version: 1.0.0\n  epoch: 0\n  description: Test package\n  copyright:\n    - license: Apache-2.0\n\nenvironment:\n  contents:\n    repositories:\n      - https://packages.wolfi.dev/os\n    keyring:\n      - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub\n    packages:\n      - busybox\n\npipeline:\n  - runs: |\n      mkdir -p ${{targets.destdir}}/usr/bin\n      echo hello > ${{targets.destdir}}/usr/bin/hello\n      chmod +x ${{targets.destdir}}/usr/bin/hello\n",
    "arch": "x86_64"
  }'
```

### Check Build Status

```bash
curl http://localhost:8080/api/v1/builds/{build_id}
```

### List All Builds

```bash
curl http://localhost:8080/api/v1/builds
```

## GCS Storage Layout

Build artifacts are stored in GCS with the following structure:

```
gs://${GCS_BUCKET}/
└── builds/
    └── {job-id}/
        ├── artifacts/
        │   ├── {package}-{version}-r{epoch}.apk
        │   └── APKINDEX.tar.gz
        └── logs/
            └── build.log
```

### Viewing Artifacts

```bash
# List artifacts for a job
gcloud storage ls -r gs://${GCS_BUCKET}/builds/{job-id}/

# Download an APK
gcloud storage cp gs://${GCS_BUCKET}/builds/{job-id}/artifacts/*.apk .

# View build log
gcloud storage cat gs://${GCS_BUCKET}/builds/{job-id}/logs/build.log
```

## Monitoring

### View Logs

```bash
# Server logs
kubectl logs -n melange deployment/melange-server -f

# BuildKit logs
kubectl logs -n melange deployment/buildkit -f
```

### Check Pod Status

```bash
kubectl get pods -n melange
```

### Describe Resources

```bash
kubectl describe deployment -n melange melange-server
kubectl describe deployment -n melange buildkit
```

## Teardown

```bash
# Interactive teardown
./deploy/gke/teardown.sh

# Or manually:
gcloud container clusters delete melange-server --zone=us-central1-a
gcloud storage rm -r gs://${GCS_BUCKET}
gcloud iam service-accounts delete melange-server@${PROJECT_ID}.iam.gserviceaccount.com
```

## Troubleshooting

### Pod CrashLoopBackOff

Check logs for errors:
```bash
kubectl logs -n melange deployment/melange-server --previous
```

Common issues:
- GCS bucket doesn't exist or no permissions
- BuildKit service not reachable

### Builds Failing

1. Check build error message:
   ```bash
   curl http://localhost:8080/api/v1/builds/{build-id} | jq .error
   ```

2. Check server logs:
   ```bash
   kubectl logs -n melange deployment/melange-server | grep {job-id}
   ```

3. Common issues:
   - Missing `repositories` in config YAML
   - Missing `keyring` for repository verification
   - Invalid architecture specified

### Workload Identity Issues

Verify the binding:
```bash
gcloud iam service-accounts get-iam-policy \
    melange-server@${PROJECT_ID}.iam.gserviceaccount.com
```

Check the Kubernetes service account annotation:
```bash
kubectl get serviceaccount -n melange melange-server -o yaml
```

## CI/CD

The service automatically redeploys when changes are merged to main. See `.github/workflows/deploy.yaml` for the workflow configuration.

To manually trigger a deployment:
```bash
gh workflow run deploy.yaml
```
