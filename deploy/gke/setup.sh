#!/bin/bash
# Copyright 2024 Chainguard, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Configuration
PROJECT_ID="${PROJECT_ID:-dlorenc-chainguard}"
CLUSTER_NAME="${CLUSTER_NAME:-melange-server}"
REGION="${REGION:-us-central1}"
ZONE="${ZONE:-us-central1-a}"
GCS_BUCKET="${GCS_BUCKET:-${PROJECT_ID}-melange-builds}"
AR_REPO="${AR_REPO:-clusterlange}"
AR_LOCATION="${AR_LOCATION:-us-central1}"
SA_NAME="${SA_NAME:-melange-server}"

echo "==> Configuration"
echo "    Project:        ${PROJECT_ID}"
echo "    Cluster:        ${CLUSTER_NAME}"
echo "    Region:         ${REGION}"
echo "    GCS Bucket:     ${GCS_BUCKET}"
echo "    Artifact Repo:  ${AR_LOCATION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}"
echo ""

# Set project
gcloud config set project "${PROJECT_ID}"

# Create GCS bucket if it doesn't exist
echo "==> Creating GCS bucket (if not exists)..."
if ! gcloud storage buckets describe "gs://${GCS_BUCKET}" &>/dev/null; then
    gcloud storage buckets create "gs://${GCS_BUCKET}" \
        --location="${REGION}" \
        --uniform-bucket-level-access
    echo "    Created bucket: gs://${GCS_BUCKET}"
else
    echo "    Bucket already exists: gs://${GCS_BUCKET}"
fi

# Create GKE cluster if it doesn't exist
echo "==> Creating GKE cluster (if not exists)..."
if ! gcloud container clusters describe "${CLUSTER_NAME}" --zone="${ZONE}" &>/dev/null; then
    gcloud container clusters create "${CLUSTER_NAME}" \
        --zone="${ZONE}" \
        --num-nodes=2 \
        --machine-type=e2-standard-4 \
        --enable-ip-alias \
        --workload-pool="${PROJECT_ID}.svc.id.goog" \
        --no-enable-autoupgrade
    echo "    Created cluster: ${CLUSTER_NAME}"
else
    echo "    Cluster already exists: ${CLUSTER_NAME}"
fi

# Get credentials
echo "==> Getting cluster credentials..."
gcloud container clusters get-credentials "${CLUSTER_NAME}" --zone="${ZONE}"

# Create GCP service account for Workload Identity
echo "==> Setting up Workload Identity..."
GCP_SA="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

if ! gcloud iam service-accounts describe "${GCP_SA}" &>/dev/null; then
    gcloud iam service-accounts create "${SA_NAME}" \
        --display-name="Melange Server Service Account"
    echo "    Created service account: ${GCP_SA}"
else
    echo "    Service account already exists: ${GCP_SA}"
fi

# Grant GCS permissions to service account
echo "==> Granting GCS permissions..."
gcloud storage buckets add-iam-policy-binding "gs://${GCS_BUCKET}" \
    --member="serviceAccount:${GCP_SA}" \
    --role="roles/storage.objectAdmin" \
    --quiet

# Grant Artifact Registry permissions
echo "==> Granting Artifact Registry permissions..."
gcloud artifacts repositories add-iam-policy-binding "${AR_REPO}" \
    --location="${AR_LOCATION}" \
    --member="serviceAccount:${GCP_SA}" \
    --role="roles/artifactregistry.reader" \
    --quiet

# Bind Kubernetes service account to GCP service account
echo "==> Binding Workload Identity..."
gcloud iam service-accounts add-iam-policy-binding "${GCP_SA}" \
    --role="roles/iam.workloadIdentityUser" \
    --member="serviceAccount:${PROJECT_ID}.svc.id.goog[melange/melange-server]" \
    --quiet

# Apply Kubernetes manifests
echo "==> Applying Kubernetes manifests..."
kubectl apply -f "${SCRIPT_DIR}/namespace.yaml"

# Update configmap with actual bucket name
kubectl create configmap melange-config \
    --namespace=melange \
    --from-literal=gcs-bucket="${GCS_BUCKET}" \
    --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f "${SCRIPT_DIR}/buildkit.yaml"

# Update service account with Workload Identity annotation and apply
cat "${SCRIPT_DIR}/melange-server.yaml" | \
    sed "s|iam.gke.io/gcp-service-account: \"\"|iam.gke.io/gcp-service-account: ${GCP_SA}|" | \
    KO_DOCKER_REPO="${AR_LOCATION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO}" \
    ko apply -f -

echo "==> Waiting for deployments..."
kubectl rollout status deployment/buildkit -n melange --timeout=180s
kubectl rollout status deployment/melange-server -n melange --timeout=180s

echo ""
echo "==> Setup complete!"
echo ""
echo "To access the API locally, run:"
echo "  kubectl port-forward -n melange svc/melange-server 8080:8080"
echo ""
echo "Then test with:"
echo "  curl http://localhost:8080/healthz"
echo ""
echo "To submit a build:"
echo "  curl -X POST http://localhost:8080/api/v1/builds -H 'Content-Type: application/json' -d @example-job.json"
echo ""
echo "Build artifacts will be stored in: gs://${GCS_BUCKET}"
