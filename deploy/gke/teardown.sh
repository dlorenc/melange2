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

# Configuration
PROJECT_ID="${PROJECT_ID:-dlorenc-chainguard}"
CLUSTER_NAME="${CLUSTER_NAME:-melange-server}"
ZONE="${ZONE:-us-central1-a}"
GCS_BUCKET="${GCS_BUCKET:-${PROJECT_ID}-melange-builds}"
SA_NAME="${SA_NAME:-melange-server}"

echo "==> Configuration"
echo "    Project:    ${PROJECT_ID}"
echo "    Cluster:    ${CLUSTER_NAME}"
echo "    GCS Bucket: ${GCS_BUCKET}"
echo ""

# Set project
gcloud config set project "${PROJECT_ID}"

# Prompt for confirmation
read -p "Are you sure you want to delete the cluster and associated resources? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# Delete GKE cluster
echo "==> Deleting GKE cluster..."
if gcloud container clusters describe "${CLUSTER_NAME}" --zone="${ZONE}" &>/dev/null; then
    gcloud container clusters delete "${CLUSTER_NAME}" --zone="${ZONE}" --quiet
    echo "    Deleted cluster: ${CLUSTER_NAME}"
else
    echo "    Cluster not found: ${CLUSTER_NAME}"
fi

# Optionally delete service account
read -p "Delete service account ${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    GCP_SA="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
    if gcloud iam service-accounts describe "${GCP_SA}" &>/dev/null; then
        gcloud iam service-accounts delete "${GCP_SA}" --quiet
        echo "    Deleted service account: ${GCP_SA}"
    else
        echo "    Service account not found: ${GCP_SA}"
    fi
fi

# Optionally delete GCS bucket
read -p "Delete GCS bucket gs://${GCS_BUCKET}? (This will delete all build artifacts!) [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if gcloud storage buckets describe "gs://${GCS_BUCKET}" &>/dev/null; then
        gcloud storage rm -r "gs://${GCS_BUCKET}" --quiet
        echo "    Deleted bucket: gs://${GCS_BUCKET}"
    else
        echo "    Bucket not found: gs://${GCS_BUCKET}"
    fi
fi

echo ""
echo "==> Teardown complete!"
