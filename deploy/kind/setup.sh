#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "==> Creating kind cluster..."
kind create cluster --name melange-service 2>/dev/null || echo "Cluster already exists"

echo "==> Building melange-server image..."
docker build -t melange-server:latest -f "${SCRIPT_DIR}/Dockerfile" "${REPO_ROOT}"

echo "==> Loading image into kind..."
kind load docker-image melange-server:latest --name melange-service

echo "==> Applying Kubernetes manifests..."
kubectl apply -f "${SCRIPT_DIR}/namespace.yaml"
kubectl apply -f "${SCRIPT_DIR}/buildkit.yaml"
kubectl apply -f "${SCRIPT_DIR}/melange-server.yaml"

echo "==> Waiting for deployments..."
kubectl rollout status deployment/buildkit -n melange --timeout=120s
kubectl rollout status deployment/melange-server -n melange --timeout=120s

echo ""
echo "==> Setup complete!"
echo ""
echo "To access the API locally, run:"
echo "  kubectl port-forward -n melange svc/melange-server 8080:8080"
echo ""
echo "Then test with:"
echo '  curl http://localhost:8080/healthz'
echo ""
echo "To submit a build job:"
echo '  curl -X POST http://localhost:8080/api/v1/jobs -H "Content-Type: application/json" -d @example-job.json'
