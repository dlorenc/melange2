#!/bin/bash
set -euo pipefail

echo "==> Deleting kind cluster..."
kind delete cluster --name melange-service

echo "==> Cleanup complete!"
