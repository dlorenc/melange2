#!/bin/bash
# run-comparison.sh - Compare old (runner-based) vs new (BuildKit-based) melange builds
#
# This script:
# 1. Builds the old melange from a pre-BuildKit commit
# 2. Builds the new melange from HEAD
# 3. Clones wolfi-dev/os if needed
# 4. Runs the comparison test
#
# Prerequisites:
# - BuildKit daemon running (e.g., docker run -d --name buildkitd -p 8372:8372 moby/buildkit:latest buildkitd --addr tcp://0.0.0.0:8372)
# - Docker running (for old melange runner)
# - Go installed

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORK_DIR="${WORK_DIR:-/tmp/melange-compare}"
BUILDKIT_ADDR="${BUILDKIT_ADDR:-tcp://localhost:8372}"

# The last commit before BuildKit became the default
OLD_COMMIT="${OLD_COMMIT:-8e45d020}"  # cli: add --buildkit-addr flag (before runner removal)

echo "=== Melange Build Comparison ==="
echo "Work directory: $WORK_DIR"
echo "BuildKit address: $BUILDKIT_ADDR"
echo "Old commit: $OLD_COMMIT"
echo ""

# Create work directory
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

# Build old melange
echo "=== Building old melange from $OLD_COMMIT ==="
if [ ! -f "$WORK_DIR/melange-old" ]; then
    OLD_BUILD_DIR="$WORK_DIR/old-build"
    rm -rf "$OLD_BUILD_DIR"
    git clone "$REPO_ROOT" "$OLD_BUILD_DIR"
    cd "$OLD_BUILD_DIR"
    git checkout "$OLD_COMMIT"
    go build -o "$WORK_DIR/melange-old" .
    cd "$WORK_DIR"
    rm -rf "$OLD_BUILD_DIR"
    echo "Built old melange: $WORK_DIR/melange-old"
else
    echo "Using existing old melange: $WORK_DIR/melange-old"
fi

# Build new melange
echo ""
echo "=== Building new melange from HEAD ==="
if [ ! -f "$WORK_DIR/melange-new" ] || [ "$FORCE_REBUILD" = "1" ]; then
    cd "$REPO_ROOT"
    go build -o "$WORK_DIR/melange-new" .
    echo "Built new melange: $WORK_DIR/melange-new"
else
    echo "Using existing new melange: $WORK_DIR/melange-new"
fi

# Clone wolfi-dev/os if needed
echo ""
echo "=== Setting up wolfi-dev/os ==="
WOLFI_DIR="$WORK_DIR/os"
if [ ! -d "$WOLFI_DIR" ]; then
    git clone --depth 1 https://github.com/wolfi-dev/os.git "$WOLFI_DIR"
    echo "Cloned wolfi-dev/os to $WOLFI_DIR"
else
    echo "Using existing wolfi-dev/os at $WOLFI_DIR"
    cd "$WOLFI_DIR"
    git pull || true
    cd "$WORK_DIR"
fi

# Check BuildKit is running
echo ""
echo "=== Checking BuildKit ==="
if ! nc -z localhost 8372 2>/dev/null; then
    echo "WARNING: BuildKit does not appear to be running on port 8372"
    echo "Start it with: docker run -d --name buildkitd -p 8372:8372 moby/buildkit:latest buildkitd --addr tcp://0.0.0.0:8372"
    exit 1
fi
echo "BuildKit is running"

# Run comparison
echo ""
echo "=== Running comparison test ==="
cd "$REPO_ROOT"

# Create packages list if not exists
PACKAGES_FILE="$WORK_DIR/packages.txt"
if [ ! -f "$PACKAGES_FILE" ]; then
    cat > "$PACKAGES_FILE" << 'EOF'
# Packages to compare between old and new melange
# One package name per line (without .yaml extension)
# Lines starting with # are comments

# Simple Go packages
age
bat
buf
crane
grpcurl
ko
yq

# More complex packages
apko
cosign
helm
kubectl
melange
skopeo
terraform

# C/native packages
curl
jq
protoc

# Large packages
git
runc

# Additional packages for thorough testing
# Uncomment to test more packages:
# aws-cli
# containerd
# docker-cli
# flux
# goreleaser
EOF
    echo "Created packages list: $PACKAGES_FILE"
fi

# Run the test
go test -v ./test/compare/... \
    -wolfi-repo="$WOLFI_DIR" \
    -old-melange="$WORK_DIR/melange-old" \
    -new-melange="$WORK_DIR/melange-new" \
    -buildkit-addr="$BUILDKIT_ADDR" \
    -packages-file="$PACKAGES_FILE" \
    -keep-outputs \
    -timeout 2h \
    "$@"

echo ""
echo "=== Comparison complete ==="
echo "Output directory: $WORK_DIR"
