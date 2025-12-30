# Registry Authentication

This document covers authentication configuration for private container registries and package repositories in melange2.

## Overview

melange2 may need to authenticate with registries in several scenarios:

1. **Base images** - Pulling private base images for builds
2. **Registry cache** - Pushing/pulling cache layers to/from private registries
3. **Debug image export** - Pushing debug images to a registry on build failure
4. **Package repositories** - Accessing private APK repositories

## HTTP Authentication

melange2 supports HTTP Basic authentication for package repositories via the `HTTP_AUTH` environment variable.

### Configuration

Set the `HTTP_AUTH` environment variable in the format:

```
HTTP_AUTH=basic:REALM:USERNAME:PASSWORD
```

Where:
- `basic` - Authentication type (currently only `basic` is supported)
- `REALM` - The authentication realm/domain
- `USERNAME` - Your username
- `PASSWORD` - Your password

### Example

```bash
export HTTP_AUTH="basic:packages.example.com:myuser:mypassword"
./melange2 build pkg.yaml
```

### Error Messages

If the `HTTP_AUTH` format is incorrect, you will see one of these errors:

```
HTTP_AUTH must be in the form 'basic:REALM:USERNAME:PASSWORD' (got N parts)
```

```
HTTP_AUTH must be in the form 'basic:REALM:USERNAME:PASSWORD' (got "X" for first part)
```

## Registry Authentication for BuildKit

BuildKit handles registry authentication for pulling/pushing images and cache layers. Authentication is configured through Docker's credential system.

### Docker Config

BuildKit uses the Docker configuration file at `~/.docker/config.json` for registry credentials. To authenticate with a registry:

```bash
# Log in to a registry (creates/updates ~/.docker/config.json)
docker login registry.example.com

# For Google Cloud Registry
gcloud auth configure-docker

# For Google Artifact Registry
gcloud auth configure-docker us-central1-docker.pkg.dev
```

### Credential Helpers

For production environments, use credential helpers instead of storing credentials in the config file:

```json
{
  "credHelpers": {
    "gcr.io": "gcloud",
    "us-central1-docker.pkg.dev": "gcloud",
    "registry.example.com": "secretmanager"
  }
}
```

## In-Cluster Registry (No Authentication)

The default GKE deployment includes an in-cluster registry for cache storage that does not require authentication.

### Configuration

The in-cluster registry is configured in `deploy/gke/registry.yaml`:

```yaml
# Service accessible at registry:5000 within the cluster
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
```

### BuildKit Configuration for Insecure Registry

BuildKit must be configured to allow insecure (HTTP) access to the in-cluster registry.

**buildkit.toml:**
```toml
[registry."registry:5000"]
  http = true
  insecure = true
```

This configuration is deployed via ConfigMap in `deploy/gke/buildkit.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: buildkit-config
  namespace: melange
data:
  buildkit.toml: |
    [registry."registry:5000"]
      http = true
      insecure = true
```

## Debug Image Export to Registry

When using `--export-on-failure=registry`, melange2 exports a debug image to a registry on build failure.

### Configuration

```bash
./melange2 build pkg.yaml \
  --export-on-failure=registry \
  --export-ref=registry.example.com/debug:failed-build
```

### Authentication Requirements

The registry specified in `--export-ref` must be accessible with credentials configured in Docker's config file or BuildKit's registry configuration.

For in-cluster registries without authentication:

```bash
./melange2 build pkg.yaml \
  --export-on-failure=registry \
  --export-ref=registry:5000/debug:failed-build
```

## Private APK Repositories

For builds that depend on packages from private APK repositories, configure authentication and add the repository.

### Adding Private Repositories

```bash
./melange2 build pkg.yaml \
  -r https://packages.example.com/repo \
  -k /path/to/repo.rsa.pub
```

### Keyring Configuration

Private repositories typically require their signing keys to be added to the build environment:

```bash
./melange2 build pkg.yaml \
  --keyring-append /path/to/private-repo.rsa.pub \
  --repository-append https://packages.example.com/private
```

## GKE Deployment Authentication

For GKE deployments, the melange-server uses Workload Identity or service account credentials for GCS access.

### GCS Storage Backend

The GCS storage backend uses Application Default Credentials:

```bash
# Set up application default credentials
gcloud auth application-default login

# Or use a service account
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
```

### Workload Identity (Recommended)

For GKE, use Workload Identity to grant the melange-server pod access to GCS:

```bash
# Create a GCP service account
gcloud iam service-accounts create melange-server

# Grant GCS access
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:melange-server@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/storage.objectAdmin"

# Bind to Kubernetes service account
gcloud iam service-accounts add-iam-policy-binding \
  melange-server@PROJECT_ID.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="serviceAccount:PROJECT_ID.svc.id.goog[melange/melange-server]"
```

## Security Best Practices

### 1. Never Store Credentials in Build Configs

Keep credentials in environment variables or external secret managers:

```bash
# Good: Use environment variable
export HTTP_AUTH="basic:example.com:user:${REPO_PASSWORD}"

# Bad: Hardcoded in command
./melange2 build --auth "user:password123"  # Don't do this!
```

### 2. Use Credential Helpers

Prefer credential helpers over stored credentials:

```json
{
  "credHelpers": {
    "gcr.io": "gcloud"
  }
}
```

### 3. Use Short-Lived Credentials

For CI/CD, use short-lived tokens instead of long-lived credentials:

```bash
# Google Cloud: Use access token
gcloud auth print-access-token | docker login -u oauth2accesstoken --password-stdin gcr.io
```

### 4. Restrict Registry Access

Limit registry access to only what's needed:
- Use read-only credentials for pulling base images
- Use separate credentials for cache (read/write)
- Use separate credentials for artifact publishing

### 5. Audit Registry Access

Enable audit logging for registries to track access patterns and detect unauthorized usage.
