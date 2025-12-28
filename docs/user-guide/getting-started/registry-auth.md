# Registry Authentication

When building packages that need to pull images from private registries, you must authenticate before running melange2.

## Docker Hub

For Docker Hub (or to avoid rate limits):

```bash
docker login
```

This stores credentials in `~/.docker/config.json`, which BuildKit uses automatically.

## Private Registries

For private registries like GitHub Container Registry:

```bash
# GitHub Container Registry
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin

# Google Container Registry
gcloud auth configure-docker

# AWS ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin ACCOUNT.dkr.ecr.us-east-1.amazonaws.com
```

## Verifying Authentication

After logging in, verify your credentials:

```bash
cat ~/.docker/config.json
```

You should see entries for your registries:

```json
{
  "auths": {
    "https://index.docker.io/v1/": {
      "auth": "..."
    },
    "ghcr.io": {
      "auth": "..."
    }
  }
}
```

## BuildKit and Credentials

When BuildKit runs inside Docker, it inherits credentials from the host's Docker configuration. If using a containerized BuildKit:

```bash
# Mount Docker config into BuildKit container
docker run -d --name buildkitd --privileged -p 1234:1234 \
  -v ~/.docker/config.json:/root/.docker/config.json:ro \
  moby/buildkit:latest --addr tcp://0.0.0.0:1234
```

## Troubleshooting

### "unauthorized" or "access denied" Errors

1. Verify you're logged in: `docker login`
2. Check the registry URL matches exactly
3. Ensure credentials are mounted in BuildKit container
4. For Docker Hub rate limits, authenticate even for public images
