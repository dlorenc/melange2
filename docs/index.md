# melange2 Documentation

Welcome to the melange2 documentation.

## Documentation Sections

### [User Guide](user-guide/index.md)

For users building APK packages with melange2:

- [Getting Started](user-guide/getting-started/installation.md) - Installation and first build
- [Building Packages](user-guide/building-packages/build-file-reference.md) - YAML configuration reference
- [Built-in Pipelines](user-guide/built-in-pipelines/overview.md) - Go, Python, Cargo, and more
- [Testing Packages](user-guide/testing-packages/test-command.md) - Package testing
- [Caching](user-guide/caching/buildkit-cache.md) - Build caching strategies
- [Deployment](user-guide/deployment/signing.md) - Signing and repositories
- [CLI Reference](user-guide/reference/cli.md) - Command-line options

### [Development Guide](development/index.md)

For developers contributing to melange2:

- [Setup](development/setup/development-environment.md) - Development environment
- [Architecture](development/architecture/overview.md) - System design
- [Testing](development/testing/testing-strategy.md) - Test types and strategies
- [Contributing](development/contributing/git-workflow.md) - How to contribute

### [CLI Reference](md/melange.md)

Auto-generated command-line documentation.

## Quick Links

| Task | Documentation |
|------|---------------|
| Install melange2 | [Installation](user-guide/getting-started/installation.md) |
| Set up BuildKit | [BuildKit Setup](user-guide/getting-started/buildkit-setup.md) |
| Write a build file | [Build File Reference](user-guide/building-packages/build-file-reference.md) |
| Use Go pipelines | [Go Pipelines](user-guide/built-in-pipelines/go/build.md) |
| Run tests | [Testing](user-guide/testing-packages/test-command.md) |
| Sign packages | [Signing](user-guide/deployment/signing.md) |
| Contribute | [Git Workflow](development/contributing/git-workflow.md) |
| Troubleshoot | [Troubleshooting](user-guide/reference/troubleshooting.md) |

## For AI Agents

See [CLAUDE.md](../CLAUDE.md) for an agent-optimized guide to the codebase.
