# Installation

## Prerequisites

- Go 1.21 or later (for building from source)
- Docker (for running BuildKit)

## Install melange2

### From Source

```bash
go install github.com/dlorenc/melange2@latest
```

### Build Locally

```bash
git clone https://github.com/dlorenc/melange2.git
cd melange2
go build -o melange2 .
```

## Verify Installation

```bash
melange2 version
```

## Next Steps

- [Set up BuildKit](buildkit-setup.md) - Configure your BuildKit daemon
- [Build your first package](first-build.md) - Step-by-step tutorial
