# Installation

melange2 requires Go 1.24 or later.

## Install from Source

```shell
go install github.com/dlorenc/melange2@latest
```

The binary will be installed to `$GOPATH/bin/melange2` (typically `~/go/bin/melange2`).

## Build from Source

Clone the repository and build:

```shell
git clone https://github.com/dlorenc/melange2.git
cd melange2
go build -o melange2 .
```

This creates the `melange2` binary in the current directory.

## Verify Installation

Check that melange2 is installed correctly:

```shell
melange2 --help
```

You should see the available commands:

```
Build apk packages using declarative pipelines

Usage:
  melange2 [command]

Available Commands:
  build       Build a package from a YAML configuration file
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  remote      Submit builds to a remote melange-server
  test        Test a package from a YAML configuration file
  ...
```

## Build the Server (Optional)

If you plan to use the remote build server:

```shell
go build -o melange-server ./cmd/melange-server/
```

## Next Steps

After installation, you need to set up BuildKit:

- [BuildKit Setup](buildkit-setup.md) - Configure the BuildKit daemon
