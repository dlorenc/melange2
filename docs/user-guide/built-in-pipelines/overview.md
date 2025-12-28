# Built-in Pipelines

melange provides built-in pipelines for common build patterns. These encapsulate best practices and reduce boilerplate in your build files.

## Using Pipelines

Pipelines are invoked with `uses`:

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/source.tar.gz
      expected-sha256: abc123...
```

The `with` section provides inputs to the pipeline.

## Core Pipelines

### fetch

Download and extract source archives:

```yaml
- uses: fetch
  with:
    uri: https://example.com/source-${{package.version}}.tar.gz
    expected-sha256: abc123...
    strip-components: 1  # Default
```

| Input | Required | Description |
|-------|----------|-------------|
| `uri` | Yes | URL to download |
| `expected-sha256` | No | SHA256 checksum |
| `expected-sha512` | No | SHA512 checksum |
| `extract` | No | Extract archive (default: true) |
| `strip-components` | No | Path components to strip (default: 1) |
| `delete` | No | Delete archive after extraction |

### git-checkout

Clone a git repository:

```yaml
- uses: git-checkout
  with:
    repository: https://github.com/org/repo
    tag: v${{package.version}}
    expected-commit: abc123...
```

| Input | Required | Description |
|-------|----------|-------------|
| `repository` | Yes | Repository URL |
| `tag` | No | Tag to checkout |
| `branch` | No | Branch to checkout |
| `expected-commit` | No | Expected commit hash |
| `depth` | No | Clone depth |
| `destination` | No | Checkout directory (default: `.`) |

### patch

Apply patches:

```yaml
- uses: patch
  with:
    patches: fix-build.patch security-fix.patch
```

| Input | Required | Description |
|-------|----------|-------------|
| `patches` | No | Space-separated list of patches |
| `series` | No | Quilt-style series file |
| `strip-components` | No | Path components to strip (default: 1) |

### strip

Strip debug symbols from binaries:

```yaml
- uses: strip
```

## Language Pipelines

### [Go Pipelines](go/build.md)

- `go/build` - Compile Go packages
- `go/install` - Install Go packages
- `go/bump` - Update Go dependencies

### [Python Pipelines](python/build.md)

- `python/build` - Build Python wheels
- `python/install` - Install Python packages
- `python/import` - Test Python imports

### [Cargo Pipelines](cargo/build.md)

- `cargo/build` - Build Rust packages

### [Autoconf Pipelines](autoconf/configure.md)

- `autoconf/configure` - Run configure scripts
- `autoconf/make` - Run make
- `autoconf/make-install` - Run make install

### Other Languages

- `cmake/configure`, `cmake/build`, `cmake/install`
- `meson/configure`, `meson/compile`, `meson/install`
- `maven/build`
- `npm/install`
- `perl/build`, `perl/install`
- `ruby/build`, `ruby/install`
- `R/install`

## Utility Pipelines

### split/dev

Move development files to a `-dev` subpackage:

```yaml
subpackages:
  - name: ${{package.name}}-dev
    pipeline:
      - uses: split/dev
```

### split/manpages

Move man pages to a separate subpackage:

```yaml
subpackages:
  - name: ${{package.name}}-doc
    pipeline:
      - uses: split/manpages
```

## Custom Pipelines

Create custom pipelines with `--pipeline-dir`:

```bash
melange2 build package.yaml --pipeline-dir=/path/to/pipelines
```

Pipeline file (`my-pipeline.yaml`):

```yaml
name: My custom pipeline
inputs:
  param:
    description: A parameter
    default: default-value
needs:
  packages:
    - required-package
pipeline:
  - runs: |
      echo "Using ${{inputs.param}}"
```

Use in build file:

```yaml
pipeline:
  - uses: my-pipeline
    with:
      param: custom-value
```
