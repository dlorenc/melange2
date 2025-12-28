# Cargo Pipelines

melange provides a built-in pipeline for building Rust packages with Cargo.

## cargo/build

Build a Rust package with `cargo auditable build`:

```yaml
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/org/rust-app
      tag: v${{package.version}}
      expected-commit: abc123...

  - uses: cargo/build
    with:
      output: myapp
```

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `output` | Yes | - | Output binary name |
| `modroot` | No | `.` | Directory containing Cargo.toml |
| `opts` | No | `release` | Build options |
| `prefix` | No | `usr` | Install prefix |
| `install-dir` | No | `bin` | Directory under prefix for binaries |

## Complete Example

```yaml
package:
  name: eza
  version: 0.18.6
  epoch: 0
  description: "A modern replacement for ls"
  copyright:
    - license: MIT

environment:
  contents:
    repositories:
      - https://packages.wolfi.dev/os
    keyring:
      - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
    packages:
      - build-base
      - rust
      - cargo-auditable
      - libgit2-dev
      - zlib-dev

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/eza-community/eza
      tag: v${{package.version}}
      expected-commit: abc123...

  - uses: cargo/build
    with:
      output: eza

test:
  pipeline:
    - runs: |
        eza --version
        eza --help
```

## Cache Mounts

BuildKit automatically caches:

- `/root/.cargo/registry` - Crate registry cache
- `/root/.cargo/git` - Git dependency cache

These persist between builds for faster compilation.

## Features and Dependencies

### With System Dependencies

```yaml
environment:
  contents:
    packages:
      - build-base
      - rust
      - cargo-auditable
      - openssl-dev    # For crates needing OpenSSL
      - pkgconf        # For pkg-config
```

### Custom Build Options

```yaml
pipeline:
  - uses: cargo/build
    with:
      output: myapp
      opts: --release --features "feature1,feature2"
```

## Common Patterns

### Multiple Binaries

```yaml
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/org/multi-bin
      tag: v${{package.version}}

  - name: Build first binary
    runs: |
      cargo auditable build --release --bin app1
      install -Dm755 target/release/app1 ${{targets.destdir}}/usr/bin/app1

  - name: Build second binary
    runs: |
      cargo auditable build --release --bin app2
      install -Dm755 target/release/app2 ${{targets.destdir}}/usr/bin/app2
```

### With Vendored Dependencies

Some Rust projects vendor their dependencies:

```yaml
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/org/vendored-rust
      tag: v${{package.version}}

  - runs: |
      mkdir -p .cargo
      cat > .cargo/config.toml << 'EOF'
      [source.crates-io]
      replace-with = "vendored-sources"

      [source.vendored-sources]
      directory = "vendor"
      EOF

  - uses: cargo/build
    with:
      output: myapp
```

### Cross-Compilation

```yaml
environment:
  contents:
    packages:
      - rust
      - cargo-auditable
  environment:
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER: x86_64-linux-gnu-gcc

pipeline:
  - uses: cargo/build
    with:
      output: myapp
      opts: --release --target x86_64-unknown-linux-gnu
```
