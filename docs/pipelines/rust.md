# Rust Pipelines

These pipelines provide support for building Rust projects with Cargo.

## cargo/build

Build an auditable Rust binary using `cargo auditable`.

The pipeline uses `cargo-auditable` which embeds dependency information in the resulting binary, making it possible to audit the binary for known vulnerabilities later.

### Required Packages

- `build-base`
- `busybox`
- `cargo-auditable`
- `rust`

### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `output` | No | - | Output binary filename (if not set, installs all binaries) |
| `opts` | No | `--release` | Options to pass to cargo build |
| `modroot` | No | `.` | Directory containing Cargo.toml |
| `rustflags` | No | `""` | RUSTFLAGS to pass to all compiler invocations |
| `prefix` | No | `usr` | Installation prefix |
| `install-dir` | No | `bin` | Directory for installed binaries |
| `output-dir` | No | `target/release` | Directory containing built binaries |
| `jobs` | No | - | Number of parallel jobs (defaults to CPU count) |

### Build Behavior

- Uses `cargo auditable build` for security-auditable binaries
- Installs binaries with mode 755
- If `output` is not specified, installs all binaries from the output directory

### Example Usage

Single binary:

```yaml
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/rustapp.git
      tag: v${{package.version}}
      expected-commit: abc123...

  - uses: cargo/build
    with:
      output: myapp
```

All binaries in workspace:

```yaml
pipeline:
  - uses: cargo/build
```

With custom rustflags:

```yaml
pipeline:
  - uses: cargo/build
    with:
      output: myapp
      rustflags: "-C target-feature=+crt-static"
```

Debug build:

```yaml
pipeline:
  - uses: cargo/build
    with:
      output: myapp
      opts: ""
      output-dir: target/debug
```

Building from subdirectory:

```yaml
pipeline:
  - uses: cargo/build
    with:
      modroot: rust/myproject
      output: myapp
```

With specific features:

```yaml
pipeline:
  - uses: cargo/build
    with:
      output: myapp
      opts: --release --features "feature1,feature2" --no-default-features
```

Limited parallelism (for memory-constrained builds):

```yaml
pipeline:
  - uses: cargo/build
    with:
      output: myapp
      jobs: 4
```

---

## Complete Examples

### Basic Rust CLI Application

```yaml
package:
  name: myrust-app
  version: 1.0.0

environment:
  contents:
    packages:
      - rust
      - cargo-auditable
      - build-base

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/myrust-app.git
      tag: v${{package.version}}
      expected-commit: abc123...

  - uses: cargo/build
    with:
      output: myrust-app

  - uses: strip
```

### Rust Workspace with Multiple Binaries

```yaml
package:
  name: rust-toolkit
  version: 2.0.0

environment:
  contents:
    packages:
      - rust
      - cargo-auditable
      - build-base

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/rust-toolkit.git
      tag: v${{package.version}}
      expected-commit: def456...

  - uses: cargo/build
    with:
      output: tool-a

  - uses: cargo/build
    with:
      output: tool-b

  - uses: cargo/build
    with:
      output: tool-c

  - uses: strip

subpackages:
  - name: rust-toolkit-tool-a
    pipeline:
      - runs: |
          mkdir -p ${{targets.contextdir}}/usr/bin
          mv ${{targets.destdir}}/usr/bin/tool-a ${{targets.contextdir}}/usr/bin/

  - name: rust-toolkit-tool-b
    pipeline:
      - runs: |
          mkdir -p ${{targets.contextdir}}/usr/bin
          mv ${{targets.destdir}}/usr/bin/tool-b ${{targets.contextdir}}/usr/bin/

  - name: rust-toolkit-tool-c
    pipeline:
      - runs: |
          mkdir -p ${{targets.contextdir}}/usr/bin
          mv ${{targets.destdir}}/usr/bin/tool-c ${{targets.contextdir}}/usr/bin/
```

### Rust with System Dependencies

```yaml
package:
  name: rust-with-deps
  version: 1.5.0

environment:
  contents:
    packages:
      - rust
      - cargo-auditable
      - build-base
      - openssl-dev
      - pkgconf

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/rust-with-deps.git
      tag: v${{package.version}}
      expected-commit: ghi789...

  - uses: cargo/build
    with:
      output: myapp
      opts: --release --features "openssl-vendored"

  - uses: strip
```

### Cross-Compilation Ready Build

```yaml
package:
  name: rust-cross
  version: 3.0.0

environment:
  contents:
    packages:
      - rust
      - cargo-auditable
      - build-base

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/rust-cross.git
      tag: v${{package.version}}
      expected-commit: jkl012...

  - uses: cargo/build
    with:
      output: mycli
      rustflags: "-C link-arg=-s"
      opts: --release --locked

  - uses: strip
```

### Workspace Build with Features

```yaml
package:
  name: rust-workspace
  version: 4.0.0

environment:
  contents:
    packages:
      - rust
      - cargo-auditable
      - build-base

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/rust-workspace.git
      tag: v${{package.version}}
      expected-commit: mno345...

  # Build main binary with all features
  - uses: cargo/build
    with:
      output: main-app
      opts: --release --all-features

  # Build minimal CLI with no default features
  - uses: cargo/build
    with:
      output: minimal-cli
      opts: --release --no-default-features -p minimal-cli

  - uses: strip
```

## Tips for Rust Builds

### Managing Build Time

Rust builds can be slow. Consider:

1. **Limit parallel jobs** for memory-constrained systems:
   ```yaml
   - uses: cargo/build
     with:
       jobs: 2
   ```

2. **Use release mode** (default) for smaller, faster binaries

### Reproducible Builds

For reproducible builds, use `--locked` to ensure Cargo.lock is respected:

```yaml
- uses: cargo/build
  with:
    opts: --release --locked
```

### Static Linking

For fully static binaries (useful for containers):

```yaml
- uses: cargo/build
  with:
    output: myapp
    rustflags: "-C target-feature=+crt-static"
```

### Security Auditing

The `cargo-auditable` tool embeds dependency information in binaries. You can later audit these binaries using:

```bash
cargo audit bin /path/to/binary
```
