# Autoconf Pipelines

melange provides built-in pipelines for building projects using autoconf/automake.

## autoconf/configure

Run the configure script:

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/project-${{package.version}}.tar.gz
      expected-sha256: abc123...

  - uses: autoconf/configure
    with:
      opts: --disable-static --enable-shared
```

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `dir` | No | `.` | Directory containing configure script |
| `opts` | No | - | Options to pass to configure |
| `build` | No | `${{host.triplet.gnu}}` | Build system triplet |
| `host` | No | `${{host.triplet.gnu}}` | Host system triplet |

## autoconf/make

Run make:

```yaml
pipeline:
  - uses: autoconf/configure
  - uses: autoconf/make
```

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `dir` | No | `.` | Directory containing Makefile |
| `opts` | No | - | Options to pass to make |

## autoconf/make-install

Run make install:

```yaml
pipeline:
  - uses: autoconf/configure
  - uses: autoconf/make
  - uses: autoconf/make-install
```

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `dir` | No | `.` | Directory containing Makefile |
| `opts` | No | - | Options to pass to make install |

## Complete Example

```yaml
package:
  name: zlib
  version: 1.3.1
  epoch: 0
  description: "Compression library"
  copyright:
    - license: Zlib

environment:
  contents:
    repositories:
      - https://packages.wolfi.dev/os
    keyring:
      - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
    packages:
      - build-base
      - busybox

pipeline:
  - uses: fetch
    with:
      uri: https://zlib.net/zlib-${{package.version}}.tar.gz
      expected-sha256: 9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23

  - uses: autoconf/configure
    with:
      opts: --prefix=/usr

  - uses: autoconf/make

  - uses: autoconf/make-install

  - uses: strip

subpackages:
  - name: zlib-dev
    description: "zlib development files"
    pipeline:
      - uses: split/dev

  - name: zlib-doc
    description: "zlib documentation"
    pipeline:
      - uses: split/manpages

test:
  pipeline:
    - runs: |
        test -f /usr/lib/libz.so
```

## Common Patterns

### With Custom Configure Options

```yaml
pipeline:
  - uses: autoconf/configure
    with:
      opts: |
        --prefix=/usr
        --sysconfdir=/etc
        --localstatedir=/var
        --disable-static
        --enable-shared
        --with-feature=value
```

### Parallel Make

```yaml
pipeline:
  - uses: autoconf/configure
  - uses: autoconf/make
    with:
      opts: -j$(nproc)
```

### Out-of-Tree Build

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/project-${{package.version}}.tar.gz

  - runs: mkdir build

  - uses: autoconf/configure
    with:
      dir: build
      opts: --prefix=/usr

  - uses: autoconf/make
    with:
      dir: build

  - uses: autoconf/make-install
    with:
      dir: build
```

### With Patches

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/project-${{package.version}}.tar.gz

  - uses: patch
    with:
      patches: fix-build.patch security.patch

  - uses: autoconf/configure
  - uses: autoconf/make
  - uses: autoconf/make-install
```

## Related Pipelines

For CMake-based projects, see:
- `cmake/configure`
- `cmake/build`
- `cmake/install`

For Meson-based projects, see:
- `meson/configure`
- `meson/compile`
- `meson/install`
