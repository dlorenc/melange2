# Build System Pipelines

These pipelines provide support for common C/C++ build systems: autoconf/automake, CMake, and Meson.

## Autoconf Pipelines

### autoconf/configure

Run autoconf configure scripts to prepare the build.

#### Required Packages

- `autoconf`
- `automake`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `dir` | No | `.` | Directory containing the configure script |
| `host` | No | `${{host.triplet.gnu}}` | GNU triplet describing the host system |
| `build` | No | `${{host.triplet.gnu}}` | GNU triplet describing the build system |
| `opts` | No | `''` | Additional options to pass to ./configure |

#### Default Configure Flags

The pipeline automatically sets these standard paths:

- `--prefix=/usr`
- `--sysconfdir=/etc`
- `--libdir=/usr/lib`
- `--mandir=/usr/share/man`
- `--infodir=/usr/share/info`
- `--localstatedir=/var`

#### Auto-Generation

If `./configure` does not exist but `./configure.ac` is present, the pipeline automatically runs `autoreconf -vfi` to generate the configure script.

#### Example Usage

Basic configure:

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/source.tar.gz
      expected-sha256: abc123...

  - uses: autoconf/configure
```

With custom options:

```yaml
pipeline:
  - uses: autoconf/configure
    with:
      opts: --enable-shared --disable-static --with-ssl
```

Configure in subdirectory:

```yaml
pipeline:
  - uses: autoconf/configure
    with:
      dir: src/
      opts: --enable-feature
```

---

### autoconf/make

Run make to build the project.

#### Required Packages

- `make`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `dir` | No | `.` | Directory containing the Makefile |
| `opts` | No | `''` | Additional options to pass to make |

#### Build Behavior

- Uses parallel builds with `-j$(nproc)`
- Enables verbose output with `V=1`

#### Example Usage

Basic build:

```yaml
pipeline:
  - uses: autoconf/configure
  - uses: autoconf/make
```

With custom options:

```yaml
pipeline:
  - uses: autoconf/make
    with:
      opts: CFLAGS="-O3" all docs
```

Build in subdirectory:

```yaml
pipeline:
  - uses: autoconf/make
    with:
      dir: build/
```

---

### autoconf/make-install

Run make install to install built files.

#### Required Packages

- `make`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `dir` | No | `.` | Directory containing the Makefile |
| `opts` | No | `''` | Additional options to pass to make |

#### Install Behavior

- Sets `DESTDIR` to `${{targets.contextdir}}` for proper staging
- Enables verbose output with `V=1`
- Automatically removes all `*.la` (libtool archive) files after installation

#### Example Usage

Basic install:

```yaml
pipeline:
  - uses: autoconf/configure
  - uses: autoconf/make
  - uses: autoconf/make-install
```

With custom options:

```yaml
pipeline:
  - uses: autoconf/make-install
    with:
      opts: install-strip
```

---

## CMake Pipelines

### cmake/configure

Configure a CMake project.

#### Required Packages

- `cmake`
- `ninja`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `output-dir` | No | `output` | Output directory for the CMake build |
| `opts` | No | - | Additional compile options for CMake |

#### Default CMake Settings

- Generator: Ninja (`-G Ninja`)
- Install prefix: `/usr`
- Library directory: `lib`
- Build type: `Release`
- Verbose makefile: enabled

#### Example Usage

Basic configure:

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/source.tar.gz
      expected-sha256: abc123...

  - uses: cmake/configure
```

With custom options:

```yaml
pipeline:
  - uses: cmake/configure
    with:
      opts: |
        -DBUILD_SHARED_LIBS=ON
        -DENABLE_TESTS=OFF
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON
```

Custom output directory:

```yaml
pipeline:
  - uses: cmake/configure
    with:
      output-dir: build
      opts: -DBUILD_EXAMPLES=OFF
```

---

### cmake/build

Build a CMake project.

#### Required Packages

- `cmake`
- `ninja`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `output-dir` | No | `output` | Output directory for the CMake build |
| `opts` | No | - | Additional compile options |

#### Build Behavior

- Sets `VERBOSE=1` for detailed build output

#### Example Usage

Basic build:

```yaml
pipeline:
  - uses: cmake/configure
  - uses: cmake/build
```

With custom options:

```yaml
pipeline:
  - uses: cmake/build
    with:
      opts: --target mylib
```

---

### cmake/install

Install a CMake project.

#### Required Packages

- `cmake`
- `ninja`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `output-dir` | No | `output` | Output directory for the CMake build |

#### Install Behavior

- Sets `DESTDIR` to `${{targets.contextdir}}` for proper staging

#### Example Usage

Complete CMake workflow:

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/cmake-project.tar.gz
      expected-sha256: abc123...

  - uses: cmake/configure
    with:
      opts: -DBUILD_SHARED_LIBS=ON

  - uses: cmake/build

  - uses: cmake/install
```

---

## Meson Pipelines

### meson/configure

Configure a project with Meson.

#### Required Packages

- `meson`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `output-dir` | No | `output` | Output directory for the Meson build |
| `opts` | No | - | Additional compile options |

#### Default Meson Settings

- Install prefix: `/usr`
- Wrap mode: `nodownload` (prevents downloading subprojects)

#### Example Usage

Basic configure:

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/source.tar.gz
      expected-sha256: abc123...

  - uses: meson/configure
```

With custom options:

```yaml
pipeline:
  - uses: meson/configure
    with:
      opts: |
        -Ddefault_library=shared
        -Dtests=false
        -Ddocs=false
```

---

### meson/compile

Build a project with Meson.

#### Required Packages

- `meson`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `output-dir` | No | `output` | Output directory for the Meson build |

#### Build Behavior

- Uses parallel builds with `-j $(nproc)`

#### Example Usage

```yaml
pipeline:
  - uses: meson/configure
  - uses: meson/compile
```

---

### meson/install

Install a project built with Meson.

#### Required Packages

- `meson`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `output-dir` | No | `output` | Output directory for the Meson build |

#### Install Behavior

- Sets `DESTDIR` to `${{targets.contextdir}}` for proper staging

#### Example Usage

Complete Meson workflow:

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/meson-project.tar.gz
      expected-sha256: abc123...

  - uses: meson/configure
    with:
      opts: -Ddefault_library=shared

  - uses: meson/compile

  - uses: meson/install
```

---

## Complete Build Examples

### Autoconf Project

```yaml
package:
  name: mylib
  version: 1.0.0

pipeline:
  - uses: fetch
    with:
      uri: https://example.com/mylib-${{package.version}}.tar.gz
      expected-sha256: abc123...

  - uses: autoconf/configure
    with:
      opts: --enable-shared --disable-static

  - uses: autoconf/make

  - uses: autoconf/make-install

  - uses: strip
```

### CMake Project

```yaml
package:
  name: myapp
  version: 2.0.0

pipeline:
  - uses: fetch
    with:
      uri: https://github.com/example/myapp/archive/v${{package.version}}.tar.gz
      expected-sha256: def456...

  - uses: cmake/configure
    with:
      opts: |
        -DBUILD_SHARED_LIBS=ON
        -DCMAKE_BUILD_TYPE=Release

  - uses: cmake/build

  - uses: cmake/install

  - uses: strip
```

### Meson Project

```yaml
package:
  name: mytool
  version: 3.0.0

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/mytool.git
      tag: v${{package.version}}
      expected-commit: abc123...

  - uses: meson/configure
    with:
      opts: |
        -Ddefault_library=shared
        -Dtests=false

  - uses: meson/compile

  - uses: meson/install

  - uses: strip
```
