# Build Options

Build options allow you to define package variants that modify variables and environment configuration at build time. This is useful for building the same package with different backends, features, or configurations.

## Basic Structure

```yaml
options:
  option-name:
    vars:
      variable-name: value
    environment:
      contents:
        packages:
          add:
            - additional-package
          remove:
            - package-to-remove
```

## Defining Options

Define options in the top-level `options` block:

```yaml
vars:
  with-openssl: --with-openssl
  with-rustls: --without-rustls

options:
  rustls:
    vars:
      with-openssl: --without-openssl
      with-rustls: --with-rustls
    environment:
      contents:
        packages:
          add:
            - rustls-ffi
          remove:
            - openssl-dev
```

## Option Fields

### vars

Override or add variables when the option is enabled:

```yaml
options:
  debug:
    vars:
      cflags: "-O0 -g"
      debug-mode: "true"
```

### environment

Modify the build environment:

```yaml
options:
  minimal:
    environment:
      contents:
        packages:
          add:
            - musl-dev
          remove:
            - glibc-dev
            - glibc
```

### Package List Operations

| Field | Description |
|-------|-------------|
| `add` | Packages to add to the environment |
| `remove` | Packages to remove from the environment |

## Using Options in Pipelines

Check if an option is enabled using conditionals:

```yaml
pipeline:
  - if: ${{options.rustls.enabled}} == 'true'
    runs: |
      echo "Building with RUSTLS backend"

  - if: ${{options.rustls.enabled}} == 'false'
    runs: |
      echo "Building with OpenSSL backend"
```

## Using Options in Subpackages

Create conditional subpackages based on options:

```yaml
subpackages:
  - if: ${{options.rustls.enabled}} == 'false'
    name: libcurl-openssl4
    description: "curl library (openssl backend)"
    dependencies:
      provides:
        - libcurl4=7.87.1
      provider-priority: 5
    pipeline:
      - runs: |
          mkdir -p "${{targets.subpkgdir}}"/usr/lib
          mv "${{targets.destdir}}"/usr/lib/libcurl.so.* "${{targets.subpkgdir}}"/usr/lib/

  - if: ${{options.rustls.enabled}} == 'true'
    name: libcurl-rustls4
    description: "curl library (rustls backend)"
    dependencies:
      provides:
        - libcurl4=7.87.1
      provider-priority: 10
    pipeline:
      - runs: |
          mkdir -p "${{targets.subpkgdir}}"/usr/lib
          mv "${{targets.destdir}}"/usr/lib/libcurl.so.* "${{targets.subpkgdir}}"/usr/lib/
```

## Enabling Options at Build Time

Enable options using the `--build-option` flag:

```bash
./melange2 build curl.yaml --build-option rustls
```

Multiple options can be enabled:

```bash
./melange2 build pkg.yaml --build-option debug --build-option minimal
```

## Complete Example

```yaml
package:
  name: curl
  version: 7.87.0
  epoch: 3
  description: "URL retrieval utility and library"
  copyright:
    - license: MIT

environment:
  contents:
    repositories:
      - https://packages.wolfi.dev/os
    keyring:
      - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
    packages:
      - brotli-dev
      - build-base
      - busybox
      - ca-certificates-bundle
      - nghttp2-dev
      - openssl-dev
      - wolfi-base
      - zlib-dev

vars:
  with-openssl: --with-openssl
  with-rustls: --without-rustls

options:
  rustls:
    vars:
      with-openssl: --without-openssl
      with-rustls: --with-rustls
    environment:
      contents:
        packages:
          add:
            - rustls-ffi
          remove:
            - openssl-dev

pipeline:
  - uses: fetch
    with:
      uri: https://curl.se/download/curl-${{package.version}}.tar.xz
      expected-sha256: ee5f1a1955b0ed413435ef79db28b834ea5f0fb7c8cfb1ce47175cc3bee08fff

  - if: ${{options.rustls.enabled}} == 'true'
    runs: |
      echo "Building with RUSTLS backend"

  - uses: autoconf/configure
    with:
      opts: |
        --enable-ipv6 \
        --enable-unix-sockets \
        ${{vars.with-openssl}} \
        ${{vars.with-rustls}} \
        --with-nghttp2 \
        --with-pic \
        --disable-ldap \
        --without-libssh2

  - uses: autoconf/make

  - uses: autoconf/make-install

  - uses: strip

subpackages:
  - name: curl-dev
    description: "Headers for libcurl"
    pipeline:
      - uses: split/dev
    dependencies:
      runtime:
        - libcurl4

  - name: curl-doc
    description: "Documentation for curl"
    pipeline:
      - uses: split/manpages

  - if: ${{options.rustls.enabled}} == 'false'
    name: libcurl-openssl4
    description: "curl library (openssl backend)"
    dependencies:
      provides:
        - libcurl4=7.87.1
      provider-priority: 5
    pipeline:
      - runs: |
          mkdir -p "${{targets.subpkgdir}}"/usr/lib
          mv "${{targets.destdir}}"/usr/lib/libcurl.so.* "${{targets.subpkgdir}}"/usr/lib/

  - if: ${{options.rustls.enabled}} == 'true'
    name: libcurl-rustls4
    description: "curl library (rustls backend)"
    dependencies:
      provides:
        - libcurl4=7.87.1
      provider-priority: 10
    pipeline:
      - runs: |
          mkdir -p "${{targets.subpkgdir}}"/usr/lib
          mv "${{targets.destdir}}"/usr/lib/libcurl.so.* "${{targets.subpkgdir}}"/usr/lib/
```

## Package Options

Separate from build options, there are package-level options that modify package behavior. These are defined in the `package.options` field:

```yaml
package:
  name: mypackage
  version: 1.0.0
  epoch: 0
  options:
    no-provides: true
    no-depends: true
    no-commands: true
```

### Package Option Fields

| Field | Type | Description |
|-------|------|-------------|
| `no-provides` | bool | Mark as virtual package with no file provides |
| `no-depends` | bool | Mark as self-contained with no dependencies |
| `no-commands` | bool | Mark as not providing any executables |
| `no-versioned-shlib-deps` | bool | Skip versioned shared library dependencies |

### no-provides

Mark the package as a virtual package that does not provide any files, executables, or libraries:

```yaml
package:
  name: virtual-package
  options:
    no-provides: true
```

### no-depends

Mark the package as self-contained with no external dependencies:

```yaml
package:
  name: standalone
  options:
    no-depends: true
```

### no-commands

Mark the package as not providing any executable commands:

```yaml
package:
  name: mylib
  options:
    no-commands: true
```

### no-versioned-shlib-deps

Skip generating versioned dependencies for shared libraries:

```yaml
package:
  name: mypackage
  options:
    no-versioned-shlib-deps: true
```

## Subpackage Options

Subpackages can also have their own options:

```yaml
subpackages:
  - name: mypackage-minimal
    options:
      no-provides: true
      no-commands: true
    pipeline:
      - runs: |
          mkdir -p "${{targets.subpkgdir}}"
```

## Struct References

### BuildOption

From `pkg/config/build_option.go`:

```go
type BuildOption struct {
    Vars        map[string]string `yaml:"vars,omitempty"`
    Environment EnvironmentOption `yaml:"environment,omitempty"`
}

type EnvironmentOption struct {
    Contents ContentsOption `yaml:"contents,omitempty"`
}

type ContentsOption struct {
    Packages ListOption `yaml:"packages,omitempty"`
}

type ListOption struct {
    Add    []string `yaml:"add,omitempty"`
    Remove []string `yaml:"remove,omitempty"`
}
```

### PackageOption

From `pkg/config/config.go`:

```go
type PackageOption struct {
    NoProvides           bool `yaml:"no-provides,omitempty"`
    NoDepends            bool `yaml:"no-depends,omitempty"`
    NoCommands           bool `yaml:"no-commands,omitempty"`
    NoVersionedShlibDeps bool `yaml:"no-versioned-shlib-deps,omitempty"`
}
```
