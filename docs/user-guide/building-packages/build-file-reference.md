# Build File Reference

This is the complete reference for melange YAML build files.

## High-Level Structure

```yaml
package:        # Required - Package metadata
environment:    # Required - Build environment specification
pipeline:       # Required - Build steps

subpackages:    # Optional - Additional packages to produce
vars:           # Optional - Custom variables
var-transforms: # Optional - Variable transformations
data:           # Optional - Data for templating
update:         # Optional - Auto-update configuration
options:        # Optional - Build options
```

## package

Package metadata used to identify and describe the package.

```yaml
package:
  name: mypackage           # Required - Package name
  version: 1.2.3            # Required - Package version
  epoch: 0                  # Required - Revision number (starts at 0)
  description: "My package" # Required - Human-readable description
  url: https://example.com  # Optional - Project homepage
  copyright:                # Required - License information
    - license: MIT
  target-architecture:      # Optional - Architectures to build for
    - x86_64
    - aarch64
```

### Package Naming

The package filename is constructed as: `{name}-{version}-r{epoch}.apk`

Example: `mypackage-1.2.3-r0.apk`

### dependencies

Runtime dependencies (installed when package is used, not during build):

```yaml
package:
  dependencies:
    runtime:
      - openssl
      - curl
    provides:
      - mypackage-alias=${{package.full-version}}
```

### options

Control SCA (Software Composition Analysis) behavior:

```yaml
package:
  options:
    no-provides: true    # Virtual package with no files
    no-depends: true     # Self-contained, no dependencies
    no-commands: true    # Don't search for commands in /usr/bin
```

### resources

Resource hints for build schedulers:

```yaml
package:
  resources:
    cpu: "8"
    memory: "16Gi"
    disk: "100Gi"
```

### scriptlets

Lifecycle scripts that run during install/uninstall:

```yaml
package:
  scriptlets:
    post-install: |
      #!/bin/sh
      echo "Package installed"
    pre-deinstall: |
      #!/bin/sh
      echo "About to uninstall"
```

## environment

Specifies the build environment.

```yaml
environment:
  contents:
    repositories:
      - https://packages.wolfi.dev/os
    keyring:
      - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
    packages:
      - build-base
      - go
  environment:
    CGO_ENABLED: "0"
    GOPATH: /home/build/go
  accounts:
    users:
      - username: builduser
        uid: 1000
        gid: 1000
    groups:
      - groupname: buildgroup
        gid: 1000
    run-as: builduser
```

### contents

| Field | Description |
|-------|-------------|
| `repositories` | APK repositories to fetch packages from |
| `keyring` | Public keys for repository verification |
| `packages` | Packages to install in the build environment |

### Package Version Constraints

```yaml
packages:
  - go>1.21       # Anything newer than 1.21
  - foo=~4.5.6    # Any 4.5.6.x version
  - python3       # Latest version
```

## pipeline

Ordered list of build steps. Each step is either `runs` (shell commands) or `uses` (built-in pipeline).

### runs

Execute shell commands:

```yaml
pipeline:
  - name: Build the binary
    runs: |
      go build -o myapp .
      install -Dm755 myapp ${{targets.destdir}}/usr/bin/myapp
```

### uses

Use a built-in pipeline:

```yaml
pipeline:
  - uses: go/build
    with:
      packages: ./cmd/myapp
      output: myapp
```

### Common Fields

| Field | Description |
|-------|-------------|
| `name` | Step name (shown in progress output) |
| `runs` | Shell commands to execute |
| `uses` | Built-in pipeline to invoke |
| `with` | Parameters for built-in pipeline |
| `working-directory` | Directory to run commands in |
| `environment` | Additional environment variables |
| `if` | Conditional execution |

### Conditional Execution

```yaml
pipeline:
  - if: ${{build.arch}} == "x86_64"
    runs: |
      ./configure --enable-sse4
```

### Nested Pipelines

```yaml
pipeline:
  - environment:
      FOO: bar
    pipeline:
      - runs: echo $FOO
```

## Variable Substitution

Use `${{...}}` for variable substitution:

| Variable | Description |
|----------|-------------|
| `${{package.name}}` | Package name |
| `${{package.version}}` | Package version |
| `${{package.epoch}}` | Package epoch |
| `${{package.full-version}}` | `{version}-r{epoch}` |
| `${{targets.destdir}}` | Output directory for package files |
| `${{targets.contextdir}}` | Build context directory |
| `${{build.arch}}` | Target architecture |
| `${{host.triplet.gnu}}` | GNU triplet (e.g., x86_64-pc-linux-gnu) |
| `${{vars.custom}}` | Custom variable |

## subpackages

Create additional packages from the same build:

```yaml
subpackages:
  - name: ${{package.name}}-dev
    description: Development headers
    pipeline:
      - uses: split/dev
  - name: ${{package.name}}-doc
    description: Documentation
    pipeline:
      - runs: |
          mkdir -p ${{targets.subpkgdir}}/usr/share/doc
          mv ${{targets.destdir}}/usr/share/doc/* ${{targets.subpkgdir}}/usr/share/doc/
```

## vars

Define custom variables:

```yaml
vars:
  go-version: "1.21"
  custom-flag: "--enable-feature"

pipeline:
  - runs: |
      go${{vars.go-version}} build ...
      ./configure ${{vars.custom-flag}}
```

## var-transforms

Transform variables using regex:

```yaml
var-transforms:
  - from: ${{package.version}}
    match: \.(\d+)$
    replace: +$1
    to: mangled-version

pipeline:
  - uses: fetch
    with:
      uri: https://example.com/release-${{vars.mangled-version}}.tar.gz
```

See [Variable Transforms](../reference/var-transforms.md) for details.

## update

Configure automatic version updates:

```yaml
update:
  enabled: true
  github:
    identifier: org/repo
    strip-prefix: v
    use-tag: true
```

See [Auto-Updates](../reference/auto-updates.md) for details.
