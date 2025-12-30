# Adding Built-in Pipelines

This guide explains how to contribute new built-in pipelines to melange2.

## Overview

Built-in pipelines are YAML files in `pkg/build/pipelines/` that define reusable build workflows. They can be referenced in melange configurations using the `uses:` directive.

## Pipeline Structure

### Directory Organization

```
pkg/build/pipelines/
+-- autoconf/
|   +-- configure.yaml
|   +-- make.yaml
|   +-- make-install.yaml
+-- cmake/
|   +-- build.yaml
|   +-- configure.yaml
|   +-- install.yaml
+-- go/
|   +-- build.yaml
|   +-- bump.yaml
|   +-- install.yaml
+-- python/
|   +-- build.yaml
|   +-- build-wheel.yaml
|   +-- install.yaml
+-- split/
|   +-- dev.yaml
|   +-- lib.yaml
|   +-- manpages.yaml
+-- fetch.yaml
+-- git-checkout.yaml
+-- patch.yaml
+-- strip.yaml
```

### Basic Pipeline YAML

```yaml
name: Descriptive name for the pipeline

needs:
  packages:
    - required-package
    - another-package

inputs:
  param-name:
    description: |
      Description of what this parameter does.
      Can be multi-line.
    required: true  # or false (default)
    default: default-value

pipeline:
  - runs: |
      echo "Shell script here"
      echo "Parameter value: ${{inputs.param-name}}"
```

## Complete Example: autoconf/configure

From `pkg/build/pipelines/autoconf/configure.yaml`:

```yaml
name: Run autoconf configure script

needs:
  packages:
    - autoconf
    - automake

inputs:
  dir:
    description: |
      The directory containing the configure script.
    default: .

  host:
    description: |
      The GNU triplet which describes the host system.
    default: ${{host.triplet.gnu}}

  build:
    description: |
      The GNU triplet which describes the build system.
    default: ${{host.triplet.gnu}}

  opts:
    description: |
      Options to pass to the ./configure command.
    default: ''

pipeline:
  - runs: |
      cd ${{inputs.dir}}

      # Attempt to generate configuration if one does not exist
      if [[ ! -f ./configure && -f ./configure.ac ]]; then
          autoreconf -vfi
      fi

      ./configure \
        --host=${{inputs.host}} \
        --build=${{inputs.build}} \
        --prefix=/usr \
        --sysconfdir=/etc \
        --libdir=/usr/lib \
        --mandir=/usr/share/man \
        --infodir=/usr/share/info \
        --localstatedir=/var \
        ${{inputs.opts}}
```

## Complete Example: go/build

From `pkg/build/pipelines/go/build.yaml`:

```yaml
name: Run a build using the go compiler

needs:
  packages:
    - ${{inputs.go-package}}
    - busybox
    - ca-certificates-bundle

inputs:
  go-package:
    description: |
      The go package to install
    default: go

  packages:
    description: |
      List of space-separated packages to compile. Files can also be specified.
      This value is passed as an argument to go build. All paths are relative
      to inputs.modroot.
    required: true

  tags:
    description: |
      A comma-separated list of build tags to append to the go compiler

  toolchaintags:
    description: |
      A comma-separated list of default toolchain go build tags
    default: "netgo,osusergo"

  output:
    description: |
      Filename to use when writing the binary. The final install location inside
      the apk will be in prefix / install-dir / output
    required: true

  vendor:
    description: |
      If true, the go mod command will also update the vendor directory
    default: "false"

  modroot:
    default: "."
    required: false
    description: |
      Top directory of the go module, this is where go.mod lives.

  prefix:
    description: |
      Prefix to relocate binaries
    default: usr

  ldflags:
    description:
      List of [pattern=]arg to append to the go compiler with -ldflags

  strip:
    description:
      Set of strip ldflags passed to the go compiler
    default: "-w"

  install-dir:
    description: |
      Directory where binaries will be installed
    default: bin

  deps:
    description: |
      space separated list of go modules to update before building.

  experiments:
    description: |
      A comma-separated list of Golang experiment names to use.
    default: ""

  extra-args:
    description: |
      A space-separated list of extra arguments to pass to the go build command.
    default: ""

  amd64:
    description: |
      GOAMD64 microarchitecture level to use
    default: "v2"

  arm64:
    description: |
      GOARM64 microarchitecture level to use
    default: "v8.0"

  buildmode:
    description: |
      The -buildmode flag value.
    default: "default"

  tidy:
    description: |
      If true, "go mod tidy" will run before the build
    default: "false"

pipeline:
  - runs: |
      cd "${{inputs.modroot}}"

      # Check if modroot is set correctly
      if [ ! -e go.mod ]; then
        echo "go.mod not found in ${{inputs.modroot}}"
        exit 1
      fi

      "${{inputs.tidy}}" && go mod tidy

      LDFLAGS="${{inputs.strip}} ${{inputs.ldflags}}"
      BASE_PATH="${{inputs.prefix}}/${{inputs.install-dir}}/${{inputs.output}}"

      # Use melange's build cache for downloaded modules
      export GOMODCACHE=/var/cache/melange/gomodcache

      # Install any specified dependencies
      if [ ! "${{inputs.deps}}" == "" ]; then
        for dep in ${{inputs.deps}}; do
          go get $dep
        done
        go mod tidy
        "${{inputs.vendor}}" && go mod vendor
      fi

      GOAMD64="${{inputs.amd64}}" \
      GOARM64="${{inputs.arm64}}" \
      GOEXPERIMENT="${{inputs.experiments}}" \
      go build \
        -o "${{targets.contextdir}}"/${BASE_PATH} \
        -tags "${{inputs.toolchaintags}},${{inputs.tags}}" \
        -ldflags "${LDFLAGS}" \
        -trimpath \
        -buildmode ${{inputs.buildmode}} \
        ${{inputs.extra-args}} \
        ${{inputs.packages}}
```

## YAML Fields Reference

### Top-Level Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Human-readable pipeline name |
| `needs` | No | Package dependencies |
| `inputs` | No | Input parameters |
| `pipeline` | Yes | List of pipeline steps |

### Needs Section

```yaml
needs:
  packages:
    - package-name
    - ${{inputs.dynamic-package}}  # Can use input substitution
```

### Input Definition

```yaml
inputs:
  param-name:
    description: |
      Multi-line description of the parameter.
    required: true     # If true, user must provide value
    default: value     # Default if not provided (makes required: false implicit)
```

### Pipeline Steps

```yaml
pipeline:
  - name: Step name (optional)
    runs: |
      Shell script to execute
    if: condition  # Optional condition
    environment:   # Optional step-specific environment
      VAR: value
```

## Variable Substitution

### Available Variables

| Variable | Description |
|----------|-------------|
| `${{inputs.name}}` | Input parameter value |
| `${{package.name}}` | Package name |
| `${{package.version}}` | Package version |
| `${{package.epoch}}` | Package epoch |
| `${{targets.destdir}}` | Output directory |
| `${{targets.contextdir}}` | Build context directory |
| `${{targets.subpkgdir}}` | Subpackage output directory |
| `${{host.triplet.gnu}}` | Host GNU triplet |
| `${{build.arch}}` | Target architecture |
| `${{vars.name}}` | Custom variable from config |

### Input in Package Dependencies

```yaml
needs:
  packages:
    - ${{inputs.go-package}}  # Dynamic package based on input
```

## Step-by-Step: Adding a New Pipeline

### 1. Choose Location

Decide where the pipeline belongs:

- **Category-specific**: `pkg/build/pipelines/{category}/{name}.yaml`
- **General-purpose**: `pkg/build/pipelines/{name}.yaml`

### 2. Create the YAML File

```yaml
name: Description of what this pipeline does

needs:
  packages:
    - required-dependency

inputs:
  source-dir:
    description: |
      Directory containing source files.
    default: .

  output-dir:
    description: |
      Directory for output files.
    default: ${{targets.destdir}}

pipeline:
  - name: Build step
    runs: |
      cd ${{inputs.source-dir}}
      # Build commands here
      mkdir -p ${{inputs.output-dir}}/usr/bin
      # Install commands here
```

### 3. Test the Pipeline

Create a test configuration:

```yaml
# examples/test-new-pipeline.yaml
package:
  name: test-new-pipeline
  version: 1.0.0
  epoch: 0

pipeline:
  - uses: category/new-pipeline
    with:
      source-dir: .
      output-dir: ${{targets.destdir}}
```

Build and test:

```bash
./melange2 build examples/test-new-pipeline.yaml \
  --buildkit-addr tcp://localhost:1234
```

### 4. Add E2E Test (Optional but Recommended)

Create `pkg/buildkit/testdata/e2e/XX-new-pipeline.yaml`:

```yaml
package:
  name: new-pipeline-test
  version: 1.0.0
  epoch: 0

pipeline:
  - uses: category/new-pipeline
    with:
      source-dir: .
```

Add test in `pkg/buildkit/e2e_test.go`:

```go
func TestE2E_NewPipeline(t *testing.T) {
    e := newE2ETestContext(t)
    cfg := loadTestConfig(t, "XX-new-pipeline.yaml")

    outDir, err := e.buildConfig(cfg)
    require.NoError(t, err, "build should succeed")

    verifyFileExists(t, outDir, "new-pipeline-test/expected/path")
}
```

### 5. Rebuild

After adding the pipeline, rebuild melange2:

```bash
go build -o melange2 .
```

## Best Practices

### 1. Default Values

Provide sensible defaults for all optional parameters:

```yaml
inputs:
  prefix:
    default: usr  # Most packages install to /usr
  jobs:
    default: "4"  # Reasonable parallelism
```

### 2. Clear Descriptions

Write clear, helpful descriptions:

```yaml
inputs:
  ldflags:
    description: |
      Linker flags to pass to the compiler. Common uses:
      - -s -w: Strip debug info for smaller binaries
      - -X main.version=$VERSION: Set version at compile time
```

### 3. Error Handling

Add validation in scripts:

```yaml
pipeline:
  - runs: |
      if [ ! -f configure ]; then
        echo "ERROR: configure script not found"
        exit 1
      fi
```

### 4. Cache Integration

Use the melange cache for downloads:

```yaml
pipeline:
  - runs: |
      export GOMODCACHE=/var/cache/melange/gomodcache
      export PIP_CACHE_DIR=/var/cache/melange/pip
```

### 5. Output to Correct Directories

Always use `${{targets.destdir}}` for package output:

```yaml
pipeline:
  - runs: |
      make install DESTDIR=${{targets.destdir}}
```

## Existing Pipeline Categories

| Category | Purpose | Examples |
|----------|---------|----------|
| `autoconf/` | GNU Autotools builds | configure, make, make-install |
| `cmake/` | CMake builds | configure, build, install |
| `go/` | Go builds | build, install, bump |
| `python/` | Python builds | build, build-wheel, install |
| `perl/` | Perl builds | make, cleanup |
| `ruby/` | Ruby builds | build, install, clean |
| `cargo/` | Rust/Cargo builds | build |
| `meson/` | Meson builds | configure, compile, install |
| `npm/` | Node.js builds | install |
| `split/` | Package splitting | dev, lib, manpages, static |
| `pecl/` | PHP PECL builds | install, phpize |
| `xcover/` | Coverage tools | ensure, profile, status |

## Documenting Pipelines

Pipeline documentation is auto-generated:

```bash
make docs-pipeline
```

This generates reference documentation from the YAML files.
