# Variables

Melange provides a powerful variable substitution system that allows you to reference package metadata, build information, and custom values throughout your build file.

## Substitution Syntax

Variables use the syntax `${{variable.name}}`:

```yaml
pipeline:
  - runs: |
      echo "Building ${{package.name}} version ${{package.version}}"
```

## Built-in Variables

### Package Variables

| Variable | Description |
|----------|-------------|
| `${{package.name}}` | Package name |
| `${{package.version}}` | Package version |
| `${{package.full-version}}` | Full version including epoch (e.g., `1.0.0-r0`) |
| `${{package.epoch}}` | Package epoch |
| `${{package.description}}` | Package description |
| `${{package.srcdir}}` | Source directory |

### Target Directories

| Variable | Description |
|----------|-------------|
| `${{targets.destdir}}` | Main package output directory |
| `${{targets.outdir}}` | Build output directory |
| `${{targets.contextdir}}` | Current context directory |
| `${{targets.subpkgdir}}` | Subpackage output directory |

### Build Variables

| Variable | Description |
|----------|-------------|
| `${{build.arch}}` | Target architecture (e.g., `x86_64`, `aarch64`) |
| `${{build.goarch}}` | Go architecture name (e.g., `amd64`, `arm64`) |

### Host Triplets

| Variable | Description |
|----------|-------------|
| `${{host.triplet.gnu}}` | GNU host triplet |
| `${{host.triplet.rust}}` | Rust host triplet |

### Cross-Compilation Triplets

| Variable | Description |
|----------|-------------|
| `${{cross.triplet.gnu.glibc}}` | GNU cross triplet for glibc |
| `${{cross.triplet.gnu.musl}}` | GNU cross triplet for musl |
| `${{cross.triplet.rust.glibc}}` | Rust cross triplet for glibc |
| `${{cross.triplet.rust.musl}}` | Rust cross triplet for musl |

### Subpackage Variables

| Variable | Description |
|----------|-------------|
| `${{subpkg.name}}` | Current subpackage name |
| `${{context.name}}` | Current context name |

### Range Variables (for subpackages)

| Variable | Description |
|----------|-------------|
| `${{range.key}}` | Current key in range iteration |
| `${{range.value}}` | Current value in range iteration |

## Custom Variables

Define custom variables in the `vars` block:

```yaml
vars:
  foo: "Hello"
  bar: "World"
  buildLocation: "/home/build/foo"

pipeline:
  - working-directory: ${{vars.buildLocation}}
    runs: |
      echo "${{vars.foo}} ${{vars.bar}}"
```

### Variable Naming

Variable names can contain letters, numbers, and hyphens:

```yaml
vars:
  my-variable: "value"
  another_var: "value2"
  version123: "1.2.3"
```

Access with `${{vars.my-variable}}`.

## Variable Transforms

Transform variables using regex patterns with `var-transforms`:

```yaml
package:
  name: bar
  version: 1.2.3.4

var-transforms:
  - from: ${{package.version}}
    match: \.(\d+)$
    replace: +$1
    to: mangled-package-version

pipeline:
  - uses: fetch
    with:
      uri: https://github.com/foo/bar/archive/refs/tags/${{vars.mangled-package-version}}.tar.gz
```

This transforms `1.2.3.4` to `1.2.3+4`.

### Transform Fields

| Field | Description |
|-------|-------------|
| `from` | Source variable or value |
| `match` | Regular expression pattern |
| `replace` | Replacement string (supports capture groups) |
| `to` | Name of the new variable to create |

### Transform Examples

**Extract Major.Minor Version:**

```yaml
var-transforms:
  - from: ${{package.version}}
    match: ^(\d+\.\d+)\.\d+$
    replace: "$1"
    to: short-package-version
```

Transforms `2.12.4` to `2.12`.

**Convert Dots to Underscores:**

```yaml
var-transforms:
  - from: ${{package.version}}
    match: \.
    replace: "_"
    to: version-underscored
```

Transforms `1.2.3` to `1_2_3`.

**Extract Git Tag:**

```yaml
var-transforms:
  - from: ${{package.version}}
    match: ^v?(.*)$
    replace: "$1"
    to: version-no-v
```

Transforms `v1.0.0` to `1.0.0`.

## Variable Usage Locations

Variables can be used in:

### Pipeline Steps

```yaml
pipeline:
  - runs: |
      echo "Package: ${{package.name}}"
      mkdir -p "${{targets.destdir}}/usr/bin"
```

### Pipeline `with` Arguments

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/${{package.name}}-${{package.version}}.tar.gz
```

### Working Directory

```yaml
pipeline:
  - working-directory: ${{vars.buildLocation}}
    runs: |
      make build
```

### Conditional Expressions

```yaml
pipeline:
  - if: ${{build.arch}} == 'x86_64'
    runs: |
      echo "Building for x86_64"
```

### Subpackage Names

```yaml
subpackages:
  - name: ${{package.name}}-dev
    pipeline:
      - uses: split/dev
```

### Dependencies

```yaml
package:
  dependencies:
    provides:
      - mypackage-version=${{package.version}}
```

### Environment Variables

```yaml
environment:
  environment:
    MY_VERSION: ${{package.version}}
```

## External Variables File

Load variables from an external YAML file:

```bash
./melange2 build pkg.yaml --vars-file vars.yaml
```

**vars.yaml:**

```yaml
my-var: "value"
another-var: "another-value"
```

Variables from the external file are merged with those in the build file. Build file variables take precedence.

## Variable Resolution Order

1. Built-in variables (`package.*`, `build.*`, `targets.*`)
2. Custom variables from `vars` block
3. Transformed variables from `var-transforms`
4. External variables file (lowest precedence)

## Built-in Variable Constants

From `pkg/config/vars.go`:

```go
const (
    SubstitutionPackageName           = "${{package.name}}"
    SubstitutionPackageVersion        = "${{package.version}}"
    SubstitutionPackageFullVersion    = "${{package.full-version}}"
    SubstitutionPackageEpoch          = "${{package.epoch}}"
    SubstitutionPackageDescription    = "${{package.description}}"
    SubstitutionPackageSrcdir         = "${{package.srcdir}}"
    SubstitutionTargetsOutdir         = "${{targets.outdir}}"
    SubstitutionTargetsDestdir        = "${{targets.destdir}}"
    SubstitutionTargetsContextdir     = "${{targets.contextdir}}"
    SubstitutionSubPkgName            = "${{subpkg.name}}"
    SubstitutionSubPkgDir             = "${{targets.subpkgdir}}"
    SubstitutionContextName           = "${{context.name}}"
    SubstitutionHostTripletGnu        = "${{host.triplet.gnu}}"
    SubstitutionHostTripletRust       = "${{host.triplet.rust}}"
    SubstitutionCrossTripletGnuGlibc  = "${{cross.triplet.gnu.glibc}}"
    SubstitutionCrossTripletGnuMusl   = "${{cross.triplet.gnu.musl}}"
    SubstitutionCrossTripletRustGlibc = "${{cross.triplet.rust.glibc}}"
    SubstitutionCrossTripletRustMusl  = "${{cross.triplet.rust.musl}}"
    SubstitutionBuildArch             = "${{build.arch}}"
    SubstitutionBuildGoArch           = "${{build.goarch}}"
)
```

## Complete Example

```yaml
package:
  name: hello
  version: 2.12.4
  epoch: 0
  description: "Example package with variables"

vars:
  foo: "Hello"
  bar: "World"
  buildLocation: "/home/build/foo"

var-transforms:
  - from: ${{package.version}}
    match: ^(\d+\.\d+)\.\d+$
    replace: "$1"
    to: short-package-version

environment:
  contents:
    packages:
      - busybox

pipeline:
  - working-directory: ${{vars.buildLocation}}
    runs: |
      echo "Building ${{package.name}} ${{package.version}}"
      echo "${{vars.foo}} ${{vars.bar}}"

  - working-directory: ${{targets.destdir}}
    runs: |
      mkdir -p usr/share
      echo "Version: ${{vars.short-package-version}}" > usr/share/version

subpackages:
  - name: subpackage-${{vars.short-package-version}}
    pipeline:
      - runs: echo "Building subpackage for ${{vars.short-package-version}}"
```
