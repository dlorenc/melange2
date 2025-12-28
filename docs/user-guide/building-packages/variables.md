# Variables and Substitution

melange uses `${{...}}` syntax for variable substitution in build files.

## Built-in Variables

### Package Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `${{package.name}}` | Package name | `mypackage` |
| `${{package.version}}` | Package version | `1.2.3` |
| `${{package.epoch}}` | Package epoch | `0` |
| `${{package.full-version}}` | Full version string | `1.2.3-r0` |
| `${{package.description}}` | Package description | `My package` |

### Target Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `${{targets.destdir}}` | Output directory for main package | `/home/build/melange-out/mypackage` |
| `${{targets.subpkgdir}}` | Output directory for subpackage | `/home/build/melange-out/mypackage-dev` |
| `${{targets.contextdir}}` | Build context directory | `/home/build` |

### Build Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `${{build.arch}}` | Target architecture | `x86_64`, `aarch64` |
| `${{build.goarch}}` | Go architecture name | `amd64`, `arm64` |

### Host Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `${{host.triplet.gnu}}` | GNU triplet | `x86_64-pc-linux-gnu` |
| `${{host.triplet.rust}}` | Rust target triple | `x86_64-unknown-linux-gnu` |

## Custom Variables

Define custom variables with the `vars` section:

```yaml
vars:
  pypi-package: my-python-package
  major-version: "3"

pipeline:
  - runs: |
      pip install ${{vars.pypi-package}}==${{package.version}}
```

## Variable Transforms

Transform variables using regex with `var-transforms`:

```yaml
package:
  version: 17.0.7.5

var-transforms:
  - from: ${{package.version}}
    match: \.(\d+)$
    replace: +$1
    to: java-version

pipeline:
  - uses: fetch
    with:
      # Downloads jdk-17.0.7+5.tar.gz
      uri: https://github.com/openjdk/jdk17u/archive/jdk-${{vars.java-version}}.tar.gz
```

### Transform Fields

| Field | Description |
|-------|-------------|
| `from` | Source variable |
| `match` | Regex pattern to match |
| `replace` | Replacement string (use `$1`, `${1}` for groups) |
| `to` | Name of new variable |

### Regex Tips

- Use `$1` or `${1}` for capture groups
- When joining groups with special chars, use `${1}_${2}`
- Test patterns at [regex101.com](https://regex101.com/)

## Environment Variables

Set environment variables for pipeline steps:

```yaml
environment:
  environment:
    CGO_ENABLED: "0"
    GOPATH: /home/build/go

pipeline:
  - runs: go build  # Uses CGO_ENABLED=0
```

Per-step environment:

```yaml
pipeline:
  - environment:
      GOOS: linux
      GOARCH: amd64
    runs: go build -o myapp-linux-amd64
```

## Variable Scope

Variables are evaluated at different times:

1. **Package variables** - Available everywhere
2. **vars** - Available after definition
3. **var-transforms** - Computed at parse time
4. **environment** - Available in pipeline steps

## Common Patterns

### Version String Manipulation

```yaml
# Extract major version from 1.2.3
var-transforms:
  - from: ${{package.version}}
    match: ^(\d+)\..*
    replace: $1
    to: major-version
```

### Architecture-Specific Builds

```yaml
pipeline:
  - if: ${{build.arch}} == "x86_64"
    runs: ./configure --enable-sse4
  - if: ${{build.arch}} == "aarch64"
    runs: ./configure --enable-neon
```

### Using Package Name in Paths

```yaml
pipeline:
  - runs: |
      install -Dm755 myapp ${{targets.destdir}}/usr/bin/${{package.name}}
```
