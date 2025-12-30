# Subpackages

The `subpackages` block defines additional packages that are created from the same build. This is commonly used to split development headers, documentation, or provide package variants.

## Basic Structure

```yaml
subpackages:
  - name: mypackage-dev
    description: "Development files for mypackage"
    pipeline:
      - uses: split/dev

  - name: mypackage-doc
    description: "Documentation for mypackage"
    pipeline:
      - uses: split/manpages
```

## Subpackage Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Required. Subpackage name |
| `description` | string | Human-readable description |
| `url` | string | Homepage URL |
| `pipeline` | []Pipeline | Build steps for this subpackage |
| `dependencies` | Dependencies | Runtime dependencies and provides |
| `options` | PackageOption | Package behavior options |
| `scriptlets` | Scriptlets | Installation scripts |
| `checks` | Checks | Linter configuration |
| `test` | Test | Test configuration |
| `if` | string | Conditional expression |
| `range` | string | Data range for iteration |
| `setcap` | []Capability | File capabilities |

## Basic Example

```yaml
package:
  name: curl
  version: 7.87.0
  epoch: 3

pipeline:
  - uses: fetch
    with:
      uri: https://curl.se/download/curl-${{package.version}}.tar.xz
  - uses: autoconf/configure
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
```

## Subpackage Dependencies

### Runtime Dependencies

```yaml
subpackages:
  - name: myapp-plugins
    dependencies:
      runtime:
        - myapp
        - libplugin
```

### Provides

Declare virtual packages:

```yaml
subpackages:
  - name: libcurl-openssl4
    description: "curl library (openssl backend)"
    dependencies:
      provides:
        - libcurl4=7.87.1
      provider-priority: 5
    pipeline:
      - runs: |
          mkdir -p "${{targets.subpkgdir}}"/usr/lib
          mv "${{targets.destdir}}"/usr/lib/libcurl.so.* "${{targets.subpkgdir}}"/usr/lib/
```

## Conditional Subpackages

Use `if` to conditionally create subpackages:

```yaml
subpackages:
  - if: ${{options.rustls.enabled}} == 'false'
    name: libcurl-openssl4
    description: "curl library (openssl backend)"
    pipeline:
      - runs: |
          mkdir -p "${{targets.subpkgdir}}"/usr/lib
          mv "${{targets.destdir}}"/usr/lib/libcurl.so.* "${{targets.subpkgdir}}"/usr/lib/

  - if: ${{options.rustls.enabled}} == 'true'
    name: libcurl-rustls4
    description: "curl library (rustls backend)"
    pipeline:
      - runs: |
          mkdir -p "${{targets.subpkgdir}}"/usr/lib
          mv "${{targets.destdir}}"/usr/lib/libcurl.so.* "${{targets.subpkgdir}}"/usr/lib/
```

## Range-Based Subpackages

Generate multiple subpackages from data using `range`:

### Define Data

```yaml
data:
  - name: lagomorphs
    items:
      hare: 'lepus saxatilis'
      rabbit: 'sylvilagus floridanus'
      pika: 'ochotona princeps'
```

### Use Range in Subpackages

```yaml
subpackages:
  - range: lagomorphs
    name: lagomorph-${{range.key}}
    description: "Data about the lagomorph ${{range.value}}"
    pipeline:
      - runs: |
          echo "${{range.value}}" > ${{targets.contextdir}}/${{range.key}}
```

This generates three subpackages:
- `lagomorph-hare`
- `lagomorph-pika`
- `lagomorph-rabbit`

Note: Keys are processed in alphabetical order.

### Range Variables

| Variable | Description |
|----------|-------------|
| `${{range.key}}` | Current key from the data items |
| `${{range.value}}` | Current value from the data items |

## Subpackage Target Directories

Special variables for subpackage pipelines:

| Variable | Description |
|----------|-------------|
| `${{targets.subpkgdir}}` | Output directory for the subpackage |
| `${{targets.destdir}}` | Main package output directory |
| `${{targets.contextdir}}` | Current context directory |
| `${{subpkg.name}}` | Current subpackage name |

## Common Split Patterns

### Split Development Files

```yaml
subpackages:
  - name: ${{package.name}}-dev
    pipeline:
      - uses: split/dev
    dependencies:
      runtime:
        - ${{package.name}}
```

### Split Documentation

```yaml
subpackages:
  - name: ${{package.name}}-doc
    pipeline:
      - uses: split/manpages
```

### Split Binaries

```yaml
subpackages:
  - name: split-me
    pipeline:
      - uses: split/bin
        with:
          package: ${{package.name}}
    test:
      pipeline:
        - runs: |
            test -x /usr/bin/split-me
```

### Custom Split

```yaml
subpackages:
  - name: myapp-config
    pipeline:
      - runs: |
          mkdir -p "${{targets.subpkgdir}}"/etc
          mv "${{targets.destdir}}"/etc/myapp.conf "${{targets.subpkgdir}}"/etc/
```

## Subpackage Options

Override package behavior:

```yaml
subpackages:
  - name: mypackage-virtual
    options:
      no-provides: true
      no-depends: true
    pipeline:
      - runs: |
          mkdir -p "${{targets.subpkgdir}}"
```

See [Options](options.md) for details on package options.

## Subpackage Tests

Define tests specific to a subpackage:

```yaml
subpackages:
  - name: split-me
    pipeline:
      - uses: split/bin
    test:
      pipeline:
        - runs: |
            test -x /usr/bin/split-me
```

### Test Environment

```yaml
subpackages:
  - name: myapp-cli
    pipeline:
      - runs: |
          mkdir -p "${{targets.subpkgdir}}"/usr/bin
          mv "${{targets.destdir}}"/usr/bin/myapp "${{targets.subpkgdir}}"/usr/bin/
    test:
      environment:
        contents:
          packages:
            - busybox
      pipeline:
        - runs: |
            myapp --version
```

## Subpackage Scriptlets

Define installation scripts:

```yaml
subpackages:
  - name: myapp-service
    scriptlets:
      post-install: |
        #!/bin/sh
        rc-update add myapp default
      pre-deinstall: |
        #!/bin/sh
        rc-service myapp stop
    pipeline:
      - runs: |
          mkdir -p "${{targets.subpkgdir}}"/etc/init.d
          install -m755 myapp.init "${{targets.subpkgdir}}"/etc/init.d/myapp
```

## Variable Substitution

Subpackage names and other fields support variable substitution:

```yaml
vars:
  short-package-version: "2.12"

subpackages:
  - name: subpackage-${{vars.short-package-version}}
    pipeline:
      - runs: echo "subpackage-${{vars.short-package-version}}"
```

## Subpackage Struct Reference

From `pkg/config/config.go`:

```go
type Subpackage struct {
    If           string         `yaml:"if,omitempty"`
    Range        string         `yaml:"range,omitempty"`
    Name         string         `yaml:"name"`
    Pipeline     []Pipeline     `yaml:"pipeline,omitempty"`
    Dependencies Dependencies   `yaml:"dependencies,omitempty"`
    Options      *PackageOption `yaml:"options,omitempty"`
    Scriptlets   *Scriptlets    `yaml:"scriptlets,omitempty"`
    Description  string         `yaml:"description,omitempty"`
    URL          string         `yaml:"url,omitempty"`
    Commit       string         `yaml:"commit,omitempty"`
    Checks       Checks         `yaml:"checks,omitempty"`
    Test         *Test          `yaml:"test,omitempty"`
    SetCap       []Capability   `yaml:"setcap,omitempty"`
}
```

## Validation

- Subpackage names must match the regex `^[a-zA-Z\d][a-zA-Z\d+_.-]*$`
- Subpackage names cannot duplicate the main package name
- Subpackage names must be unique within the build file
- The `range` field must reference a defined data block
