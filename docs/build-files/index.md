# Build File Overview

A melange build file is a YAML configuration that defines how to build an APK package. This document provides an overview of the build file structure and its main sections.

## File Structure

A complete build file contains the following top-level sections:

```yaml
package:         # Required: Package metadata
environment:     # Required: Build environment configuration
pipeline:        # Required: Build steps
subpackages:     # Optional: Additional packages to produce
vars:            # Optional: Custom variables
var-transforms:  # Optional: Variable transformations
data:            # Optional: Data for range-based subpackages
options:         # Optional: Build option variants
capabilities:    # Optional: Linux capabilities for the build runner
test:            # Optional: Test configuration for the main package
```

## Minimal Example

The simplest valid build file:

```yaml
package:
  name: minimal
  version: 0.0.1
  epoch: 0
  description: a very basic melange example

environment:
  contents:
    repositories:
      - https://packages.wolfi.dev/os
    keyring:
      - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
    packages:
      - busybox

pipeline:
  - runs: |
      mkdir -p "${{targets.destdir}}"
      echo "hello" > "${{targets.destdir}}/hello"
```

## Complete Example

A more comprehensive build file demonstrating multiple features:

```yaml
package:
  name: hello
  version: 2.12
  epoch: 0
  description: "the GNU hello world program"
  copyright:
    - attestation: |
        Copyright 1992, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2005,
        2006, 2007, 2008, 2010, 2011, 2013, 2014, 2022 Free Software Foundation,
        Inc.
      license: GPL-3.0-or-later
  dependencies:
    runtime:

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
      uri: https://mirrors.ocf.berkeley.edu/gnu/hello/hello-${{package.version}}.tar.gz
      expected-sha256: cf04af86dc085268c5f4470fbae49b18afbc221b78096aab842d934a76bad0ab

  - uses: autoconf/configure

  - uses: autoconf/make

  - uses: autoconf/make-install

  - uses: strip
```

## Section Reference

| Section | Required | Description |
|---------|----------|-------------|
| `package` | Yes | Package metadata including name, version, description, and dependencies |
| `environment` | Yes | Build environment configuration with repositories and packages |
| `pipeline` | Yes | List of build steps to execute |
| `subpackages` | No | Additional packages to create from the build |
| `vars` | No | Custom variables for use in templates |
| `var-transforms` | No | Regex-based transformations to create derived variables |
| `data` | No | Named data sets for range-based subpackage generation |
| `options` | No | Build option variants that modify variables and environment |
| `capabilities` | No | Linux capabilities to add or drop for the build runner |
| `test` | No | Test pipeline for the main package |

## Configuration Struct

The build file maps to the `Configuration` struct in `pkg/config/config.go`:

```go
type Configuration struct {
    Package      Package                         `yaml:"package"`
    Environment  apko_types.ImageConfiguration   `yaml:"environment,omitempty"`
    Capabilities Capabilities                    `yaml:"capabilities,omitempty"`
    Pipeline     []Pipeline                      `yaml:"pipeline,omitempty"`
    Subpackages  []Subpackage                    `yaml:"subpackages,omitempty"`
    Data         []RangeData                     `yaml:"data,omitempty"`
    Update       Update                          `yaml:"update,omitempty"`
    Vars         map[string]string               `yaml:"vars,omitempty"`
    VarTransforms []VarTransforms                `yaml:"var-transforms,omitempty"`
    Options      map[string]BuildOption          `yaml:"options,omitempty"`
    Test         *Test                           `yaml:"test,omitempty"`
}
```

## Related Documentation

- [Package Metadata](package-metadata.md) - Detailed documentation of the `package` block
- [Environment](environment.md) - Build environment configuration
- [Pipeline](pipeline.md) - Build step syntax and options
- [Subpackages](subpackages.md) - Creating additional packages
- [Variables](variables.md) - Built-in and custom variables
- [Options](options.md) - Build option variants
