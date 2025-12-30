# Package Metadata

The `package` block defines metadata for the APK package being built. This is a required section in every build file.

## Basic Fields

### name (required)

The package name. Must match the regex `^[a-zA-Z\d][a-zA-Z\d+_.-]*$`.

```yaml
package:
  name: hello
```

### version (required)

The package version string. Cannot be empty.

```yaml
package:
  name: hello
  version: 2.12.4
```

### epoch (required)

A monotonically increasing integer used for package ordering when the version string is unchanged. Start at 0 for new packages.

```yaml
package:
  name: hello
  version: 2.12.4
  epoch: 0
```

### description

A human-readable description of the package.

```yaml
package:
  name: hello
  version: 2.12.4
  epoch: 0
  description: "the GNU hello world program"
```

### url

The URL to the package's homepage.

```yaml
package:
  name: hello
  version: 2.12.4
  epoch: 0
  url: https://www.gnu.org/software/hello/
```

## Copyright

The `copyright` block defines licensing information for the package.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `license` | string | Required. SPDX license identifier |
| `attestation` | string | Optional. Copyright attestation text |
| `paths` | []string | Optional. Paths covered by this license (typically `*`) |
| `license-path` | string | Optional. Path to custom license text file |
| `detection-override` | string | Optional. License override for detection |

### Example

```yaml
package:
  name: hello
  version: 2.12
  epoch: 0
  copyright:
    - attestation: |
        Copyright 1992, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2005,
        2006, 2007, 2008, 2010, 2011, 2013, 2014, 2022 Free Software Foundation,
        Inc.
      license: GPL-3.0-or-later
```

### Multiple Licenses

```yaml
package:
  name: mypackage
  version: 1.0.0
  epoch: 0
  copyright:
    - license: MIT
      paths:
        - "*"
    - license: Apache-2.0
      paths:
        - "contrib/*"
```

## Dependencies

The `dependencies` block defines package dependencies and provides.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `runtime` | []string | Packages required at runtime |
| `provides` | []string | Virtual packages this package provides |
| `replaces` | []string | Packages this package replaces |
| `provider-priority` | string | Integer priority for provider resolution |
| `replaces-priority` | string | Integer priority for file replacements |

### Runtime Dependencies

```yaml
package:
  name: myapp
  version: 1.0.0
  epoch: 0
  dependencies:
    runtime:
      - libc
      - libssl3
      - libcrypto3
```

### Provides

Declare virtual packages that this package provides:

```yaml
package:
  name: libcurl-openssl4
  version: 7.87.1
  epoch: 0
  dependencies:
    provides:
      - libcurl4=7.87.1
    provider-priority: 5
```

### Variable Substitution in Dependencies

Dependencies support variable substitution:

```yaml
package:
  name: replacement-provides
  version: 0.0.1
  epoch: 0
  dependencies:
    provides:
      - replacement-provides-version=${{package.version}}
      - replacement-provides-foo=${{vars.foo}}

vars:
  foo: FOO
```

## Target Architecture

Limit which architectures the package builds for:

```yaml
package:
  name: one-arch
  version: 0.0.1
  epoch: 0
  target-architecture:
    - x86_64
```

Valid architectures include: `x86_64`, `aarch64`, `armv7`, `ppc64le`, `s390x`, `riscv64`.

Note: Using `target-architecture: ['all']` is deprecated.

## Annotations

Add arbitrary key-value metadata:

```yaml
package:
  name: mypackage
  version: 1.0.0
  epoch: 0
  annotations:
    org.opencontainers.image.source: https://github.com/example/mypackage
    custom.annotation: some-value
```

## Resources

Specify resource requirements for the build:

```yaml
package:
  name: gcc-13
  version: 13.2.0
  epoch: 0
  resources:
    cpu: "8"
    memory: "16Gi"
    disk: "100Gi"
  test-resources:
    cpu: "4"
    memory: "8Gi"
    disk: "50Gi"
```

### Resource Fields

| Field | Description |
|-------|-------------|
| `cpu` | CPU cores (e.g., "8") |
| `cpumodel` | Specific CPU model requirement |
| `memory` | Memory limit (e.g., "16Gi") |
| `disk` | Disk space requirement (e.g., "100Gi") |

## Timeout

Set a build timeout:

```yaml
package:
  name: mypackage
  version: 1.0.0
  epoch: 0
  timeout: 2h
```

## CPE (Common Platform Enumeration)

Define CPE values for vulnerability matching:

```yaml
package:
  name: mypackage
  version: 1.0.0
  epoch: 0
  cpe:
    vendor: myvendor
    product: mypackage
```

### CPE Fields

| Field | Description |
|-------|-------------|
| `part` | Part type (defaults to "a" for application) |
| `vendor` | Vendor name (required if product is set) |
| `product` | Product name (required if vendor is set) |
| `edition` | Edition |
| `language` | Language |
| `sw_edition` | Software edition |
| `target_sw` | Target software |
| `target_hw` | Target hardware |
| `other` | Other CPE field |

## Checks

Configure build checks/linters:

```yaml
package:
  name: git-checkout
  version: v0.0.1
  epoch: 0
  checks:
    disabled:
      - empty
```

## Scriptlets

Define scripts that run during package installation/removal:

```yaml
package:
  name: mypackage
  version: 1.0.0
  epoch: 0
  scriptlets:
    pre-install: |
      #!/bin/sh
      echo "About to install"
    post-install: |
      #!/bin/sh
      echo "Installation complete"
    pre-deinstall: |
      #!/bin/sh
      echo "About to remove"
    post-deinstall: |
      #!/bin/sh
      echo "Removal complete"
    pre-upgrade: |
      #!/bin/sh
      echo "About to upgrade"
    post-upgrade: |
      #!/bin/sh
      echo "Upgrade complete"
```

### Trigger Scriptlets

Run scripts when specific paths change:

```yaml
package:
  name: mypackage
  version: 1.0.0
  epoch: 0
  scriptlets:
    trigger:
      paths:
        - /usr/share/icons/*
      script: |
        #!/bin/sh
        update-icon-cache /usr/share/icons
```

## File Capabilities (setcap)

Set Linux capabilities on files:

```yaml
package:
  name: mypackage
  version: 1.0.0
  epoch: 0
  setcap:
    - path: /usr/bin/ping
      add:
        cap_net_raw: ep
      reason: "Allow ping to send ICMP packets without root"
```

### Supported Capabilities

| Capability | Description |
|------------|-------------|
| `cap_net_bind_service` | Bind to privileged ports |
| `cap_net_admin` | Network administration |
| `cap_net_raw` | Use raw sockets |
| `cap_ipc_lock` | Lock memory |
| `cap_sys_admin` | System administration |

### Capability Flags

| Flag | Meaning |
|------|---------|
| `e` | Effective |
| `p` | Permitted |
| `i` | Inheritable |

## Package Struct Reference

From `pkg/config/config.go`:

```go
type Package struct {
    Name               string            `yaml:"name"`
    Version            string            `yaml:"version"`
    Epoch              uint64            `yaml:"epoch"`
    Description        string            `yaml:"description,omitempty"`
    Annotations        map[string]string `yaml:"annotations,omitempty"`
    URL                string            `yaml:"url,omitempty"`
    Commit             string            `yaml:"commit,omitempty"`
    TargetArchitecture []string          `yaml:"target-architecture,omitempty"`
    Copyright          []Copyright       `yaml:"copyright,omitempty"`
    Dependencies       Dependencies      `yaml:"dependencies,omitempty"`
    Options            *PackageOption    `yaml:"options,omitempty"`
    Scriptlets         *Scriptlets       `yaml:"scriptlets,omitempty"`
    Checks             Checks            `yaml:"checks,omitempty"`
    CPE                CPE               `yaml:"cpe,omitempty"`
    SetCap             []Capability      `yaml:"setcap,omitempty"`
    Timeout            time.Duration     `yaml:"timeout,omitempty"`
    Resources          *Resources        `yaml:"resources,omitempty"`
    TestResources      *Resources        `yaml:"test-resources,omitempty"`
}
```
