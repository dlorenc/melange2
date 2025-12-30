# Go Pipelines

These pipelines provide comprehensive support for building Go projects.

## go/build

Build Go projects from source with full control over build parameters.

### Required Packages

- `${{inputs.go-package}}` (default: `go`)
- `busybox`
- `ca-certificates-bundle`

### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `packages` | **Yes** | - | Space-separated packages to compile (passed to `go build`) |
| `output` | **Yes** | - | Output binary filename |
| `go-package` | No | `go` | The Go package to use (e.g., `go-1.21`) |
| `modroot` | No | `.` | Directory containing go.mod |
| `prefix` | No | `usr` | Installation prefix |
| `install-dir` | No | `bin` | Directory for installed binaries |
| `tags` | No | - | Comma-separated list of build tags |
| `toolchaintags` | No | `netgo,osusergo` | Default toolchain build tags |
| `ldflags` | No | - | Linker flags to pass to the compiler |
| `strip` | No | `-w` | Strip flags (note: symbol tables kept for audits) |
| `vendor` | No | `false` | Update vendor directory before building |
| `deps` | No | - | Space-separated go modules to update before building |
| `experiments` | No | `""` | Comma-separated Go experiment names |
| `extra-args` | No | `""` | Additional arguments for go build |
| `amd64` | No | `v2` | GOAMD64 microarchitecture level |
| `arm64` | No | `v8.0` | GOARM64 microarchitecture level |
| `buildmode` | No | `default` | Go buildmode (see `go help buildmode`) |
| `tidy` | No | `false` | Run `go mod tidy` before building |
| `ignore-untracked-files` | No | `true` | Ignore untracked files in git versioning |

### Build Behavior

- Verifies `go.mod` exists in `modroot`
- Uses melange build cache for Go module downloads (`GOMODCACHE=/var/cache/melange/gomodcache`)
- Applies local go.mod/go.sum overlays if present at `/home/build/go.mod.local`
- Uses `-trimpath` for reproducible builds
- Combines `toolchaintags` and `tags` inputs

### Example Usage

Simple binary build:

```yaml
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/myapp.git
      tag: v${{package.version}}
      expected-commit: abc123...

  - uses: go/build
    with:
      packages: ./cmd/myapp
      output: myapp
```

With custom ldflags for version injection:

```yaml
pipeline:
  - uses: go/build
    with:
      packages: ./cmd/myapp
      output: myapp
      ldflags: |
        -X main.version=${{package.version}}
        -X main.commit=${{vars.commit}}
```

Multiple binaries:

```yaml
pipeline:
  - uses: go/build
    with:
      packages: ./cmd/server
      output: server

  - uses: go/build
    with:
      packages: ./cmd/client
      output: client
```

With build tags and experiments:

```yaml
pipeline:
  - uses: go/build
    with:
      packages: .
      output: mytool
      tags: sqlite,netgo
      experiments: loopvar
```

Building from a subdirectory:

```yaml
pipeline:
  - uses: go/build
    with:
      modroot: src/go
      packages: ./cmd/app
      output: app
```

With vendored dependencies:

```yaml
pipeline:
  - uses: go/build
    with:
      packages: .
      output: myapp
      vendor: true
      deps: github.com/some/dep@v1.2.3
```

Plugin build mode:

```yaml
pipeline:
  - uses: go/build
    with:
      packages: ./plugin
      output: myplugin.so
      buildmode: plugin
```

---

## go/install

Install Go packages directly from a remote repository using `go install`.

### Required Packages

- `${{inputs.go-package}}` (default: `go`)
- `busybox`
- `ca-certificates-bundle`
- `git`

### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `package` | **Yes** | - | Import path to the package |
| `go-package` | No | `go` | The Go package to use |
| `version` | No | - | Package version (tag, commit, or `latest`) |
| `prefix` | No | `usr` | Installation prefix |
| `install-dir` | No | `bin` | Directory for installed binaries |
| `ldflags` | No | - | Linker flags |
| `strip` | No | `-w` | Strip flags |
| `tags` | No | - | Comma-separated build tags |
| `toolchaintags` | No | `netgo,osusergo` | Default toolchain build tags |
| `experiments` | No | `""` | Comma-separated Go experiment names |
| `amd64` | No | `v2` | GOAMD64 microarchitecture level |
| `arm64` | No | `v8.0` | GOARM64 microarchitecture level |

### Example Usage

Install a specific version:

```yaml
pipeline:
  - uses: go/install
    with:
      package: github.com/example/tool
      version: v1.2.3
```

Install latest version:

```yaml
pipeline:
  - uses: go/install
    with:
      package: github.com/example/tool
      version: latest
```

Install with custom ldflags:

```yaml
pipeline:
  - uses: go/install
    with:
      package: github.com/example/tool
      version: v${{package.version}}
      ldflags: -X main.version=${{package.version}}
```

Install from a specific commit:

```yaml
pipeline:
  - uses: go/install
    with:
      package: github.com/example/tool
      version: abc123def456
```

---

## go/bump

Update Go dependencies to specific versions using the `gobump` tool.

### Required Packages

- `git`
- `gobump`

### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `deps` | **Yes** | - | Space-separated dependencies to bump |
| `modroot` | No | `.` | Root directory of the Go module |
| `go-version` | No | `""` | Go version to set in go.mod syntax |
| `replaces` | No | - | Replace directives to add to go.mod |
| `tidy` | No | `true` | Run go mod tidy before and after bump |
| `show-diff` | No | `false` | Show diff of go.mod changes |
| `tidy-compat` | No | `""` | Go version for tidy compatibility |
| `work` | No | `false` | Use go work vendor instead of go mod vendor |

### Example Usage

Bump a single dependency:

```yaml
pipeline:
  - uses: go/bump
    with:
      deps: github.com/example/lib@v2.0.0
```

Bump multiple dependencies:

```yaml
pipeline:
  - uses: go/bump
    with:
      deps: |
        github.com/lib/a@v1.0.0
        github.com/lib/b@v2.0.0
```

With replace directives:

```yaml
pipeline:
  - uses: go/bump
    with:
      deps: github.com/example/lib@v1.5.0
      replaces: github.com/old/pkg=github.com/new/pkg@v1.0.0
```

Update Go version in go.mod:

```yaml
pipeline:
  - uses: go/bump
    with:
      deps: github.com/example/lib@v1.0.0
      go-version: "1.21"
```

---

## go/covdata

Get coverage data using the Go covdata tool.

### Required Packages

- `${{inputs.package}}` (default: `go`)
- `busybox`
- `jq`

### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `package` | No | `go` | The Go package to use |
| `cover-dir` | No | `/home/build` | GOCOVERDIR path with coverage data |

### Example Usage

```yaml
test:
  pipeline:
    - runs: |
        export GOCOVERDIR=/home/build
        ./myapp --run-tests
    - uses: go/covdata
      with:
        cover-dir: /home/build
```

---

## Complete Examples

### Standard CLI Application

```yaml
package:
  name: myapp
  version: 1.0.0

environment:
  contents:
    packages:
      - go
      - git

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/myapp.git
      tag: v${{package.version}}
      expected-commit: abc123...

  - uses: go/build
    with:
      packages: ./cmd/myapp
      output: myapp
      ldflags: |
        -X main.version=${{package.version}}
```

### Multi-Binary Project

```yaml
package:
  name: mytoolkit
  version: 2.0.0

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/toolkit.git
      tag: v${{package.version}}
      expected-commit: def456...

  - uses: go/build
    with:
      packages: ./cmd/server
      output: server
      tags: netgo

  - uses: go/build
    with:
      packages: ./cmd/cli
      output: cli
      tags: netgo

subpackages:
  - name: mytoolkit-server
    pipeline:
      - runs: |
          mkdir -p ${{targets.contextdir}}/usr/bin
          mv ${{targets.destdir}}/usr/bin/server ${{targets.contextdir}}/usr/bin/

  - name: mytoolkit-cli
    pipeline:
      - runs: |
          mkdir -p ${{targets.contextdir}}/usr/bin
          mv ${{targets.destdir}}/usr/bin/cli ${{targets.contextdir}}/usr/bin/
```

### With Dependency Updates

```yaml
package:
  name: myapp
  version: 1.0.0

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/myapp.git
      tag: v${{package.version}}
      expected-commit: abc123...

  - uses: go/bump
    with:
      deps: |
        golang.org/x/crypto@v0.17.0
        golang.org/x/net@v0.19.0

  - uses: go/build
    with:
      packages: .
      output: myapp
```
