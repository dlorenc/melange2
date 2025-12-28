# Go Pipelines

melange provides built-in pipelines for building Go projects.

## go/build

Compile Go packages with `go build`:

```yaml
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/org/repo
      tag: v${{package.version}}
      expected-commit: abc123...

  - uses: go/build
    with:
      packages: ./cmd/myapp
      output: myapp
```

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `packages` | Yes | - | Packages to compile (passed to `go build`) |
| `output` | Yes | - | Output binary name |
| `modroot` | No | `.` | Directory containing go.mod |
| `prefix` | No | `usr` | Install prefix |
| `install-dir` | No | `bin` | Directory under prefix for binaries |
| `tags` | No | - | Build tags (comma-separated) |
| `ldflags` | No | - | Linker flags |
| `deps` | No | - | Dependencies to update before building |
| `vendor` | No | `false` | Run `go mod vendor` |
| `tidy` | No | `false` | Run `go mod tidy` |

### Example: Full Build

```yaml
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/app
      tag: v${{package.version}}

  - uses: go/build
    with:
      packages: ./cmd/app
      output: app
      tags: netgo,osusergo
      ldflags: |
        -X main.version=${{package.version}}
        -X main.commit=${{package.epoch}}
```

## go/install

Install packages directly with `go install`:

```yaml
pipeline:
  - uses: go/install
    with:
      package: github.com/example/tool
      version: v${{package.version}}
```

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `package` | Yes | - | Import path of the package |
| `version` | No | - | Version to install (tag, commit, or `latest`) |
| `prefix` | No | `usr` | Install prefix |
| `install-dir` | No | `bin` | Directory under prefix for binaries |
| `tags` | No | - | Build tags |
| `ldflags` | No | - | Linker flags |

### Example: Simple Install

```yaml
package:
  name: mytool
  version: 1.0.0

pipeline:
  - uses: go/install
    with:
      package: github.com/example/mytool
      version: v${{package.version}}
```

## go/bump

Update Go dependencies:

```yaml
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/app
      tag: v${{package.version}}

  - uses: go/bump
    with:
      deps: github.com/sirupsen/logrus@v1.9.3

  - uses: go/build
    with:
      packages: .
      output: app
```

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `deps` | Yes | - | Space-separated dependencies to update |
| `modroot` | No | `.` | Directory containing go.mod |
| `replaces` | No | - | Replace directives to add |
| `tidy` | No | `true` | Run `go mod tidy` |
| `work` | No | `false` | Use `go work vendor` for workspaces |

## Environment Variables

The Go pipelines automatically set:

- `GOPATH=/home/build/go`
- `GOCACHE` for build caching
- `CGO_ENABLED=0` (can be overridden)

Override in your build file:

```yaml
environment:
  environment:
    CGO_ENABLED: "1"
```

## Cache Mounts

BuildKit automatically caches:

- `/go/pkg/mod` - Go module cache
- `/root/.cache/go-build` - Go build cache

These persist between builds for faster compilation.

## Common Patterns

### Multiple Binaries

```yaml
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/multi-binary
      tag: v${{package.version}}

  - uses: go/build
    with:
      packages: ./cmd/app1
      output: app1

  - uses: go/build
    with:
      packages: ./cmd/app2
      output: app2
```

### With CGO

```yaml
environment:
  contents:
    packages:
      - build-base
      - go
  environment:
    CGO_ENABLED: "1"

pipeline:
  - uses: go/build
    with:
      packages: .
      output: myapp
      tags: cgo
```

### Vendored Dependencies

```yaml
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/vendored
      tag: v${{package.version}}

  - uses: go/build
    with:
      packages: .
      output: myapp
      vendor: true
```
