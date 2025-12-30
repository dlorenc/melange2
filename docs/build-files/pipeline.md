# Pipeline

The `pipeline` block defines the build steps to execute. Each step can run shell commands or invoke reusable pipelines.

## Basic Structure

```yaml
pipeline:
  - runs: |
      echo "Step 1"
  - runs: |
      echo "Step 2"
```

## Pipeline Step Types

### runs

Execute shell commands:

```yaml
pipeline:
  - runs: |
      mkdir -p "${{targets.destdir}}/usr/bin"
      cp myapp "${{targets.destdir}}/usr/bin/"
```

Commands are executed with `/bin/sh -c` in the build environment.

### uses

Invoke a reusable pipeline:

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/source.tar.gz
      expected-sha256: abc123...
```

### uses with with

Pass arguments to a reusable pipeline:

```yaml
pipeline:
  - uses: autoconf/configure
    with:
      opts: |
        --enable-ipv6 \
        --with-openssl \
        --disable-ldap
```

## Pipeline Step Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Optional user-defined name for the step |
| `uses` | string | Reusable pipeline to invoke |
| `with` | map[string]string | Arguments for the reusable pipeline |
| `runs` | string | Shell commands to execute |
| `if` | string | Conditional expression |
| `working-directory` | string | Working directory for the step |
| `pipeline` | []Pipeline | Nested pipeline steps |
| `needs` | Needs | Package dependencies for this step |
| `label` | string | Label for the step |
| `assertions` | PipelineAssertions | Assertions for nested pipelines |
| `environment` | map[string]string | Environment variable overrides |

## Conditional Execution

Use the `if` field to conditionally execute steps:

```yaml
pipeline:
  - if: ${{build.arch}} == 'x86_64'
    runs: |
      echo "Building for x86_64"

  - if: ${{build.arch}} == 'aarch64'
    runs: |
      echo "Building for aarch64"

  - if: ${{package.name}} == 'hello'
    runs: |
      echo "Package name is hello"
```

### Conditional Operators

| Operator | Example |
|----------|---------|
| `==` | `${{build.arch}} == 'x86_64'` |
| `!=` | `${{package.name}} != 'test'` |

### Conditional with uses

```yaml
pipeline:
  - uses: fetch
    if: ${{package.name}} != 'hello'
    with:
      uri: https://example.com/file.tar.gz
```

## Working Directory

Change the working directory for a step:

```yaml
pipeline:
  - working-directory: /home/build/foo
    runs: |
      echo "Current directory: $(pwd)"

  - working-directory: ${{vars.buildLocation}}
    runs: |
      make -C subdir
```

Default working directory is `/home/build`.

## Nested Pipelines

Create nested pipeline blocks:

```yaml
pipeline:
  - working-directory: /home/build/bar
    pipeline:
      - runs: |
          echo "Inherits working-directory from parent"
      - working-directory: /home/build/baz
        runs: |
          echo "Overrides working-directory"
```

Nested pipelines inherit `working-directory` and `environment` from their parent.

## Assertions

Validate that a certain number of steps executed:

```yaml
pipeline:
  - assertions:
      required-steps: 1
    pipeline:
      - if: ${{build.arch}} == 'x86_64'
        runs: |
          echo "x86_64 specific step"
      - if: ${{build.arch}} == 'aarch64'
        runs: |
          echo "aarch64 specific step"
```

This ensures at least one architecture-specific step runs.

## Named Steps

Give steps descriptive names:

```yaml
pipeline:
  - name: Download source
    uses: fetch
    with:
      uri: https://example.com/source.tar.gz

  - name: Configure build
    uses: autoconf/configure

  - name: Compile
    uses: autoconf/make

  - name: Install
    uses: autoconf/make-install
```

## Environment Overrides

Override environment variables for specific steps:

```yaml
pipeline:
  - runs: |
      echo "Default environment"
  - environment:
      CFLAGS: "-O3"
      DEBUG: "1"
    runs: |
      echo "Custom CFLAGS: $CFLAGS"
```

## Needs (Package Dependencies)

Specify packages required by a specific step:

```yaml
pipeline:
  - needs:
      packages:
        - go
    runs: |
      go build -o myapp
```

## Common Pipeline Patterns

### Fetch and Build

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/project-${{package.version}}.tar.gz
      expected-sha256: abc123...

  - uses: autoconf/configure

  - uses: autoconf/make

  - uses: autoconf/make-install

  - uses: strip
```

### Git Checkout and Build

```yaml
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/project.git
      tag: v${{package.version}}
      expected-commit: abc123...

  - uses: go/build
    with:
      packages: .
      output: myapp
```

### Multi-Stage Build

```yaml
pipeline:
  - name: Download dependencies
    uses: fetch
    with:
      uri: https://example.com/deps.tar.gz

  - name: Configure
    working-directory: /home/build/source
    runs: |
      ./configure --prefix=/usr

  - name: Build
    working-directory: /home/build/source
    runs: |
      make -j$(nproc)

  - name: Install
    working-directory: /home/build/source
    runs: |
      make install DESTDIR="${{targets.destdir}}"
```

## Built-in Pipelines

Melange includes many built-in pipelines in `pkg/build/pipelines/`:

| Pipeline | Description |
|----------|-------------|
| `fetch` | Download and extract archives |
| `git-checkout` | Clone git repositories |
| `autoconf/configure` | Run ./configure |
| `autoconf/make` | Run make |
| `autoconf/make-install` | Run make install |
| `cmake/configure` | CMake configuration |
| `cmake/build` | CMake build |
| `cmake/install` | CMake install |
| `go/build` | Build Go packages |
| `go/install` | Install Go packages |
| `strip` | Strip debug symbols |
| `split/dev` | Split development files |
| `split/manpages` | Split man pages |
| `split/bin` | Split binaries |

## Pipeline Struct Reference

From `pkg/config/config.go`:

```go
type Pipeline struct {
    If          string              `yaml:"if,omitempty"`
    Name        string              `yaml:"name,omitempty"`
    Uses        string              `yaml:"uses,omitempty"`
    With        map[string]string   `yaml:"with,omitempty"`
    Runs        string              `yaml:"runs,omitempty"`
    Pipeline    []Pipeline          `yaml:"pipeline,omitempty"`
    Inputs      map[string]Input    `yaml:"inputs,omitempty"`
    Needs       *Needs              `yaml:"needs,omitempty"`
    Label       string              `yaml:"label,omitempty"`
    Assertions  *PipelineAssertions `yaml:"assertions,omitempty"`
    WorkDir     string              `yaml:"working-directory,omitempty"`
    Environment map[string]string   `yaml:"environment,omitempty"`
}
```

## Validation Rules

The configuration parser enforces these rules:

1. A step cannot have both `uses` and `runs`
2. A step cannot have both `with` and `runs`
3. `with` requires `uses` to be set
4. Combining `uses` with nested `pipeline` generates a warning
