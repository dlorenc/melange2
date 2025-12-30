# Pipelines

Pipelines are reusable build steps that encapsulate common build patterns. melange2 includes a comprehensive set of built-in pipelines for fetching sources, building with various build systems, and packaging software.

## How Pipelines Work

Pipelines are defined in YAML files and can be invoked using the `uses:` syntax within your package build file. Each pipeline accepts inputs that customize its behavior and may require specific packages to be available.

### Basic Syntax

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/source.tar.gz
      expected-sha256: abc123...
```

### Pipeline Structure

Each built-in pipeline has:

- **name**: A descriptive name for the pipeline
- **needs.packages**: List of packages required for the pipeline to run
- **inputs**: Configuration parameters with descriptions and defaults
- **pipeline**: The actual build steps to execute

### Variable Substitution

Pipelines support variable substitution using the `${{...}}` syntax:

| Variable | Description |
|----------|-------------|
| `${{package.name}}` | Package name |
| `${{package.version}}` | Package version |
| `${{targets.destdir}}` | Main package output directory |
| `${{targets.contextdir}}` | Current subpackage output directory |
| `${{targets.outdir}}` | Parent directory of all package outputs |
| `${{build.arch}}` | Target architecture |
| `${{host.triplet.gnu}}` | GNU triplet for the host system |
| `${{vars.custom}}` | Custom variables defined in your build file |
| `${{inputs.param}}` | Pipeline input parameter |

### Combining Multiple Pipelines

You can chain multiple pipelines together in a single build:

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/source.tar.gz
      expected-sha256: abc123...

  - uses: autoconf/configure
    with:
      opts: --enable-feature

  - uses: autoconf/make

  - uses: autoconf/make-install

  - uses: strip
```

### Custom Commands

In addition to pipelines, you can run custom shell commands:

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/source.tar.gz
      expected-sha256: abc123...

  - runs: |
      # Custom build commands
      ./custom-build.sh
      install -Dm755 mybinary ${{targets.contextdir}}/usr/bin/mybinary
```

## Available Pipelines

### Source Fetching

| Pipeline | Description |
|----------|-------------|
| [fetch](fetch.md#fetch) | Download and extract tarballs |
| [git-checkout](fetch.md#git-checkout) | Clone git repositories |
| [patch](fetch.md#patch) | Apply patches to source code |

### Build Systems

| Pipeline | Description |
|----------|-------------|
| [autoconf/configure](build-systems.md#autoconfconfigure) | Run autoconf configure scripts |
| [autoconf/make](build-systems.md#autoconfmake) | Build with make |
| [autoconf/make-install](build-systems.md#autoconfmake-install) | Install with make |
| [cmake/configure](build-systems.md#cmakeconfigure) | Configure CMake projects |
| [cmake/build](build-systems.md#cmakebuild) | Build CMake projects |
| [cmake/install](build-systems.md#cmakeinstall) | Install CMake projects |
| [meson/configure](build-systems.md#mesonconfigure) | Configure Meson projects |
| [meson/compile](build-systems.md#mesoncompile) | Build Meson projects |
| [meson/install](build-systems.md#mesoninstall) | Install Meson projects |

### Language-Specific

| Pipeline | Description |
|----------|-------------|
| [go/build](go.md#gobuild) | Build Go projects |
| [go/install](go.md#goinstall) | Install Go packages |
| [go/bump](go.md#gobump) | Update Go dependencies |
| [python/build](python.md#pythonbuild) | Build Python packages (setup.py) |
| [python/build-wheel](python.md#pythonbuild-wheel) | Build and install Python wheels |
| [python/install](python.md#pythoninstall) | Install Python packages |
| [cargo/build](rust.md#cargobuild) | Build Rust projects with cargo |

### Other Languages and Tools

| Pipeline | Description |
|----------|-------------|
| [npm/install](other.md#npminstall) | Install npm packages |
| [ruby/build](other.md#rubybuild) | Build Ruby gems |
| [ruby/install](other.md#rubyinstall) | Install Ruby gems |
| [perl/make](other.md#perlmake) | Create Makefile for Perl modules |
| [maven/pombump](other.md#mavenpombump) | Update Maven POM dependencies |
| [R/build](other.md#rbuild) | Build R packages |

### Utilities

| Pipeline | Description |
|----------|-------------|
| [strip](other.md#strip) | Strip debug symbols from binaries |
| [split/dev](other.md#splitdev) | Split development files into subpackage |
| [split/static](other.md#splitstatic) | Split static libraries into subpackage |
| [split/manpages](other.md#splitmanpages) | Split man pages into subpackage |
| [split/debug](other.md#splitdebug) | Split debug symbols into subpackage |

## Creating Custom Pipelines

While built-in pipelines cover most use cases, you can also define inline pipelines using the `runs:` directive:

```yaml
pipeline:
  - runs: |
      cd src
      make PREFIX=/usr
      make DESTDIR=${{targets.contextdir}} install
```

For more complex reusable build logic, consider contributing a new built-in pipeline to melange2.
