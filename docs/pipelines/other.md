# Other Pipelines

This page documents pipelines for additional languages, tools, and utilities.

## npm/install

Install a portable npm package globally.

### Required Packages

- `busybox`
- `nodejs`
- `${{inputs.npm-package}}` (default: `npm`)
- `npm`

### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `package` | **Yes** | - | Name of the npm package to install |
| `version` | **Yes** | - | Version of the package to install |
| `prefix` | No | `${{targets.contextdir}}/usr/` | Installation prefix for bin and lib |
| `overrides` | No | - | Space/comma/newline-separated package@version overrides |
| `npm-package` | No | `npm` | Package manager to use (`npm` or `pnpm`) |

### Override Vulnerabilities

The `overrides` input allows replacing vulnerable transitive dependencies:

```yaml
overrides: |
  yargs@^17.0.0
  get-stdin@^9.0.0
```

### Example Usage

Basic installation:

```yaml
pipeline:
  - uses: npm/install
    with:
      package: typescript
      version: 5.3.0
```

With security overrides:

```yaml
pipeline:
  - uses: npm/install
    with:
      package: some-package
      version: 1.0.0
      overrides: |
        vulnerable-dep@^2.0.0
        another-dep@^1.5.0
```

Using pnpm:

```yaml
pipeline:
  - uses: npm/install
    with:
      package: mypackage
      version: 2.0.0
      npm-package: pnpm
```

---

## Ruby Pipelines

### ruby/build

Build a Ruby gem from a gemspec.

#### Required Packages

- `busybox`
- `ca-certificates-bundle`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `gem` | **Yes** | - | Gem name (expects `{gem}.gemspec` file) |
| `dir` | No | `.` | Working directory |
| `output` | No | - | Custom output filename for the gem |
| `opts` | No | - | Additional options for `gem build` |

#### Build Behavior

- Automatically removes `signing_key` from gemspec (not available in build environment)
- Runs `gem build {gem}.gemspec`

#### Example Usage

```yaml
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/mygem.git
      tag: v${{package.version}}
      expected-commit: abc123...

  - uses: ruby/build
    with:
      gem: mygem
```

---

### ruby/install

Install a Ruby gem.

#### Required Packages

- `busybox`
- `ca-certificates-bundle`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `version` | **Yes** | - | Gem version to install |
| `gem` | No | - | Gem name (uses `{gem}-{version}.gem`) |
| `gem-file` | No | - | Full filename of the gem file |
| `dir` | No | `.` | Working directory |
| `opts` | No | `''` | Additional options for `gem install` |

**Note**: Either `gem` or `gem-file` must be provided.

#### Install Behavior

- Installs to Ruby's default gem directory
- Uses `--ignore-dependencies --no-document --local`
- Creates bin directory at `/usr/bin`

#### Example Usage

Install after building:

```yaml
pipeline:
  - uses: ruby/build
    with:
      gem: mygem

  - uses: ruby/install
    with:
      gem: mygem
      version: ${{package.version}}
```

Install from gem file:

```yaml
pipeline:
  - uses: ruby/install
    with:
      gem-file: vendor/mygem-1.0.0.gem
      version: 1.0.0
```

---

### ruby/clean

Clean up Ruby gem installation artifacts.

#### Required Packages

- `busybox`
- `ca-certificates-bundle`

#### Inputs

This pipeline has no configurable inputs.

#### Clean Behavior

Removes from the gem installation directory:
- `build_info/`
- `cache/`
- `gem_make.out` files
- `mkmf.log` files

#### Example Usage

```yaml
pipeline:
  - uses: ruby/build
    with:
      gem: mygem

  - uses: ruby/install
    with:
      gem: mygem
      version: ${{package.version}}

  - uses: ruby/clean
```

---

## Perl Pipelines

### perl/make

Create a Makefile for a Perl module using `Makefile.PL`.

#### Required Packages

- `busybox`
- `perl`

#### Inputs

This pipeline has no configurable inputs.

#### Build Behavior

- Sets `PERL_CFLAGS` from Perl configuration
- Runs `perl -I. Makefile.PL INSTALLDIRS=vendor`

#### Example Usage

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://cpan.metacpan.org/authors/.../Module-1.0.tar.gz
      expected-sha256: abc123...

  - uses: perl/make

  - uses: autoconf/make

  - uses: autoconf/make-install
```

---

### perl/cleanup

Clean up Perl installation artifacts.

#### Required Packages

- `busybox`

#### Inputs

This pipeline has no configurable inputs.

#### Clean Behavior

Removes from the context directory:
- `perllocal.pod` files
- `.packlist` files

#### Example Usage

```yaml
pipeline:
  - uses: perl/make
  - uses: autoconf/make
  - uses: autoconf/make-install
  - uses: perl/cleanup
```

---

## PHP/PECL Pipelines

### pecl/phpize

Run phpize and configure a PHP PECL module.

#### Required Packages

- `autoconf`
- `busybox`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `php-config` | No | `php-config` | php-config command to use |
| `prefix` | No | `/usr` | Configure prefix |

#### Example Usage

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://pecl.php.net/get/extension-1.0.0.tgz
      expected-sha256: abc123...

  - uses: pecl/phpize

  - uses: autoconf/make

  - uses: pecl/install
    with:
      extension: myextension
```

---

### pecl/install

Install and enable a PHP PECL module.

#### Required Packages

- `automake`
- `busybox`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `extension` | **Yes** | - | Name of the PECL extension |

#### Install Behavior

- Runs `make INSTALL_ROOT="${{targets.contextdir}}" install`
- Creates `/etc/php/conf.d/{extension}.ini` to enable the extension

#### Example Usage

```yaml
pipeline:
  - uses: pecl/install
    with:
      extension: redis
```

---

## Maven Pipelines

### maven/configure-mirror

Configure GCP Maven Central mirror for faster downloads.

#### Required Packages

- `busybox`

#### Inputs

This pipeline has no configurable inputs.

#### Behavior

Creates `/root/.m2/settings.xml` with Google Cloud Storage Maven Central mirror.

#### Example Usage

```yaml
pipeline:
  - uses: maven/configure-mirror

  - runs: mvn package -DskipTests
```

---

### maven/pombump

Update versions and properties in Maven POM files using `pombump`.

#### Required Packages

- `busybox`
- `pombump`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `pom` | No | `pom.xml` | Path to pom.xml |
| `patch-file` | No | `./pombump-deps.yaml` | YAML file with dependency patches |
| `properties-file` | No | `./pombump-properties.yaml` | YAML file with property updates |
| `dependencies` | No | - | Dependencies via command line |
| `properties` | No | - | Properties via command line |
| `debug` | No | `false` | Print diff of pom.xml changes |
| `show-dependency-tree` | No | `false` | Display dependency tree before changes |

#### Example Usage

Using patch files:

```yaml
pipeline:
  - uses: maven/pombump
```

With inline dependencies:

```yaml
pipeline:
  - uses: maven/pombump
    with:
      dependencies: "com.example:lib:2.0.0"
      properties: "java.version=17"
      debug: true
```

---

## R Pipeline

### R/build

Build and install an R package from source.

#### Required Packages

- `R`
- `R-dev`
- `R-doc`
- `busybox`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `package` | **Yes** | - | R package name |
| `version` | **Yes** | - | R package version |
| `path` | No | `.` | Path to R package source or tarball |

#### Example Usage

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://cran.r-project.org/src/contrib/mypackage_${{package.version}}.tar.gz
      expected-sha256: abc123...

  - uses: R/build
    with:
      package: mypackage
      version: ${{package.version}}
```

---

## Utility Pipelines

### strip

Strip debug symbols from binaries to reduce size.

#### Required Packages

- `binutils`
- `scanelf`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `opts` | No | `-g` | Flags to pass to the strip command |

#### Behavior

- Uses `scanelf` to find ELF binaries (ET_DYN and ET_EXEC)
- Skips standalone binaries
- Ensures file is writable before stripping

#### Example Usage

Default stripping (debug symbols only):

```yaml
pipeline:
  - uses: autoconf/make-install
  - uses: strip
```

Full stripping:

```yaml
pipeline:
  - uses: strip
    with:
      opts: --strip-all
```

---

## Split Pipelines

These pipelines help split package contents into subpackages.

### split/dev

Split development files (headers, pkg-config, static libs) into a -dev subpackage.

#### Required Packages

- `busybox`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `package` | No | - | Source package to split from |

#### Files Moved

- `usr/include/`
- `usr/lib/pkgconfig/`
- `usr/share/pkgconfig/`
- `usr/share/aclocal/`
- `usr/bin/*-config`, `usr/bin/*_config`
- `usr/share/vala/vapi/`
- `usr/share/gir-[0-9]*`
- `usr/share/cmake/`, `usr/lib/cmake/`
- `usr/lib/qt*/mkspecs/`, `usr/share/qt*/mkspecs/`
- `*.a` (static libraries)
- `*.h`, `*.c`, `*.o`, `*.prl` files
- `*.so` symlinks (for linking)

#### Example Usage

```yaml
subpackages:
  - name: mylib-dev
    pipeline:
      - uses: split/dev
    dependencies:
      runtime:
        - mylib
```

---

### split/static

Split static library files (.a) into a -static subpackage.

#### Required Packages

- `busybox`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `package` | No | - | Source package to split from |

#### Example Usage

```yaml
subpackages:
  - name: mylib-static
    pipeline:
      - uses: split/static
```

---

### split/manpages

Split man pages into a -doc subpackage.

#### Required Packages

- `busybox`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `package` | No | - | Source package to split from |

#### Directories Searched

- `usr/share/man/`
- `usr/local/share/man/`
- `usr/man/`

#### Example Usage

```yaml
subpackages:
  - name: myapp-doc
    pipeline:
      - uses: split/manpages
```

---

### split/infodir

Split GNU info pages into a subpackage.

#### Required Packages

- `busybox`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `package` | No | - | Source package to split from |

#### Example Usage

```yaml
subpackages:
  - name: myapp-info
    pipeline:
      - uses: split/infodir
```

---

### split/locales

Split locale/translation files into a -lang subpackage.

#### Required Packages

- `busybox`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `package` | No | - | Source package to split from |

#### Example Usage

```yaml
subpackages:
  - name: myapp-lang
    pipeline:
      - uses: split/locales
```

---

### split/debug

Split debug symbols into a -dbg subpackage.

#### Required Packages

- `binutils`
- `busybox`
- `scanelf`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `package` | No | - | Source package to split from |

#### Behavior

- Uses `objcopy --only-keep-debug` to extract debug info
- Creates `.debug` files in `/usr/lib/debug/`
- Adds debug link to original binary

#### Example Usage

```yaml
subpackages:
  - name: myapp-dbg
    pipeline:
      - uses: split/debug
```

---

### split/bin

Split executable files from usr/bin into a -bin subpackage.

#### Required Packages

- `busybox`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `package` | No | - | Source package to split from |

#### Example Usage

```yaml
subpackages:
  - name: mylib-bin
    pipeline:
      - uses: split/bin
```

---

### split/lib

Split shared library files into a -libs subpackage.

#### Required Packages

- `busybox`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `package` | No | - | Source package to split from |
| `patterns` | No | - | Newline-separated library name patterns |
| `paths` | No | - | Additional paths to search for libraries |

#### Example Usage

Split all shared libraries:

```yaml
subpackages:
  - name: myapp-libs
    pipeline:
      - uses: split/lib
```

Split specific libraries:

```yaml
subpackages:
  - name: libssl-libs
    pipeline:
      - uses: split/lib
        with:
          patterns: |
            ssl
            crypto
```

---

### split/alldocs

Split all documentation (man pages, info, docs) into a -doc subpackage.

#### Required Packages

- `busybox`

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `package` | No | - | Source package to split from |

#### Directories Moved

- Man pages from `usr/share/man/`, `usr/local/share/man/`, `usr/man/`
- Info pages from `usr/share/info/`
- Documentation from `usr/share/doc/`, `usr/local/share/doc/`

#### Example Usage

```yaml
subpackages:
  - name: myapp-doc
    pipeline:
      - uses: split/alldocs
```

---

## Coverage Pipelines

### llvm/covreport

Generate coverage report using LLVM tools.

#### Required Packages

- `${{inputs.package}}` (default: `llvm-19`)

#### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `package` | No | `llvm-19` | LLVM package to use |
| `object` | No | `""` | Path to coverage executable |
| `ignore-filename-regex` | No | `""` | Regex to exclude files from report |

### xcover Pipelines

The xcover pipelines provide function-level coverage profiling:

- **xcover/profile** - Start coverage profiling
- **xcover/wait** - Wait for profiler to be ready
- **xcover/status** - Check profiler status
- **xcover/stop** - Stop profiling
- **xcover/ensure** - Verify minimum coverage threshold

See the pipeline YAML files for detailed input documentation.
