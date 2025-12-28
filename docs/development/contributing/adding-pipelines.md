# Adding Built-in Pipelines

This guide explains how to add new built-in pipelines to melange2.

## Pipeline Structure

Pipelines are YAML files in `pkg/build/pipelines/`:

```
pkg/build/pipelines/
├── fetch.yaml
├── git-checkout.yaml
├── go/
│   ├── build.yaml
│   ├── install.yaml
│   └── bump.yaml
├── python/
│   ├── build.yaml
│   └── install.yaml
└── your-category/
    └── your-pipeline.yaml
```

## Creating a Pipeline

### 1. Create the YAML File

Create `pkg/build/pipelines/category/name.yaml`:

```yaml
name: Pipeline display name

needs:
  packages:
    - required-package-1
    - required-package-2

inputs:
  required-input:
    description: A required input parameter
    required: true

  optional-input:
    description: An optional parameter with default
    default: "default-value"

pipeline:
  - runs: |
      # Use inputs with ${{inputs.input-name}}
      echo "Building with ${{inputs.required-input}}"

      # Use package variables
      echo "Package: ${{package.name}} v${{package.version}}"

      # Write to output directory
      install -Dm755 output ${{targets.destdir}}/usr/bin/output
```

### 2. Define Inputs

| Field | Description |
|-------|-------------|
| `description` | Help text for the input |
| `required` | If true, must be provided |
| `default` | Default value if not provided |

### 3. Define Needs

Packages required to run the pipeline:

```yaml
needs:
  packages:
    - go           # Go compiler
    - build-base   # Build tools
```

### 4. Write the Pipeline

Use standard melange pipeline syntax:

```yaml
pipeline:
  - name: Configure
    runs: |
      ./configure --prefix=/usr

  - name: Build
    runs: |
      make -j$(nproc)

  - name: Install
    runs: |
      make DESTDIR=${{targets.destdir}} install
```

## Example: CMake Pipeline

```yaml
# pkg/build/pipelines/cmake/build.yaml
name: CMake build

needs:
  packages:
    - cmake
    - make
    - build-base

inputs:
  source-dir:
    description: Source directory containing CMakeLists.txt
    default: "."

  build-dir:
    description: Build directory
    default: "build"

  opts:
    description: Additional CMake options
    default: ""

pipeline:
  - name: Configure
    runs: |
      cmake -B ${{inputs.build-dir}} \
            -S ${{inputs.source-dir}} \
            -DCMAKE_INSTALL_PREFIX=/usr \
            -DCMAKE_BUILD_TYPE=Release \
            ${{inputs.opts}}

  - name: Build
    runs: |
      cmake --build ${{inputs.build-dir}} -j$(nproc)

  - name: Install
    runs: |
      DESTDIR=${{targets.destdir}} cmake --install ${{inputs.build-dir}}
```

## Using Your Pipeline

In a build file:

```yaml
pipeline:
  - uses: cmake/build
    with:
      source-dir: src
      opts: -DENABLE_FEATURE=ON
```

## Testing Your Pipeline

### 1. Build melange2 with Your Changes

```bash
go build -o melange2 .
```

### 2. Create a Test Package

```yaml
# test-package.yaml
package:
  name: test-new-pipeline
  version: 1.0.0
  epoch: 0
  description: "Test new pipeline"
  copyright:
    - license: MIT

environment:
  contents:
    packages:
      - busybox

pipeline:
  - uses: your-category/your-pipeline
    with:
      required-input: test-value
```

### 3. Build and Verify

```bash
./melange2 build test-package.yaml --buildkit-addr tcp://localhost:1234 --debug
```

### 4. Add E2E Test

Create `pkg/buildkit/testdata/e2e/XX-your-pipeline.yaml` and add a test in `e2e_test.go`.

## Best Practices

1. **Keep pipelines focused** - One task per pipeline
2. **Use meaningful defaults** - Common cases should "just work"
3. **Document inputs** - Clear descriptions help users
4. **Handle errors** - Use `set -e` in shell scripts
5. **Be deterministic** - Avoid timestamps, random values
6. **Test thoroughly** - Add E2E tests for your pipeline

## README Generation

Pipeline READMEs are auto-generated. After adding a pipeline, the build process will update the README in that directory.

## Submitting

1. Create a branch
2. Add your pipeline
3. Add tests
4. Create a PR with:
   - Description of the pipeline
   - Example usage
   - Test results
