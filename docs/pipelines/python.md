# Python Pipelines

These pipelines provide support for building and installing Python packages.

## python/build

Build a Python package using `setup.py build`.

### Required Packages

- `busybox`
- `python3`

### Inputs

This pipeline has no configurable inputs.

### Build Behavior

- Verifies Python is installed
- Resolves Python symlinks to ensure correct interpreter
- Runs `python setup.py build`

### Example Usage

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/mypackage-${{package.version}}.tar.gz
      expected-sha256: abc123...

  - uses: python/build
```

**Note**: This pipeline uses the legacy `setup.py` build method. For modern Python packages, prefer `python/build-wheel`.

---

## python/build-wheel

Build and install a Python wheel using PEP 517 build system.

### Required Packages

- `busybox`
- `py3-build`
- `py3-installer`
- `python3`

### Inputs

This pipeline has no configurable inputs.

### Build Behavior

- Verifies Python 3 is installed
- Resolves Python symlinks to ensure correct interpreter
- Runs `python -m build` to create a wheel
- Installs the wheel using `python -m installer`
- Removes `.pyc` bytecode files from the output

### Example Usage

Basic wheel build:

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/mypackage-${{package.version}}.tar.gz
      expected-sha256: abc123...

  - uses: python/build-wheel
```

From git:

```yaml
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/mypackage.git
      tag: v${{package.version}}
      expected-commit: abc123...

  - uses: python/build-wheel
```

---

## python/install

Install a Python package using `setup.py install`.

### Required Packages

- `busybox`
- `python3`

### Inputs

This pipeline has no configurable inputs.

### Install Behavior

- Verifies Python is installed
- Resolves Python symlinks to ensure correct interpreter
- Runs `python setup.py install --prefix=/usr --root="${{targets.contextdir}}"`

### Example Usage

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/mypackage-${{package.version}}.tar.gz
      expected-sha256: abc123...

  - uses: python/build

  - uses: python/install
```

**Note**: This pipeline uses the legacy `setup.py` install method. For modern Python packages, prefer `python/build-wheel` which handles both build and install.

---

## python/import

Test that a Python package can be imported successfully.

### Required Packages

- `wolfi-base`

### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `python` | No | `DEFAULT` | Python interpreter to use |
| `import` | No | - | Single package to import (deprecated, use `imports`) |
| `from` | No | - | Package to import from (deprecated, use `imports`) |
| `imports` | No | - | Multi-line import commands to test |

### Import Formats

The `imports` input supports multiple formats:

```yaml
imports: |
  import mypackage
  from mypackage import submodule
  from mypackage.utils import helper  # inline comments supported
  # full line comments also supported
```

### Python Interpreter Selection

When `python` is set to `DEFAULT` (the default), the pipeline auto-detects the Python interpreter by looking for `/usr/bin/python3.[0-9][0-9]` or `/usr/bin/python3.[789]`. If multiple or no interpreters are found, it fails.

### Example Usage

Simple import test:

```yaml
test:
  pipeline:
    - uses: python/import
      with:
        imports: import mypackage
```

Multiple imports:

```yaml
test:
  pipeline:
    - uses: python/import
      with:
        imports: |
          import mypackage
          from mypackage import core
          from mypackage.utils import helper
```

With specific Python version:

```yaml
test:
  pipeline:
    - uses: python/import
      with:
        python: /usr/bin/python3.11
        imports: import mypackage
```

Legacy single import (deprecated):

```yaml
test:
  pipeline:
    - uses: python/import
      with:
        import: submodule
        from: mypackage
```

---

## python/test

Run a custom test command for a Python package.

### Required Packages

- `wolfi-base`

### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `command` | **Yes** | - | The test command to run |

### Example Usage

Run pytest:

```yaml
test:
  pipeline:
    - uses: python/test
      with:
        command: pytest -v tests/
```

Run custom test script:

```yaml
test:
  pipeline:
    - uses: python/test
      with:
        command: python -m mypackage.tests
```

---

## Complete Examples

### Modern Python Package (PEP 517)

```yaml
package:
  name: py3-mypackage
  version: 1.0.0

environment:
  contents:
    packages:
      - python3
      - py3-build
      - py3-installer

pipeline:
  - uses: fetch
    with:
      uri: https://pypi.io/packages/source/m/mypackage/mypackage-${{package.version}}.tar.gz
      expected-sha256: abc123...

  - uses: python/build-wheel

test:
  pipeline:
    - uses: python/import
      with:
        imports: |
          import mypackage
          from mypackage import core
```

### Legacy Python Package (setup.py)

```yaml
package:
  name: py3-legacypackage
  version: 2.0.0

environment:
  contents:
    packages:
      - python3
      - py3-setuptools

pipeline:
  - uses: fetch
    with:
      uri: https://example.com/legacypackage-${{package.version}}.tar.gz
      expected-sha256: def456...

  - uses: python/build

  - uses: python/install

test:
  pipeline:
    - uses: python/import
      with:
        imports: import legacypackage
```

### Package with Native Extensions

```yaml
package:
  name: py3-nativeext
  version: 3.0.0

environment:
  contents:
    packages:
      - python3
      - python3-dev
      - py3-build
      - py3-installer
      - build-base

pipeline:
  - uses: fetch
    with:
      uri: https://example.com/nativeext-${{package.version}}.tar.gz
      expected-sha256: ghi789...

  - uses: python/build-wheel

test:
  pipeline:
    - uses: python/import
      with:
        imports: import nativeext
    - uses: python/test
      with:
        command: pytest tests/ -v
```

### Package from Git with Tests

```yaml
package:
  name: py3-gitpackage
  version: 1.5.0

environment:
  contents:
    packages:
      - python3
      - py3-build
      - py3-installer
      - py3-pytest

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/gitpackage.git
      tag: v${{package.version}}
      expected-commit: abc123...

  - uses: python/build-wheel

test:
  pipeline:
    - uses: python/import
      with:
        imports: |
          import gitpackage
          from gitpackage import api
          from gitpackage.utils import helpers
    - uses: python/test
      with:
        command: pytest -xvs tests/
```
