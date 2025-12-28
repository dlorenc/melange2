# Python Pipelines

melange provides built-in pipelines for building Python packages.

## python/build

Build a Python wheel:

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://pypi.io/packages/source/m/mypackage/mypackage-${{package.version}}.tar.gz
      expected-sha256: abc123...

  - uses: python/build
```

## python/install

Install a built wheel:

```yaml
pipeline:
  - uses: python/build
  - uses: python/install
```

## python/import

Test that a Python package can be imported:

```yaml
test:
  pipeline:
    - uses: python/import
      with:
        imports: |
          import mypackage
          from mypackage import submodule
```

### Inputs

| Input | Required | Description |
|-------|----------|-------------|
| `imports` | No | Import statements to test (one per line) |
| `python` | No | Python interpreter to use |

## python/test

Run Python tests:

```yaml
test:
  pipeline:
    - uses: python/test
      with:
        command: pytest tests/
```

### Inputs

| Input | Required | Description |
|-------|----------|-------------|
| `command` | Yes | Test command to run |

## Complete Example

```yaml
package:
  name: py3-requests
  version: 2.31.0
  epoch: 0
  description: "Python HTTP library"
  copyright:
    - license: Apache-2.0

environment:
  contents:
    repositories:
      - https://packages.wolfi.dev/os
    keyring:
      - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
    packages:
      - python-3
      - py3-pip
      - py3-setuptools
      - py3-wheel

pipeline:
  - uses: fetch
    with:
      uri: https://files.pythonhosted.org/packages/source/r/requests/requests-${{package.version}}.tar.gz
      expected-sha256: 942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1

  - uses: python/build

  - uses: python/install

subpackages:
  - name: py3-requests-doc
    description: "Documentation for py3-requests"
    pipeline:
      - uses: split/manpages

test:
  environment:
    contents:
      packages:
        - python-3
  pipeline:
    - uses: python/import
      with:
        imports: |
          import requests
          from requests import Session
```

## Cache Mounts

BuildKit automatically caches:

- `/root/.cache/pip` - pip download cache

This persists between builds for faster dependency resolution.

## Common Patterns

### With Build Dependencies

```yaml
environment:
  contents:
    packages:
      - python-3-dev
      - py3-pip
      - py3-setuptools
      - py3-wheel
      - build-base  # For packages with C extensions
```

### Multiple Python Versions

```yaml
vars:
  py-version: "3.11"

environment:
  contents:
    packages:
      - python-${{vars.py-version}}
      - py${{vars.py-version}}-pip
```

### Testing Imports

```yaml
test:
  environment:
    contents:
      packages:
        - python-3
        - busybox
  pipeline:
    - uses: python/import
      with:
        imports: |
          import mypackage
          # Test submodules
          from mypackage.core import main
          from mypackage.utils import helper
```
