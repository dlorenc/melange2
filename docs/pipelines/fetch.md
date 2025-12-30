# Source Fetching Pipelines

These pipelines handle downloading and preparing source code for building.

## fetch

Fetch and extract external objects (tarballs) into the workspace.

### Required Packages

- `wget`

### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `uri` | **Yes** | - | The URI to fetch as an artifact |
| `expected-sha256` | No | - | The expected SHA256 checksum of the downloaded artifact |
| `expected-sha512` | No | - | The expected SHA512 checksum of the downloaded artifact |
| `expected-none` | No | - | Set to skip checksum validation (not recommended) |
| `extract` | No | `true` | Whether to extract the downloaded artifact as a source tarball |
| `strip-components` | No | `1` | Number of path components to strip while extracting |
| `directory` | No | `.` | Directory to extract the artifact into (passed to `tar -C`) |
| `delete` | No | `false` | Whether to delete the fetched artifact after unpacking |
| `timeout` | No | `5` | Timeout in seconds for connecting and reading |
| `dns-timeout` | No | `20` | Timeout in seconds for DNS lookups |
| `retry-limit` | No | `5` | Number of times to retry fetching before failing |
| `purl-name` | No | `${{package.name}}` | Package-URL (PURL) name for SPDX SBOM External References |
| `purl-version` | No | `${{package.version}}` | Package-URL (PURL) version for SPDX SBOM External References |

**Note**: Either `expected-sha256` or `expected-sha512` must be provided unless `expected-none` is set.

### Example Usage

Basic tarball fetch:

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://github.com/example/project/archive/v${{package.version}}.tar.gz
      expected-sha256: abc123def456...
```

Fetch without extraction:

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/binary-tool
      expected-sha256: abc123def456...
      extract: false
```

Extract to a specific directory:

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/source.tar.gz
      expected-sha256: abc123def456...
      directory: vendor/
      strip-components: 0
```

---

## git-checkout

Check out sources from a git repository.

### Required Packages

- `git`

### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `repository` | **Yes** | - | The repository URL to clone |
| `destination` | No | `.` | Path to check out the sources to |
| `depth` | No | `unset` | Clone depth (`-1` for full history, `1` for shallow) |
| `branch` | No | - | Branch to check out (mutually exclusive with `tag`) |
| `tag` | No | - | Tag to check out (mutually exclusive with `branch`) |
| `expected-commit` | No | - | Expected commit hash for verification |
| `recurse-submodules` | No | `false` | Whether to recurse into submodules |
| `cherry-picks` | No | - | List of cherry picks to apply (see format below) |
| `sparse-paths` | No | - | List of directory paths for sparse checkout |
| `type-hint` | No | - | Type hint for SBOM generation (`gitlab` supported) |

### Depth Behavior

- If `depth` is `unset` and both `branch` and `expected-commit` are provided, defaults to `-1` (full history)
- Otherwise defaults to `1` (shallow clone)
- Use `-1` explicitly for full branch history

### Cherry-Picks Format

```yaml
cherry-picks: |
  branch/commit-id: comment explaining cherry-pick
  3.10/62705d869aca4055e8a96e2ed4f9013e9917c661: backport fix
```

Each line format: `[branch/]commit-id: comment`
- Comments after `#` are ignored
- Empty lines are allowed
- Branch prefix helps git find the commit reference

### Example Usage

Basic tag checkout:

```yaml
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/project.git
      tag: v${{package.version}}
      expected-commit: abc123def456...
```

Branch checkout with full history:

```yaml
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/project.git
      branch: main
      expected-commit: abc123def456...
      depth: -1
```

With submodules:

```yaml
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/project.git
      tag: v${{package.version}}
      expected-commit: abc123def456...
      recurse-submodules: true
```

Sparse checkout for monorepos:

```yaml
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/monorepo.git
      tag: v${{package.version}}
      expected-commit: abc123def456...
      sparse-paths: |
        packages/mypackage
        shared/lib
```

With cherry-picks:

```yaml
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/project.git
      tag: v${{package.version}}
      expected-commit: abc123def456...
      cherry-picks: |
        main/deadbeef12345: fix critical security issue
        release-1.0/cafebabe6789: backport performance fix
```

---

## patch

Apply patches to source code.

### Required Packages

- `patch`

### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `patches` | No | - | Whitespace-delimited list of patch files to apply |
| `series` | No | - | A quilt-style patch series file to apply |
| `strip-components` | No | `1` | Number of path components to strip |
| `fuzz` | No | `2` | Maximum fuzz factor for context diffs |

**Note**: Either `patches` or `series` must be provided.

### Example Usage

Apply individual patches:

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/source.tar.gz
      expected-sha256: abc123...

  - uses: patch
    with:
      patches: |
        fix-build.patch
        add-feature.patch
```

Using a series file:

```yaml
pipeline:
  - uses: fetch
    with:
      uri: https://example.com/source.tar.gz
      expected-sha256: abc123...

  - uses: patch
    with:
      series: patches/series
```

With custom strip components:

```yaml
pipeline:
  - uses: patch
    with:
      patches: vendor-fix.patch
      strip-components: 2
```
