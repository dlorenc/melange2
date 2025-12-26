# Melange BuildKit Refactor - Detailed Implementation Plan

## Executive Summary

Replace melange's runner implementations (bubblewrap, docker, qemu) with BuildKit as the sole execution backend. This document provides step-by-step implementation details with specific test criteria for each phase.

---

## Phase 0: Prototype Apko Image Loading (DO FIRST)

**Why first**: Loading apko-built OCI images into BuildKit is the trickiest part. Apko produces `v1.Layer` objects, but BuildKit expects either:
1. A registry reference (`llb.Image("...")`)
2. An OCI layout on disk (`llb.OCILayout(...)`)
3. A local filesystem (`llb.Local(...)`)

We need to prototype this before any other work.

### Step 0.1: Create Prototype Test File

**File**: `pkg/buildkit/apko_load_test.go`

**Approaches to prototype**:

1. **OCI Layout approach**:
   - Export apko layer to OCI layout format on disk
   - Use `llb.OCILayout()` to load it
   - This requires writing the image to disk first

2. **Scratch + Copy approach**:
   - Start with `llb.Scratch()`
   - Use `llb.Copy()` to copy the rootfs from a local directory
   - Requires extracting the apko layer to disk first

3. **Image store approach**:
   - Push apko image to a local registry or BuildKit's content store
   - Reference via `llb.Image()`

**Test Criteria for Phase 0**:
- [ ] Can connect to BuildKit running at `localhost:1234`
- [ ] Can load an apko-built image (alpine-base or minimal test image)
- [ ] Can run `echo hello` in the loaded image and get output
- [ ] Prototype works with testcontainers (no external BuildKit required)
- [ ] Document which approach works best and why

### Step 0.2: Understand Apko's Image Output

**Research needed**: In apko, images are built via `layer, err := bc.BuildLayer(ctx)` which returns `v1.Layer`. We need to understand the format and how to convert to OCI layout.

---

## Phase 1: Core BuildKit Client Package

### Step 1.1: Create Basic Client

**File**: `pkg/buildkit/client.go`

**Test Criteria**:
- [ ] `New()` connects to BuildKit at specified address
- [ ] `New()` returns clear error if BuildKit unreachable
- [ ] `Close()` cleanly disconnects
- [ ] `Ping()` returns nil when connected, error otherwise

### Step 1.2: Create Testcontainers Helper

**File**: `pkg/buildkit/testutil_test.go`

**Test Criteria**:
- [ ] `StartBuildKit()` starts container successfully
- [ ] Container is accessible at returned address
- [ ] Container is cleaned up after test

### Step 1.3: Implement Determinism Helpers

**File**: `pkg/buildkit/determinism.go`

**Test Criteria**:
- [ ] `SortedEnv` produces same output regardless of input map iteration order
- [ ] Running `SortedEnv` 1000 times with same input produces identical output each time
- [ ] `MergeEnv` correctly overrides earlier values with later ones

---

## Phase 2: Image Loading (Using Phase 0 Prototype)

### Step 2.1: Implement Image Loader

**File**: `pkg/buildkit/image.go`

**Test Criteria**:
- [ ] Can load a real apko-built layer
- [ ] Can run commands in the loaded image
- [ ] Temporary directories are cleaned up
- [ ] Works for both x86_64 and aarch64

---

## Phase 3: LLB Pipeline Builder

### Step 3.1: Single Pipeline to LLB

**File**: `pkg/buildkit/llb.go`

**Test Criteria**:
- [ ] Simple `runs: echo hello` produces correct LLB
- [ ] Pipeline with `if:` condition is skipped when false
- [ ] Environment variables are sorted (check via LLB inspection)
- [ ] Nested pipelines execute in order
- [ ] Custom `workdir` is respected

### Step 3.2: Full Build LLB (All Pipelines + Subpackages)

**Test Criteria**:
- [ ] Full build with main + subpackage pipelines works
- [ ] Workspace files are copied into container
- [ ] Output directories are created
- [ ] Subpackages run after main pipelines
- [ ] LLB is deterministic (same config = same digest)

---

## Phase 4: Build Integration

### Step 4.1: Update Build Struct
### Step 4.2: Update BuildPackage
### Step 4.3: Implement Workspace Export

**Test Criteria**:
- [ ] Workspace files are exported to correct location
- [ ] Only melange-out is exported (not entire rootfs)
- [ ] File permissions are preserved
- [ ] Symlinks are preserved

---

## Phase 5: CLI Updates

**Test Criteria**:
- [ ] `melange build --buildkit-addr tcp://localhost:1234 foo.yaml` works
- [ ] Default address works when BuildKit is running
- [ ] Clear error when BuildKit not available
- [ ] All wolfi-dev/os Makefile patterns still work

---

## Phase 6: Cleanup

### Files to delete:
- `pkg/container/bubblewrap_runner.go`
- `pkg/container/bubblewrap_runner_test.go`
- `pkg/container/qemu_runner.go`
- `pkg/container/qemu_runner_test.go`
- `pkg/container/docker/docker_runner.go`
- `pkg/container/docker/` (entire directory)
- `pkg/build/runner.go`

**Test Criteria**:
- [ ] `go build ./...` succeeds
- [ ] `go test ./...` passes
- [ ] No dead code warnings
- [ ] Binary size reduced

---

## Verification Checklist

### Phase 0 Complete When:
- [ ] Prototype test file exists and passes
- [ ] Documentation of chosen image loading approach
- [ ] Helper function for layer → OCI layout conversion

### Phase 1 Complete When:
- [ ] Can connect to BuildKit via testcontainers
- [ ] Determinism helpers have 100% test coverage
- [ ] All unit tests pass

### Phase 2 Complete When:
- [ ] Can load real apko image into BuildKit
- [ ] Can run commands in loaded image
- [ ] Integration test passes

### Phase 3 Complete When:
- [ ] Simple pipeline converts to correct LLB
- [ ] Nested pipelines work
- [ ] Subpackages work
- [ ] Determinism test passes (100 iterations)

### Phase 4 Complete When:
- [ ] `testdata/simple.yaml` builds successfully
- [ ] `testdata/with-subpackage.yaml` builds successfully
- [ ] `testdata/with-templating.yaml` builds successfully
- [ ] APK files are generated

### Phase 5 Complete When:
- [ ] CLI flags updated
- [ ] Help text accurate
- [ ] Error messages clear

### Phase 6 Complete When:
- [ ] Old runner code deleted
- [ ] `go build` succeeds
- [ ] `go test ./...` passes
- [ ] No unused dependencies

### Final Verification:
- [ ] Build 3 real wolfi packages successfully
- [ ] All tests pass in CI
- [ ] wolfi-dev/os Makefile works with new melange
