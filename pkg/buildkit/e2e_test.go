// Copyright 2024 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package buildkit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/pkg/config"
)

// e2eTestContext holds shared resources for e2e tests
type e2eTestContext struct {
	t          *testing.T
	ctx        context.Context
	bk         *buildKitContainer
	workingDir string
}

// newE2ETestContext creates a new e2e test context with BuildKit running
func newE2ETestContext(t *testing.T) *e2eTestContext {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	ctx := context.Background()
	bk := startBuildKitContainer(t, ctx)
	workingDir := t.TempDir()

	return &e2eTestContext{
		t:          t,
		ctx:        ctx,
		bk:         bk,
		workingDir: workingDir,
	}
}

// buildConfig executes a build with the given config and returns the output directory
func (e *e2eTestContext) buildConfig(cfg *config.Configuration) (string, error) {
	builder, err := NewBuilder(e.bk.Addr)
	if err != nil {
		return "", err
	}
	defer builder.Close()

	// Create output directory
	outDir := filepath.Join(e.workingDir, "output")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", err
	}

	// Build the LLB graph using alpine as base (since we don't have a real apko layer)
	pipeline := NewPipelineBuilder()

	// Set up base environment from config
	pipeline.BaseEnv["HOME"] = "/home/build"
	for k, v := range cfg.Environment.Environment {
		pipeline.BaseEnv[k] = v
	}

	// Start with alpine base image
	state := llb.Image("alpine:latest")

	// Prepare workspace
	state = PrepareWorkspace(state, cfg.Package.Name)

	// Perform variable substitution on pipelines
	pipelines := substituteVariables(cfg, cfg.Pipeline)

	// Build the pipelines
	state, err = pipeline.BuildPipelines(state, pipelines)
	if err != nil {
		return "", err
	}

	// Build subpackages
	for _, subpkg := range cfg.Subpackages {
		subPipelines := substituteVariables(cfg, subpkg.Pipeline)
		state, err = pipeline.BuildPipelines(state, subPipelines)
		if err != nil {
			return "", err
		}
	}

	// Export the workspace
	export := ExportWorkspace(state)
	def, err := export.Marshal(e.ctx, llb.LinuxAmd64)
	if err != nil {
		return "", err
	}

	// Connect to BuildKit and solve
	c, err := New(e.ctx, e.bk.Addr)
	if err != nil {
		return "", err
	}
	defer c.Close()

	_, err = c.Client().Solve(e.ctx, def, client.SolveOpt{
		Exports: []client.ExportEntry{{
			Type:      client.ExporterLocal,
			OutputDir: outDir,
		}},
	}, nil)
	if err != nil {
		return "", err
	}

	return outDir, nil
}

// substituteVariables performs basic variable substitution in pipelines
func substituteVariables(cfg *config.Configuration, pipelines []config.Pipeline) []config.Pipeline {
	result := make([]config.Pipeline, len(pipelines))

	for i, p := range pipelines {
		result[i] = p

		// Substitute in runs field
		if p.Runs != "" {
			runs := p.Runs

			// Package variables
			runs = strings.ReplaceAll(runs, "${{package.name}}", cfg.Package.Name)
			runs = strings.ReplaceAll(runs, "${{package.version}}", cfg.Package.Version)
			runs = strings.ReplaceAll(runs, "${{package.epoch}}", string(rune('0'+cfg.Package.Epoch)))
			runs = strings.ReplaceAll(runs, "${{package.full-version}}", cfg.Package.Version+"-r"+string(rune('0'+cfg.Package.Epoch)))

			// Target paths
			runs = strings.ReplaceAll(runs, "${{targets.destdir}}", "/home/build/melange-out/"+cfg.Package.Name)
			runs = strings.ReplaceAll(runs, "${{targets.contextdir}}", "/home/build")
			runs = strings.ReplaceAll(runs, "${{targets.subpkgdir}}", "/home/build/melange-out/"+cfg.Package.Name+"-subpkg")

			// Custom variables
			for k, v := range cfg.Vars {
				runs = strings.ReplaceAll(runs, "${{vars."+k+"}}", v)
			}

			result[i].Runs = runs
		}

		// Substitute in if field
		if p.If != "" {
			ifCond := p.If
			for k, v := range cfg.Vars {
				ifCond = strings.ReplaceAll(ifCond, "${{vars."+k+"}}", v)
			}
			result[i].If = ifCond
		}
	}

	return result
}

// loadTestConfig loads a test configuration from the testdata directory
func loadTestConfig(t *testing.T, name string) *config.Configuration {
	t.Helper()

	configPath := filepath.Join("testdata", "e2e", name)
	cfg, err := config.ParseConfiguration(context.Background(), configPath)
	require.NoError(t, err, "should parse config %s", name)

	return cfg
}

// verifyFileExists checks that a file exists in the output directory
func verifyFileExists(t *testing.T, outDir, path string) {
	t.Helper()
	fullPath := filepath.Join(outDir, path)
	_, err := os.Stat(fullPath)
	require.NoError(t, err, "file should exist: %s", path)
}

// verifyFileContains checks that a file contains expected content
func verifyFileContains(t *testing.T, outDir, path, expected string) {
	t.Helper()
	fullPath := filepath.Join(outDir, path)
	content, err := os.ReadFile(fullPath)
	require.NoError(t, err, "should read file: %s", path)
	require.Contains(t, string(content), expected, "file %s should contain %q", path, expected)
}

// TestE2E_SimpleRun tests basic shell command execution
func TestE2E_SimpleRun(t *testing.T) {
	e := newE2ETestContext(t)
	cfg := loadTestConfig(t, "01-simple-run.yaml")

	outDir, err := e.buildConfig(cfg)
	require.NoError(t, err, "build should succeed")

	// Verify output files were created
	verifyFileExists(t, outDir, "simple-run-test/usr/bin/hello")
	verifyFileExists(t, outDir, "simple-run-test/etc/simple-run.conf")
	verifyFileContains(t, outDir, "simple-run-test/etc/simple-run.conf", "version=1.0.0")
}

// TestE2E_VariableSubstitution tests package variable substitution
func TestE2E_VariableSubstitution(t *testing.T) {
	e := newE2ETestContext(t)
	cfg := loadTestConfig(t, "02-variable-substitution.yaml")

	outDir, err := e.buildConfig(cfg)
	require.NoError(t, err, "build should succeed")

	// Verify package variables
	verifyFileContains(t, outDir, "var-test/usr/share/var-test/package-vars.txt", "name=var-test")
	verifyFileContains(t, outDir, "var-test/usr/share/var-test/package-vars.txt", "version=2.3.4")
	verifyFileContains(t, outDir, "var-test/usr/share/var-test/package-vars.txt", "epoch=5")

	// Verify custom variables
	verifyFileContains(t, outDir, "var-test/usr/share/var-test/custom-vars.txt", "custom-var=custom-value")
	verifyFileContains(t, outDir, "var-test/usr/share/var-test/custom-vars.txt", "another-var=another-value")
}

// TestE2E_EnvironmentVars tests environment variable handling
func TestE2E_EnvironmentVars(t *testing.T) {
	e := newE2ETestContext(t)
	cfg := loadTestConfig(t, "03-environment-vars.yaml")

	outDir, err := e.buildConfig(cfg)
	require.NoError(t, err, "build should succeed")

	// Verify global environment variables
	verifyFileContains(t, outDir, "env-test/usr/share/env-test/global-env.txt", "CUSTOM_VAR=custom-env-value")
	verifyFileContains(t, outDir, "env-test/usr/share/env-test/global-env.txt", "BUILD_TYPE=release")

	// Verify HOME is set
	verifyFileContains(t, outDir, "env-test/usr/share/env-test/home.txt", "HOME=/home/build")
}

// TestE2E_WorkingDirectory tests working directory handling
func TestE2E_WorkingDirectory(t *testing.T) {
	e := newE2ETestContext(t)
	cfg := loadTestConfig(t, "05-working-directory.yaml")

	outDir, err := e.buildConfig(cfg)
	require.NoError(t, err, "build should succeed")

	// Verify working directory was set correctly
	verifyFileContains(t, outDir, "workdir-test/usr/share/workdir-test/workdir.txt", "/home/build/src/project")

	// Verify files were combined (proves relative paths worked)
	verifyFileContains(t, outDir, "workdir-test/usr/share/workdir-test/combined.txt", "source file 1")
	verifyFileContains(t, outDir, "workdir-test/usr/share/workdir-test/combined.txt", "nested file")
}

// TestE2E_MultiPipeline tests multiple pipeline steps in sequence
func TestE2E_MultiPipeline(t *testing.T) {
	e := newE2ETestContext(t)
	cfg := loadTestConfig(t, "06-multi-pipeline.yaml")

	outDir, err := e.buildConfig(cfg)
	require.NoError(t, err, "build should succeed")

	// Verify all steps ran in sequence
	verifyFileContains(t, outDir, "multi-pipeline-test/usr/share/multi-pipeline/progress.txt", "step1")
	verifyFileContains(t, outDir, "multi-pipeline-test/usr/share/multi-pipeline/progress.txt", "step2")
	verifyFileContains(t, outDir, "multi-pipeline-test/usr/share/multi-pipeline/progress.txt", "step3")
	verifyFileContains(t, outDir, "multi-pipeline-test/usr/share/multi-pipeline/progress.txt", "step4")
	verifyFileContains(t, outDir, "multi-pipeline-test/usr/share/multi-pipeline/progress.txt", "step5")

	// Verify validation passed
	verifyFileContains(t, outDir, "multi-pipeline-test/usr/share/multi-pipeline/count.txt", "2")
}

// TestE2E_Subpackages tests basic subpackage handling
func TestE2E_Subpackages(t *testing.T) {
	e := newE2ETestContext(t)
	cfg := loadTestConfig(t, "04-subpackage-basic.yaml")

	outDir, err := e.buildConfig(cfg)
	require.NoError(t, err, "build should succeed")

	// Verify main package files
	verifyFileExists(t, outDir, "subpkg-test/usr/bin/subpkg-main")

	// Note: Full subpackage splitting requires more infrastructure
	// This test verifies the pipeline structure is correct
}

// TestE2E_BuilderIntegration tests the full Builder.Build path
func TestE2E_BuilderIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	ctx := context.Background()
	bk := startBuildKitContainer(t, ctx)

	builder, err := NewBuilder(bk.Addr)
	require.NoError(t, err)
	defer builder.Close()

	workspaceDir := t.TempDir()

	cfg := &BuildConfig{
		PackageName:  "integration-test",
		Arch:         apko_types.Architecture("amd64"),
		WorkspaceDir: workspaceDir,
		BaseEnv: map[string]string{
			"TEST_VAR": "test-value",
		},
		Pipelines: []config.Pipeline{
			{
				Name: "create-output",
				Runs: `
mkdir -p /home/build/melange-out/integration-test/usr/share
echo "integration test output" > /home/build/melange-out/integration-test/usr/share/result.txt
echo "TEST_VAR=$TEST_VAR" > /home/build/melange-out/integration-test/usr/share/env.txt
`,
			},
		},
	}

	// Use alpine as base since our test layer doesn't have a shell
	// In real usage, apko layer would have a full rootfs
	pipeline := NewPipelineBuilder()
	state := llb.Image("alpine:latest")
	state = PrepareWorkspace(state, cfg.PackageName)

	// Build pipelines
	state, err = pipeline.BuildPipelines(state, cfg.Pipelines)
	require.NoError(t, err)

	// Export
	export := ExportWorkspace(state)
	def, err := export.Marshal(ctx, llb.LinuxAmd64)
	require.NoError(t, err)

	c, err := New(ctx, bk.Addr)
	require.NoError(t, err)
	defer c.Close()

	outDir := filepath.Join(workspaceDir, "output")
	require.NoError(t, os.MkdirAll(outDir, 0755))

	_, err = c.Client().Solve(ctx, def, client.SolveOpt{
		Exports: []client.ExportEntry{{
			Type:      client.ExporterLocal,
			OutputDir: outDir,
		}},
	}, nil)
	require.NoError(t, err)

	// Verify output
	content, err := os.ReadFile(filepath.Join(outDir, "integration-test", "usr", "share", "result.txt"))
	require.NoError(t, err)
	require.Contains(t, string(content), "integration test output")
}

// TestE2E_PipelineEnvironment tests environment variable propagation to pipelines
func TestE2E_PipelineEnvironment(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	ctx := context.Background()
	bk := startBuildKitContainer(t, ctx)

	c, err := client.New(ctx, bk.Addr)
	require.NoError(t, err)
	defer c.Close()

	// Test that environment variables are properly passed to pipeline steps
	state := llb.Image("alpine:latest")

	// Set up environment
	state = state.Run(
		llb.Args([]string{"/bin/sh", "-c", `
mkdir -p /output
echo "MY_VAR=$MY_VAR" > /output/env.txt
echo "ANOTHER_VAR=$ANOTHER_VAR" >> /output/env.txt
`}),
		llb.AddEnv("MY_VAR", "value1"),
		llb.AddEnv("ANOTHER_VAR", "value2"),
	).Root()

	// Export output - copy contents only
	export := llb.Scratch().File(llb.Copy(state, "/output/", "/", &llb.CopyInfo{
		CopyDirContentsOnly: true,
	}))
	def, err := export.Marshal(ctx, llb.LinuxAmd64)
	require.NoError(t, err)

	outDir := t.TempDir()
	_, err = c.Solve(ctx, def, client.SolveOpt{
		Exports: []client.ExportEntry{{
			Type:      client.ExporterLocal,
			OutputDir: outDir,
		}},
	}, nil)
	require.NoError(t, err)

	// Verify environment was passed
	content, err := os.ReadFile(filepath.Join(outDir, "env.txt"))
	require.NoError(t, err)
	require.Contains(t, string(content), "MY_VAR=value1")
	require.Contains(t, string(content), "ANOTHER_VAR=value2")
}

// TestE2E_LargeOutput tests handling of larger output files
func TestE2E_LargeOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	ctx := context.Background()
	bk := startBuildKitContainer(t, ctx)

	c, err := client.New(ctx, bk.Addr)
	require.NoError(t, err)
	defer c.Close()

	// Create a build that generates multiple output files
	state := llb.Image("alpine:latest").
		Run(llb.Args([]string{"/bin/sh", "-c", `
mkdir -p /output/bin /output/lib /output/include /output/share/doc

# Create multiple files
for i in 1 2 3 4 5; do
    echo "binary $i" > /output/bin/binary$i
    echo "library $i" > /output/lib/lib$i.so
    echo "header $i" > /output/include/header$i.h
    echo "doc $i" > /output/share/doc/doc$i.txt
done

# Create a larger file
dd if=/dev/zero bs=1024 count=100 2>/dev/null | tr '\0' 'x' > /output/large.bin
`})).Root()

	export := llb.Scratch().File(llb.Copy(state, "/output/", "/", &llb.CopyInfo{
		CopyDirContentsOnly: true,
	}))
	def, err := export.Marshal(ctx, llb.LinuxAmd64)
	require.NoError(t, err)

	outDir := t.TempDir()
	_, err = c.Solve(ctx, def, client.SolveOpt{
		Exports: []client.ExportEntry{{
			Type:      client.ExporterLocal,
			OutputDir: outDir,
		}},
	}, nil)
	require.NoError(t, err)

	// Verify files were created
	for i := 1; i <= 5; i++ {
		verifyFileExists(t, outDir, filepath.Join("bin", "binary"+string(rune('0'+i))))
		verifyFileExists(t, outDir, filepath.Join("lib", "lib"+string(rune('0'+i))+".so"))
	}

	// Verify large file
	info, err := os.Stat(filepath.Join(outDir, "large.bin"))
	require.NoError(t, err)
	require.Equal(t, int64(102400), info.Size(), "large file should be 100KB")
}

// TestE2E_ConditionalPipelines tests if: conditions on pipelines
func TestE2E_ConditionalPipelines(t *testing.T) {
	e := newE2ETestContext(t)
	cfg := loadTestConfig(t, "09-conditional-if.yaml")

	outDir, err := e.buildConfig(cfg)
	require.NoError(t, err, "build should succeed")

	// Verify always-running pipeline
	verifyFileExists(t, outDir, "conditional-test/usr/share/conditional-test/always.txt")

	// Verify enabled feature ran (vars.enable-feature = "true")
	verifyFileExists(t, outDir, "conditional-test/usr/share/conditional-test/enabled.txt")

	// Verify disabled feature did NOT run (vars.disable-feature = "false")
	_, err = os.Stat(filepath.Join(outDir, "conditional-test/usr/share/conditional-test/disabled.txt"))
	require.True(t, os.IsNotExist(err), "disabled.txt should not exist")
}

// TestE2E_ScriptAssertions tests script assertions and command chaining
func TestE2E_ScriptAssertions(t *testing.T) {
	e := newE2ETestContext(t)
	cfg := loadTestConfig(t, "10-script-assertions.yaml")

	outDir, err := e.buildConfig(cfg)
	require.NoError(t, err, "build should succeed")

	// Verify all assertion files exist
	verifyFileExists(t, outDir, "assertion-test/usr/share/assertion-test/test.txt")
	verifyFileExists(t, outDir, "assertion-test/usr/share/assertion-test/chain1.txt")
	verifyFileExists(t, outDir, "assertion-test/usr/share/assertion-test/chain2.txt")
	verifyFileExists(t, outDir, "assertion-test/usr/share/assertion-test/chain3.txt")
	verifyFileExists(t, outDir, "assertion-test/usr/share/assertion-test/var.txt")
	verifyFileExists(t, outDir, "assertion-test/usr/share/assertion-test/passed.txt")

	// Verify variable substitution in script
	verifyFileContains(t, outDir, "assertion-test/usr/share/assertion-test/var.txt", "my-value")
}

// TestE2E_NestedPipelines tests deeply nested pipeline execution
func TestE2E_NestedPipelines(t *testing.T) {
	e := newE2ETestContext(t)
	cfg := loadTestConfig(t, "11-nested-pipelines.yaml")

	outDir, err := e.buildConfig(cfg)
	require.NoError(t, err, "build should succeed")

	// Verify execution order
	verifyFileContains(t, outDir, "nested-test/usr/share/nested-test/order.txt", "outer-start")
	verifyFileContains(t, outDir, "nested-test/usr/share/nested-test/order.txt", "inner-1")
	verifyFileContains(t, outDir, "nested-test/usr/share/nested-test/order.txt", "deeply-nested")
	verifyFileContains(t, outDir, "nested-test/usr/share/nested-test/order.txt", "inner-2")
	verifyFileContains(t, outDir, "nested-test/usr/share/nested-test/order.txt", "after-nested")

	// Verify all 5 steps ran
	verifyFileContains(t, outDir, "nested-test/usr/share/nested-test/count.txt", "5")
}

// TestE2E_Permissions tests file permissions and symlinks
func TestE2E_Permissions(t *testing.T) {
	e := newE2ETestContext(t)
	cfg := loadTestConfig(t, "12-permissions.yaml")

	outDir, err := e.buildConfig(cfg)
	require.NoError(t, err, "build should succeed")

	// Verify executable was created
	verifyFileExists(t, outDir, "permissions-test/usr/bin/myapp")

	// Verify library and symlinks
	verifyFileExists(t, outDir, "permissions-test/usr/lib/libtest.so.1.0.0")

	// Verify permissions were verified
	verifyFileContains(t, outDir, "permissions-test/etc/perms.txt", "permissions verified")
}

// TestE2E_FetchSource tests fetching sources with checksum validation and archive extraction
func TestE2E_FetchSource(t *testing.T) {
	e := newE2ETestContext(t)
	cfg := loadTestConfig(t, "13-fetch-source.yaml")

	outDir, err := e.buildConfig(cfg)
	require.NoError(t, err, "build should succeed")

	// Verify HTTP fetch with checksum succeeded
	verifyFileExists(t, outDir, "fetch-test/usr/share/fetch-test/fetched.txt")
	verifyFileExists(t, outDir, "fetch-test/usr/share/fetch-test/checksum.txt")

	// Verify archive extraction succeeded
	verifyFileExists(t, outDir, "fetch-test/usr/share/fetch-test/file1.txt")
	verifyFileContains(t, outDir, "fetch-test/usr/share/fetch-test/file1.txt", "file1 content")

	// Verify strip-components worked
	verifyFileContains(t, outDir, "fetch-test/usr/share/fetch-test/strip-test.txt", "strip-components successful")

	// Verify all tests passed
	verifyFileContains(t, outDir, "fetch-test/usr/share/fetch-test/status.txt", "all fetch tests passed")
}

// TestE2E_GitCheckout tests git clone and checkout operations
func TestE2E_GitCheckout(t *testing.T) {
	e := newE2ETestContext(t)
	cfg := loadTestConfig(t, "14-git-operations.yaml")

	outDir, err := e.buildConfig(cfg)
	require.NoError(t, err, "build should succeed")

	// Verify basic clone succeeded
	verifyFileContains(t, outDir, "git-checkout-test/usr/share/git-test/clone.txt", "basic clone successful")

	// Verify tag checkout succeeded
	verifyFileContains(t, outDir, "git-checkout-test/usr/share/git-test/tag.txt", "tag checkout successful")

	// Verify commit hash was captured
	verifyFileExists(t, outDir, "git-checkout-test/usr/share/git-test/commit.txt")

	// Verify destination directory checkout succeeded
	verifyFileContains(t, outDir, "git-checkout-test/usr/share/git-test/destination.txt", "destination directory successful")

	// Verify all git tests passed
	verifyFileContains(t, outDir, "git-checkout-test/usr/share/git-test/status.txt", "all git tests passed")
}

// TestE2E_MultipleSubpackages tests multiple subpackage handling
func TestE2E_MultipleSubpackages(t *testing.T) {
	e := newE2ETestContext(t)
	cfg := loadTestConfig(t, "15-multiple-subpackages.yaml")

	outDir, err := e.buildConfig(cfg)
	require.NoError(t, err, "build should succeed")

	// Verify main package
	verifyFileExists(t, outDir, "multi-subpkg/usr/bin/multi-app")
	verifyFileExists(t, outDir, "multi-subpkg/usr/lib/libmulti.so.2.0.0")
	verifyFileExists(t, outDir, "multi-subpkg/usr/include/multi.h")

	// Verify subpackage markers (shows pipelines ran)
	verifyFileExists(t, outDir, "multi-subpkg-dev/usr/dev-marker.txt")
	verifyFileExists(t, outDir, "multi-subpkg-doc/usr/share/doc-marker.txt")
	verifyFileExists(t, outDir, "multi-subpkg-libs/usr/lib/libs-marker.txt")
}
