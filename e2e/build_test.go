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

package e2e

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/e2e/harness"
	"github.com/dlorenc/melange2/pkg/buildkit"
	"github.com/dlorenc/melange2/pkg/config"
)

// buildTestContext holds shared resources for build tests.
type buildTestContext struct {
	t       *testing.T
	h       *harness.Harness
	ctx     context.Context
	outDir  string
}

// newBuildTestContext creates a new build test context with BuildKit running.
func newBuildTestContext(t *testing.T) *buildTestContext {
	t.Helper()

	h := harness.New(t)

	outDir := filepath.Join(h.TempDir(), "output")
	require.NoError(t, os.MkdirAll(outDir, 0755))

	return &buildTestContext{
		t:      t,
		h:      h,
		ctx:    h.Context(),
		outDir: outDir,
	}
}

// loadConfig loads a test configuration from the fixtures directory.
func (c *buildTestContext) loadConfig(name string) *config.Configuration {
	c.t.Helper()

	configPath := filepath.Join("fixtures", "build", name)
	cfg, err := config.ParseConfiguration(c.ctx, configPath)
	require.NoError(c.t, err, "should parse config %s", name)

	return cfg
}

// buildConfig builds a configuration and returns the output directory.
func (c *buildTestContext) buildConfig(cfg *config.Configuration) string {
	c.t.Helper()

	// Create a unique output directory for this build
	buildOutDir := filepath.Join(c.outDir, cfg.Package.Name)
	require.NoError(c.t, os.MkdirAll(buildOutDir, 0755))

	// Build pipeline
	pipeline := buildkit.NewPipelineBuilder()
	pipeline.BaseEnv["HOME"] = "/home/build"
	for k, v := range cfg.Environment.Environment {
		pipeline.BaseEnv[k] = v
	}

	// Start with base image
	state := llb.Image(harness.TestBaseImage)
	state = buildkit.SetupBuildUser(state)
	state = buildkit.PrepareWorkspace(state, cfg.Package.Name)

	// Create subpackage output directories
	for _, sp := range cfg.Subpackages {
		state = state.File(
			llb.Mkdir(buildkit.WorkspaceOutputDir(sp.Name), 0755,
				llb.WithParents(true),
				llb.WithUIDGID(buildkit.BuildUserUID, buildkit.BuildUserGID),
			),
			llb.WithCustomName("create output directory for "+sp.Name),
		)
	}

	// Substitute variables and build main pipelines
	pipelines := substituteVars(cfg, cfg.Pipeline, "")
	var err error
	state, err = pipeline.BuildPipelines(state, pipelines)
	require.NoError(c.t, err)

	// Build subpackage pipelines
	for _, sp := range cfg.Subpackages {
		subPipelines := substituteVars(cfg, sp.Pipeline, sp.Name)
		state, err = pipeline.BuildPipelines(state, subPipelines)
		require.NoError(c.t, err)
	}

	// Export workspace
	export := buildkit.ExportWorkspace(state)
	def, err := export.Marshal(c.ctx, llb.LinuxAmd64)
	require.NoError(c.t, err)

	// Solve
	bkClient, err := buildkit.New(c.ctx, c.h.BuildKitAddr())
	require.NoError(c.t, err)
	defer bkClient.Close()

	_, err = bkClient.Client().Solve(c.ctx, def, client.SolveOpt{
		Exports: []client.ExportEntry{{
			Type:      client.ExporterLocal,
			OutputDir: buildOutDir,
		}},
	}, nil)
	require.NoError(c.t, err)

	return buildOutDir
}

// substituteVars performs variable substitution on pipelines.
func substituteVars(cfg *config.Configuration, pipelines []config.Pipeline, subpkgName string) []config.Pipeline {
	result := make([]config.Pipeline, len(pipelines))

	for i, p := range pipelines {
		result[i] = p

		if p.Runs != "" {
			runs := p.Runs

			// Package variables
			runs = replaceAll(runs, "${{package.name}}", cfg.Package.Name)
			runs = replaceAll(runs, "${{package.version}}", cfg.Package.Version)
			runs = replaceAll(runs, "${{package.epoch}}", epochString(cfg.Package.Epoch))
			runs = replaceAll(runs, "${{package.full-version}}", fullVersion(cfg))

			// Target paths
			runs = replaceAll(runs, "${{targets.destdir}}", "/home/build/melange-out/"+cfg.Package.Name)
			runs = replaceAll(runs, "${{targets.contextdir}}", "/home/build")

			// Subpackage output directory
			if subpkgName != "" {
				runs = replaceAll(runs, "${{targets.subpkgdir}}", "/home/build/melange-out/"+subpkgName)
			}

			// Custom variables
			for k, v := range cfg.Vars {
				runs = replaceAll(runs, "${{vars."+k+"}}", v)
			}

			result[i].Runs = runs
		}

		// Substitute in if field
		if p.If != "" {
			ifCond := p.If
			for k, v := range cfg.Vars {
				ifCond = replaceAll(ifCond, "${{vars."+k+"}}", v)
			}
			result[i].If = ifCond
		}
	}

	return result
}

func replaceAll(s, old, new string) string {
	for {
		updated := replaceOnce(s, old, new)
		if updated == s {
			return s
		}
		s = updated
	}
}

func replaceOnce(s, old, new string) string {
	i := indexOf(s, old)
	if i < 0 {
		return s
	}
	return s[:i] + new + s[i+len(old):]
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func epochString(epoch uint64) string {
	return string(rune('0' + epoch))
}

func fullVersion(cfg *config.Configuration) string {
	return cfg.Package.Version + "-r" + epochString(cfg.Package.Epoch)
}

// =============================================================================
// Build Tests
// =============================================================================

func TestBuild_Simple(t *testing.T) {
	c := newBuildTestContext(t)
	cfg := c.loadConfig("simple.yaml")

	outDir := c.buildConfig(cfg)

	harness.FileExists(t, outDir, "simple-test/usr/bin/hello")
	harness.FileExists(t, outDir, "simple-test/etc/simple.conf")
	harness.FileContains(t, outDir, "simple-test/etc/simple.conf", "version=1.0.0")
}

func TestBuild_Variables(t *testing.T) {
	c := newBuildTestContext(t)
	cfg := c.loadConfig("variables.yaml")

	outDir := c.buildConfig(cfg)

	// Package variables
	harness.FileContains(t, outDir, "var-test/usr/share/var-test/package-vars.txt", "name=var-test")
	harness.FileContains(t, outDir, "var-test/usr/share/var-test/package-vars.txt", "version=2.3.4")
	harness.FileContains(t, outDir, "var-test/usr/share/var-test/package-vars.txt", "epoch=5")

	// Custom variables
	harness.FileContains(t, outDir, "var-test/usr/share/var-test/custom-vars.txt", "custom-var=custom-value")
	harness.FileContains(t, outDir, "var-test/usr/share/var-test/custom-vars.txt", "another-var=another-value")
}

func TestBuild_Environment(t *testing.T) {
	c := newBuildTestContext(t)
	cfg := c.loadConfig("environment.yaml")

	outDir := c.buildConfig(cfg)

	// Global environment variables
	harness.FileContains(t, outDir, "env-test/usr/share/env-test/global-env.txt", "CUSTOM_VAR=custom-env-value")
	harness.FileContains(t, outDir, "env-test/usr/share/env-test/global-env.txt", "BUILD_TYPE=release")

	// HOME should be set
	harness.FileContains(t, outDir, "env-test/usr/share/env-test/home.txt", "HOME=/home/build")
}

func TestBuild_WorkingDirectory(t *testing.T) {
	c := newBuildTestContext(t)
	cfg := c.loadConfig("workdir.yaml")

	outDir := c.buildConfig(cfg)

	// Verify working directory was set correctly
	harness.FileContains(t, outDir, "workdir-test/usr/share/workdir-test/workdir.txt", "/home/build/src/project")

	// Verify files were combined (proves relative paths worked)
	harness.FileContains(t, outDir, "workdir-test/usr/share/workdir-test/combined.txt", "source file 1")
	harness.FileContains(t, outDir, "workdir-test/usr/share/workdir-test/combined.txt", "nested file")
}

func TestBuild_MultiPipeline(t *testing.T) {
	c := newBuildTestContext(t)
	cfg := c.loadConfig("multi-pipeline.yaml")

	outDir := c.buildConfig(cfg)

	// Verify all steps ran in sequence
	harness.FileContains(t, outDir, "multi-pipeline-test/usr/share/multi-pipeline/progress.txt", "step1")
	harness.FileContains(t, outDir, "multi-pipeline-test/usr/share/multi-pipeline/progress.txt", "step2")
	harness.FileContains(t, outDir, "multi-pipeline-test/usr/share/multi-pipeline/progress.txt", "step3")
	harness.FileContains(t, outDir, "multi-pipeline-test/usr/share/multi-pipeline/progress.txt", "step4")
	harness.FileContains(t, outDir, "multi-pipeline-test/usr/share/multi-pipeline/progress.txt", "step5")

	// Count should be 5
	harness.FileContains(t, outDir, "multi-pipeline-test/usr/share/multi-pipeline/count.txt", "5")
}

func TestBuild_Conditional(t *testing.T) {
	c := newBuildTestContext(t)
	cfg := c.loadConfig("conditional.yaml")

	outDir := c.buildConfig(cfg)

	// Always-running pipeline should run
	harness.FileExists(t, outDir, "conditional-test/usr/share/conditional-test/always.txt")

	// Enabled feature should run (vars.enable-feature = "true")
	harness.FileExists(t, outDir, "conditional-test/usr/share/conditional-test/enabled.txt")

	// Disabled feature should NOT run (vars.disable-feature = "false")
	harness.FileNotExists(t, outDir, "conditional-test/usr/share/conditional-test/disabled.txt")
}

func TestBuild_Subpackages(t *testing.T) {
	c := newBuildTestContext(t)
	cfg := c.loadConfig("subpackages.yaml")

	outDir := c.buildConfig(cfg)

	// Main package files
	harness.FileExists(t, outDir, "multi-subpkg/usr/bin/multi-app")
	harness.FileExists(t, outDir, "multi-subpkg/usr/lib/libmulti.so.2.0.0")
	harness.FileExists(t, outDir, "multi-subpkg/usr/include/multi.h")

	// Subpackage markers (shows pipelines ran)
	harness.FileExists(t, outDir, "multi-subpkg-dev/usr/dev-marker.txt")
	harness.FileExists(t, outDir, "multi-subpkg-doc/usr/share/doc-marker.txt")
	harness.FileExists(t, outDir, "multi-subpkg-libs/usr/lib/libs-marker.txt")
}

// TestBuild_FullIntegration tests the full build path through the Build struct.
func TestBuild_FullIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	h := harness.New(t)
	ctx := h.Context()

	// Create a simple config inline
	cfg := &buildkit.BuildConfig{
		PackageName: "integration-test",
		Arch:        apko_types.Architecture("amd64"),
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

	pipeline := buildkit.NewPipelineBuilder()
	pipeline.BaseEnv = cfg.BaseEnv

	state := llb.Image(harness.TestBaseImage)
	state = buildkit.SetupBuildUser(state)
	state = buildkit.PrepareWorkspace(state, cfg.PackageName)

	var err error
	state, err = pipeline.BuildPipelines(state, cfg.Pipelines)
	require.NoError(t, err)

	export := buildkit.ExportWorkspace(state)
	def, err := export.Marshal(ctx, llb.LinuxAmd64)
	require.NoError(t, err)

	bkClient, err := buildkit.New(ctx, h.BuildKitAddr())
	require.NoError(t, err)
	defer bkClient.Close()

	outDir := filepath.Join(h.TempDir(), "output")
	require.NoError(t, os.MkdirAll(outDir, 0755))

	_, err = bkClient.Client().Solve(ctx, def, client.SolveOpt{
		Exports: []client.ExportEntry{{
			Type:      client.ExporterLocal,
			OutputDir: outDir,
		}},
	}, nil)
	require.NoError(t, err)

	// Verify output
	harness.FileContains(t, outDir, "integration-test/usr/share/result.txt", "integration test output")
	harness.FileContains(t, outDir, "integration-test/usr/share/env.txt", "TEST_VAR=test-value")
}
