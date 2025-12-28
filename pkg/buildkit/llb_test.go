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
	"testing"

	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/pkg/config"
)

func TestPipelineBuilderSimple(t *testing.T) {
	builder := NewPipelineBuilder()

	pipeline := config.Pipeline{
		Runs: "echo hello",
	}

	base := llb.Image(TestBaseImage)
	state, err := builder.BuildPipeline(base, &pipeline)
	require.NoError(t, err)

	// Verify we can marshal the state
	def, err := state.Marshal(context.Background(), llb.LinuxAmd64)
	require.NoError(t, err)
	require.NotEmpty(t, def.Def)
}

func TestPipelineBuilderWithEnvironment(t *testing.T) {
	builder := NewPipelineBuilder()

	pipeline := config.Pipeline{
		Runs: "echo $MY_VAR",
		Environment: map[string]string{
			"MY_VAR": "hello",
		},
	}

	base := llb.Image(TestBaseImage)
	state, err := builder.BuildPipeline(base, &pipeline)
	require.NoError(t, err)

	def, err := state.Marshal(context.Background(), llb.LinuxAmd64)
	require.NoError(t, err)
	require.NotEmpty(t, def.Def)
}

func TestPipelineBuilderWithWorkDir(t *testing.T) {
	builder := NewPipelineBuilder()

	// Test absolute workdir
	pipeline := config.Pipeline{
		Runs:    "pwd",
		WorkDir: "/tmp/custom",
	}

	base := llb.Image(TestBaseImage)
	state, err := builder.BuildPipeline(base, &pipeline)
	require.NoError(t, err)

	def, err := state.Marshal(context.Background(), llb.LinuxAmd64)
	require.NoError(t, err)
	require.NotEmpty(t, def.Def)
}

func TestPipelineBuilderWithRelativeWorkDir(t *testing.T) {
	builder := NewPipelineBuilder()

	// Test relative workdir (should join with /home/build)
	pipeline := config.Pipeline{
		Runs:    "pwd",
		WorkDir: "subdir",
	}

	base := llb.Image(TestBaseImage)
	state, err := builder.BuildPipeline(base, &pipeline)
	require.NoError(t, err)

	def, err := state.Marshal(context.Background(), llb.LinuxAmd64)
	require.NoError(t, err)
	require.NotEmpty(t, def.Def)
}

func TestPipelineBuilderNestedPipelines(t *testing.T) {
	builder := NewPipelineBuilder()

	pipeline := config.Pipeline{
		Runs: "echo parent",
		Pipeline: []config.Pipeline{
			{Runs: "echo child1"},
			{Runs: "echo child2"},
		},
	}

	base := llb.Image(TestBaseImage)
	state, err := builder.BuildPipeline(base, &pipeline)
	require.NoError(t, err)

	def, err := state.Marshal(context.Background(), llb.LinuxAmd64)
	require.NoError(t, err)
	require.NotEmpty(t, def.Def)
}

func TestPipelineBuilderIfConditionTrue(t *testing.T) {
	builder := NewPipelineBuilder()

	// Condition that evaluates to true ('a' == 'a')
	pipeline := config.Pipeline{
		If:   "'a' == 'a'",
		Runs: "echo should run",
	}

	base := llb.Image(TestBaseImage)
	state, err := builder.BuildPipeline(base, &pipeline)
	require.NoError(t, err)

	// State should be different from base (pipeline ran)
	baseDef, _ := base.Marshal(context.Background(), llb.LinuxAmd64)
	stateDef, _ := state.Marshal(context.Background(), llb.LinuxAmd64)
	require.NotEqual(t, baseDef.Def, stateDef.Def)
}

func TestPipelineBuilderIfConditionFalse(t *testing.T) {
	builder := NewPipelineBuilder()

	// Condition that evaluates to false ('a' == 'b')
	pipeline := config.Pipeline{
		If:   "'a' == 'b'",
		Runs: "echo should not run",
	}

	base := llb.Image(TestBaseImage)
	state, err := builder.BuildPipeline(base, &pipeline)
	require.NoError(t, err)

	// State should be same as base (pipeline skipped)
	baseDef, _ := base.Marshal(context.Background(), llb.LinuxAmd64)
	stateDef, _ := state.Marshal(context.Background(), llb.LinuxAmd64)
	require.Equal(t, baseDef.Def, stateDef.Def)
}

func TestPipelineBuilderEmptyRuns(t *testing.T) {
	builder := NewPipelineBuilder()

	// Pipeline with no runs (e.g., just nested pipelines)
	pipeline := config.Pipeline{
		Pipeline: []config.Pipeline{
			{Runs: "echo nested"},
		},
	}

	base := llb.Image(TestBaseImage)
	state, err := builder.BuildPipeline(base, &pipeline)
	require.NoError(t, err)

	def, err := state.Marshal(context.Background(), llb.LinuxAmd64)
	require.NoError(t, err)
	require.NotEmpty(t, def.Def)
}

func TestPipelineBuilderMultiplePipelines(t *testing.T) {
	builder := NewPipelineBuilder()

	pipelines := []config.Pipeline{
		{Runs: "echo step1"},
		{Runs: "echo step2"},
		{Runs: "echo step3"},
	}

	base := llb.Image(TestBaseImage)
	state, err := builder.BuildPipelines(base, pipelines)
	require.NoError(t, err)

	def, err := state.Marshal(context.Background(), llb.LinuxAmd64)
	require.NoError(t, err)
	require.NotEmpty(t, def.Def)
}

func TestPipelineBuilderDeterminism(t *testing.T) {
	// Run 100 times to check for non-determinism
	var firstDigest string

	for i := 0; i < 100; i++ {
		builder := NewPipelineBuilder()
		pipeline := config.Pipeline{
			Runs: "echo hello",
			Environment: map[string]string{
				"Z_VAR": "z",
				"A_VAR": "a",
				"M_VAR": "m",
			},
		}

		base := llb.Image(TestBaseImage)
		state, err := builder.BuildPipeline(base, &pipeline)
		require.NoError(t, err)

		def, err := state.Marshal(context.Background(), llb.LinuxAmd64)
		require.NoError(t, err)

		dgst, err := def.Head()
		require.NoError(t, err)
		digest := dgst.String()
		if i == 0 {
			firstDigest = digest
		} else {
			require.Equal(t, firstDigest, digest, "iteration %d produced different digest", i)
		}
	}
}

func TestPipelineBuilderDebug(t *testing.T) {
	builder := NewPipelineBuilder()
	builder.Debug = true

	pipeline := config.Pipeline{
		Runs: "echo debug",
	}

	base := llb.Image(TestBaseImage)
	state, err := builder.BuildPipeline(base, &pipeline)
	require.NoError(t, err)

	def, err := state.Marshal(context.Background(), llb.LinuxAmd64)
	require.NoError(t, err)
	require.NotEmpty(t, def.Def)
}

func TestPrepareWorkspace(t *testing.T) {
	base := llb.Image(TestBaseImage)
	state := PrepareWorkspace(base, "test-pkg")

	def, err := state.Marshal(context.Background(), llb.LinuxAmd64)
	require.NoError(t, err)
	require.NotEmpty(t, def.Def)
}

func TestExportWorkspace(t *testing.T) {
	base := llb.Image(TestBaseImage)
	prepared := PrepareWorkspace(base, "test-pkg")
	export := ExportWorkspace(prepared)

	def, err := export.Marshal(context.Background(), llb.LinuxAmd64)
	require.NoError(t, err)
	require.NotEmpty(t, def.Def)
}

// Integration test that actually runs a pipeline in BuildKit
func TestPipelineBuilderIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	bk := startBuildKitContainer(t, ctx)

	c, err := client.New(ctx, bk.Addr)
	require.NoError(t, err)
	defer c.Close()

	t.Logf("BuildKit running at %s", bk.Addr)

	// Create a pipeline that creates a file
	builder := NewPipelineBuilder()
	pipelines := []config.Pipeline{
		{
			Name: "create-output",
			Runs: `
mkdir -p /home/build/melange-out/test-pkg
echo "hello from pipeline" > /home/build/melange-out/test-pkg/output.txt
`,
		},
		{
			Name: "verify-output",
			Runs: "cat /home/build/melange-out/test-pkg/output.txt",
		},
	}

	// Start with alpine and prepare workspace
	base := llb.Image(TestBaseImage)
	state := PrepareWorkspace(base, "test-pkg")

	// Run pipelines
	state, err = builder.BuildPipelines(state, pipelines)
	require.NoError(t, err)

	// Export workspace
	export := ExportWorkspace(state)
	def, err := export.Marshal(ctx, llb.LinuxAmd64)
	require.NoError(t, err)

	// Solve and export
	exportDir := t.TempDir()
	_, err = c.Solve(ctx, def, client.SolveOpt{
		Exports: []client.ExportEntry{{
			Type:      client.ExporterLocal,
			OutputDir: exportDir,
		}},
	}, nil)
	require.NoError(t, err)

	// Verify output
	content, err := os.ReadFile(filepath.Join(exportDir, "test-pkg", "output.txt"))
	require.NoError(t, err)
	require.Contains(t, string(content), "hello from pipeline")
}

// Integration test with nested pipelines
func TestNestedPipelinesIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	bk := startBuildKitContainer(t, ctx)

	c, err := client.New(ctx, bk.Addr)
	require.NoError(t, err)
	defer c.Close()

	builder := NewPipelineBuilder()
	pipeline := config.Pipeline{
		Name: "parent",
		Runs: `
mkdir -p /home/build/melange-out/test-pkg
echo "step1" >> /home/build/melange-out/test-pkg/log.txt
`,
		Pipeline: []config.Pipeline{
			{
				Name: "child1",
				Runs: `echo "step2" >> /home/build/melange-out/test-pkg/log.txt`,
			},
			{
				Name: "child2",
				Runs: `echo "step3" >> /home/build/melange-out/test-pkg/log.txt`,
			},
		},
	}

	base := llb.Image(TestBaseImage)
	state := PrepareWorkspace(base, "test-pkg")
	state, err = builder.BuildPipeline(state, &pipeline)
	require.NoError(t, err)

	export := ExportWorkspace(state)
	def, err := export.Marshal(ctx, llb.LinuxAmd64)
	require.NoError(t, err)

	exportDir := t.TempDir()
	_, err = c.Solve(ctx, def, client.SolveOpt{
		Exports: []client.ExportEntry{{
			Type:      client.ExporterLocal,
			OutputDir: exportDir,
		}},
	}, nil)
	require.NoError(t, err)

	content, err := os.ReadFile(filepath.Join(exportDir, "test-pkg", "log.txt"))
	require.NoError(t, err)
	require.Contains(t, string(content), "step1")
	require.Contains(t, string(content), "step2")
	require.Contains(t, string(content), "step3")
}

// Integration test with environment variables
func TestEnvironmentIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	bk := startBuildKitContainer(t, ctx)

	c, err := client.New(ctx, bk.Addr)
	require.NoError(t, err)
	defer c.Close()

	builder := NewPipelineBuilder()
	builder.BaseEnv["GLOBAL_VAR"] = "global"

	pipeline := config.Pipeline{
		Name: "env-test",
		Runs: `
mkdir -p /home/build/melange-out/test-pkg
echo "PATH=$PATH" > /home/build/melange-out/test-pkg/env.txt
echo "GLOBAL_VAR=$GLOBAL_VAR" >> /home/build/melange-out/test-pkg/env.txt
echo "LOCAL_VAR=$LOCAL_VAR" >> /home/build/melange-out/test-pkg/env.txt
`,
		Environment: map[string]string{
			"LOCAL_VAR": "local",
		},
	}

	base := llb.Image(TestBaseImage)
	state := PrepareWorkspace(base, "test-pkg")
	state, err = builder.BuildPipeline(state, &pipeline)
	require.NoError(t, err)

	export := ExportWorkspace(state)
	def, err := export.Marshal(ctx, llb.LinuxAmd64)
	require.NoError(t, err)

	exportDir := t.TempDir()
	_, err = c.Solve(ctx, def, client.SolveOpt{
		Exports: []client.ExportEntry{{
			Type:      client.ExporterLocal,
			OutputDir: exportDir,
		}},
	}, nil)
	require.NoError(t, err)

	content, err := os.ReadFile(filepath.Join(exportDir, "test-pkg", "env.txt"))
	require.NoError(t, err)
	require.Contains(t, string(content), "GLOBAL_VAR=global")
	require.Contains(t, string(content), "LOCAL_VAR=local")
	require.Contains(t, string(content), "PATH=")
}

// Integration test with if conditions
func TestIfConditionIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	bk := startBuildKitContainer(t, ctx)

	c, err := client.New(ctx, bk.Addr)
	require.NoError(t, err)
	defer c.Close()

	builder := NewPipelineBuilder()
	pipelines := []config.Pipeline{
		{
			Name: "setup",
			Runs: `
mkdir -p /home/build/melange-out/test-pkg
echo "setup done" > /home/build/melange-out/test-pkg/status.txt
`,
		},
		{
			Name: "should-run",
			If:   "'yes' == 'yes'",
			Runs: `echo "ran-true" >> /home/build/melange-out/test-pkg/status.txt`,
		},
		{
			Name: "should-skip",
			If:   "'yes' == 'no'",
			Runs: `echo "ran-false" >> /home/build/melange-out/test-pkg/status.txt`,
		},
	}

	base := llb.Image(TestBaseImage)
	state := PrepareWorkspace(base, "test-pkg")
	state, err = builder.BuildPipelines(state, pipelines)
	require.NoError(t, err)

	export := ExportWorkspace(state)
	def, err := export.Marshal(ctx, llb.LinuxAmd64)
	require.NoError(t, err)

	exportDir := t.TempDir()
	_, err = c.Solve(ctx, def, client.SolveOpt{
		Exports: []client.ExportEntry{{
			Type:      client.ExporterLocal,
			OutputDir: exportDir,
		}},
	}, nil)
	require.NoError(t, err)

	content, err := os.ReadFile(filepath.Join(exportDir, "test-pkg", "status.txt"))
	require.NoError(t, err)
	require.Contains(t, string(content), "setup done")
	require.Contains(t, string(content), "ran-true")
	require.NotContains(t, string(content), "ran-false")
}

func TestCopyCacheToWorkspace(t *testing.T) {
	base := llb.Image(TestBaseImage)
	state := CopyCacheToWorkspace(base, "test-cache")

	def, err := state.Marshal(context.Background(), llb.LinuxAmd64)
	require.NoError(t, err)
	require.NotEmpty(t, def.Def)
}

func TestCacheConstants(t *testing.T) {
	require.Equal(t, "/var/cache/melange", DefaultCacheDir)
	require.Equal(t, "cache", CacheLocalName)
}

func TestBuildPipelinesWithRecoverySuccess(t *testing.T) {
	builder := NewPipelineBuilder()

	pipelines := []config.Pipeline{
		{Runs: "echo step1"},
		{Runs: "echo step2"},
		{Runs: "echo step3"},
	}

	base := llb.Image(TestBaseImage)
	result := builder.BuildPipelinesWithRecovery(base, pipelines)

	require.NoError(t, result.Error)
	require.Equal(t, -1, result.FailedAtIndex)

	// Verify we can marshal the final state
	def, err := result.State.Marshal(context.Background(), llb.LinuxAmd64)
	require.NoError(t, err)
	require.NotEmpty(t, def.Def)
}

func TestBuildPipelinesWithRecoveryFailure(t *testing.T) {
	builder := NewPipelineBuilder()

	pipelines := []config.Pipeline{
		{Runs: "echo step1"},
		{Runs: "echo step2", If: "invalid condition syntax"},
		{Runs: "echo step3"},
	}

	base := llb.Image(TestBaseImage)
	result := builder.BuildPipelinesWithRecovery(base, pipelines)

	// Should fail at pipeline index 1
	require.Error(t, result.Error)
	require.Equal(t, 1, result.FailedAtIndex)
	require.Contains(t, result.Error.Error(), "pipeline 1")

	// The returned state should be the state before the failed pipeline
	// (i.e., after step1 but before step2)
	def, err := result.State.Marshal(context.Background(), llb.LinuxAmd64)
	require.NoError(t, err)
	require.NotEmpty(t, def.Def)

	// State should be different from base (step1 ran)
	baseDef, _ := base.Marshal(context.Background(), llb.LinuxAmd64)
	require.NotEqual(t, baseDef.Def, def.Def)
}

func TestBuildPipelinesWithRecoveryFirstStepFailure(t *testing.T) {
	builder := NewPipelineBuilder()

	pipelines := []config.Pipeline{
		{Runs: "echo step1", If: "invalid condition"},
		{Runs: "echo step2"},
	}

	base := llb.Image(TestBaseImage)
	result := builder.BuildPipelinesWithRecovery(base, pipelines)

	// Should fail at pipeline index 0
	require.Error(t, result.Error)
	require.Equal(t, 0, result.FailedAtIndex)

	// The returned state should be the base state (nothing ran)
	def, err := result.State.Marshal(context.Background(), llb.LinuxAmd64)
	require.NoError(t, err)

	baseDef, _ := base.Marshal(context.Background(), llb.LinuxAmd64)
	require.Equal(t, baseDef.Def, def.Def)
}

func TestBuildPipelinesWithRecoveryEmptyPipelines(t *testing.T) {
	builder := NewPipelineBuilder()

	pipelines := []config.Pipeline{}

	base := llb.Image(TestBaseImage)
	result := builder.BuildPipelinesWithRecovery(base, pipelines)

	require.NoError(t, result.Error)
	require.Equal(t, -1, result.FailedAtIndex)

	// State should equal base
	def, err := result.State.Marshal(context.Background(), llb.LinuxAmd64)
	require.NoError(t, err)

	baseDef, _ := base.Marshal(context.Background(), llb.LinuxAmd64)
	require.Equal(t, baseDef.Def, def.Def)
}

// Integration test for cache directory
func TestCacheDirectoryIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	bk := startBuildKitContainer(t, ctx)

	c, err := client.New(ctx, bk.Addr)
	require.NoError(t, err)
	defer c.Close()

	// Create a cache directory with a test file
	cacheDir := t.TempDir()
	testFile := filepath.Join(cacheDir, "cached-artifact.txt")
	err = os.WriteFile(testFile, []byte("cached content"), 0644)
	require.NoError(t, err)

	// Create a pipeline that reads from the cache
	builder := NewPipelineBuilder()
	pipeline := config.Pipeline{
		Name: "read-cache",
		Runs: `
mkdir -p /home/build/melange-out/test-pkg
cat /var/cache/melange/cached-artifact.txt > /home/build/melange-out/test-pkg/from-cache.txt
`,
	}

	// Build the LLB graph
	base := llb.Image(TestBaseImage)
	state := PrepareWorkspace(base, "test-pkg")
	state = CopyCacheToWorkspace(state, CacheLocalName)
	state, err = builder.BuildPipeline(state, &pipeline)
	require.NoError(t, err)

	export := ExportWorkspace(state)
	def, err := export.Marshal(ctx, llb.LinuxAmd64)
	require.NoError(t, err)

	// Solve with cache directory as local mount
	exportDir := t.TempDir()
	_, err = c.Solve(ctx, def, client.SolveOpt{
		LocalDirs: map[string]string{
			CacheLocalName: cacheDir,
		},
		Exports: []client.ExportEntry{{
			Type:      client.ExporterLocal,
			OutputDir: exportDir,
		}},
	}, nil)
	require.NoError(t, err)

	// Verify the cached content was read
	content, err := os.ReadFile(filepath.Join(exportDir, "test-pkg", "from-cache.txt"))
	require.NoError(t, err)
	require.Equal(t, "cached content", string(content))
}
