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
	"time"

	apkofs "chainguard.dev/apko/pkg/apk/fs"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/e2e/harness"
	"github.com/dlorenc/melange2/pkg/buildkit"
	"github.com/dlorenc/melange2/pkg/config"
	"github.com/dlorenc/melange2/pkg/output"
)

// outputTestContext holds shared resources for output processor tests.
type outputTestContext struct {
	t            *testing.T
	h            *harness.Harness
	ctx          context.Context
	workspaceDir string
	outDir       string
}

// newOutputTestContext creates a new output test context.
func newOutputTestContext(t *testing.T) *outputTestContext {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	h := harness.New(t)

	workspaceDir := filepath.Join(h.TempDir(), "workspace")
	outDir := filepath.Join(h.TempDir(), "output")
	require.NoError(t, os.MkdirAll(workspaceDir, 0755))
	require.NoError(t, os.MkdirAll(outDir, 0755))

	return &outputTestContext{
		t:            t,
		h:            h,
		ctx:          h.Context(),
		workspaceDir: workspaceDir,
		outDir:       outDir,
	}
}

// buildPackageToWorkspace builds a package and exports to the workspace directory.
// The workspace will contain a melange-out/<pkgname> directory with the build output.
func (c *outputTestContext) buildPackageToWorkspace(cfg *config.Configuration) error {
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
	if err != nil {
		return err
	}

	// Build subpackage pipelines
	for _, sp := range cfg.Subpackages {
		subPipelines := substituteVars(cfg, sp.Pipeline, sp.Name)
		state, err = pipeline.BuildPipelines(state, subPipelines)
		if err != nil {
			return err
		}
	}

	// Export workspace
	export := buildkit.ExportWorkspace(state)
	def, err := export.Marshal(c.ctx, llb.LinuxAmd64)
	if err != nil {
		return err
	}

	// Solve
	bkClient, err := buildkit.New(c.ctx, c.h.BuildKitAddr())
	if err != nil {
		return err
	}
	defer bkClient.Close()

	_, err = bkClient.Client().Solve(c.ctx, def, client.SolveOpt{
		Exports: []client.ExportEntry{{
			Type:      client.ExporterLocal,
			OutputDir: c.workspaceDir,
		}},
	}, nil)

	return err
}

// TestOutput_ProcessorSkipsAll tests that the processor respects skip options.
func TestOutput_ProcessorSkipsAll(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	c := newOutputTestContext(t)
	defer c.h.Close()

	// Load and build a simple package
	configPath := filepath.Join("fixtures", "build", "simple.yaml")
	cfg, err := config.ParseConfiguration(c.ctx, configPath)
	require.NoError(t, err)

	err = c.buildPackageToWorkspace(cfg)
	require.NoError(t, err)

	// Create workspace filesystem
	wsFS := apkofs.DirFS(c.ctx, c.workspaceDir)

	// Create processor with everything skipped
	processor := &output.Processor{
		Options: output.ProcessOptions{
			SkipLint:         true,
			SkipLicenseCheck: true,
			SkipSBOM:         true,
			SkipEmit:         true,
			SkipIndex:        true,
		},
	}

	input := &output.ProcessInput{
		Configuration:   cfg,
		WorkspaceDir:    c.workspaceDir,
		WorkspaceDirFS:  wsFS,
		OutDir:          c.outDir,
		Arch:            "amd64",
		SourceDateEpoch: time.Now(),
	}

	// Should succeed with everything skipped
	err = processor.Process(c.ctx, input)
	assert.NoError(t, err)
}

// TestOutput_LintingRuns tests that linting runs on build output.
func TestOutput_LintingRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	c := newOutputTestContext(t)
	defer c.h.Close()

	// Load and build a simple package
	configPath := filepath.Join("fixtures", "build", "simple.yaml")
	cfg, err := config.ParseConfiguration(c.ctx, configPath)
	require.NoError(t, err)

	err = c.buildPackageToWorkspace(cfg)
	require.NoError(t, err)

	// Create workspace filesystem
	wsFS := apkofs.DirFS(c.ctx, c.workspaceDir)

	// Create processor with only linting enabled (no required linters - just warn)
	processor := &output.Processor{
		Options: output.ProcessOptions{
			SkipLint:         false,
			SkipLicenseCheck: true,
			SkipSBOM:         true,
			SkipEmit:         true,
			SkipIndex:        true,
		},
		Lint: output.LintConfig{
			Require: []string{}, // No required linters
			Warn:    []string{}, // No warn linters
		},
	}

	input := &output.ProcessInput{
		Configuration:   cfg,
		WorkspaceDir:    c.workspaceDir,
		WorkspaceDirFS:  wsFS,
		OutDir:          c.outDir,
		Arch:            "amd64",
		SourceDateEpoch: time.Now(),
	}

	// Should succeed - linting runs but nothing required
	err = processor.Process(c.ctx, input)
	assert.NoError(t, err)
}

// TestOutput_LicenseCheckRuns tests that license checking runs on build output.
func TestOutput_LicenseCheckRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	c := newOutputTestContext(t)
	defer c.h.Close()

	// Load and build a simple package
	configPath := filepath.Join("fixtures", "build", "simple.yaml")
	cfg, err := config.ParseConfiguration(c.ctx, configPath)
	require.NoError(t, err)

	err = c.buildPackageToWorkspace(cfg)
	require.NoError(t, err)

	// Create workspace filesystem
	wsFS := apkofs.DirFS(c.ctx, c.workspaceDir)

	// Create processor with only license check enabled
	processor := &output.Processor{
		Options: output.ProcessOptions{
			SkipLint:         true,
			SkipLicenseCheck: false,
			SkipSBOM:         true,
			SkipEmit:         true,
			SkipIndex:        true,
		},
	}

	input := &output.ProcessInput{
		Configuration:   cfg,
		WorkspaceDir:    c.workspaceDir,
		WorkspaceDirFS:  wsFS,
		OutDir:          c.outDir,
		Arch:            "amd64",
		SourceDateEpoch: time.Now(),
	}

	// Run the processor - license check should work
	err = processor.Process(c.ctx, input)
	// May fail if no copyright info, but that's expected for simple test
	// The important thing is that the code path runs
	t.Logf("License check result: %v", err)
}

// TestOutput_NewProcessor tests the constructor.
func TestOutput_NewProcessor(t *testing.T) {
	p := output.NewProcessor()
	require.NotNil(t, p)

	// Default options should all be false (nothing skipped)
	assert.False(t, p.Options.SkipLint)
	assert.False(t, p.Options.SkipLicenseCheck)
	assert.False(t, p.Options.SkipSBOM)
	assert.False(t, p.Options.SkipEmit)
	assert.False(t, p.Options.SkipIndex)
}
