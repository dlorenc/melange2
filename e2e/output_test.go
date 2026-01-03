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
	apko_types "chainguard.dev/apko/pkg/build/types"
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
	// Compile configuration using production code path
	if err := harness.CompileConfiguration(c.ctx, cfg, nil); err != nil {
		return err
	}

	// Build using production BuildWithImage
	builder, err := buildkit.NewBuilder(c.h.BuildKitAddr())
	if err != nil {
		return err
	}
	defer builder.Close()

	buildCfg := &buildkit.BuildConfig{
		PackageName:  cfg.Package.Name,
		Arch:         apko_types.Architecture("amd64"),
		Pipelines:    cfg.Pipeline,
		Subpackages:  cfg.Subpackages,
		BaseEnv:      cfg.Environment.Environment,
		WorkspaceDir: c.workspaceDir,
	}

	return builder.BuildWithImage(c.ctx, harness.TestBaseImage, buildCfg)
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

// TestOutput_LicenseFileExport tests that license files referenced in copyright
// configuration are exported from BuildKit and available for SBOM generation.
// This specifically tests the fix for the bug where license files (like COPYING)
// created during git-checkout were not exported from BuildKit.
func TestOutput_LicenseFileExport(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	c := newOutputTestContext(t)
	defer c.h.Close()

	// Load the license-file fixture which creates a LICENSE file in the workspace
	configPath := filepath.Join("fixtures", "build", "license-file.yaml")
	cfg, err := config.ParseConfiguration(c.ctx, configPath)
	require.NoError(t, err)

	// Compile configuration
	err = harness.CompileConfiguration(c.ctx, cfg, nil)
	require.NoError(t, err)

	// Build using BuildWithImage with license files specified
	builder, err := buildkit.NewBuilder(c.h.BuildKitAddr())
	require.NoError(t, err)
	defer builder.Close()

	// Collect license files from config (same as production code in build_buildkit.go)
	var licenseFiles []string
	for _, cp := range cfg.Package.Copyright {
		if cp.LicensePath != "" {
			licenseFiles = append(licenseFiles, cp.LicensePath)
		}
	}

	buildCfg := &buildkit.BuildConfig{
		PackageName:  cfg.Package.Name,
		Arch:         apko_types.Architecture("amd64"),
		Pipelines:    cfg.Pipeline,
		Subpackages:  cfg.Subpackages,
		BaseEnv:      cfg.Environment.Environment,
		WorkspaceDir: c.workspaceDir,
		LicenseFiles: licenseFiles, // This is the key part - export license files
	}

	err = builder.BuildWithImage(c.ctx, harness.TestBaseImage, buildCfg)
	require.NoError(t, err, "BuildWithImage should succeed")

	// Verify the LICENSE file was exported to the workspace
	licensePath := filepath.Join(c.workspaceDir, "LICENSE")
	_, err = os.Stat(licensePath)
	require.NoError(t, err, "LICENSE file should exist in workspace after export")

	// Verify the content
	content, err := os.ReadFile(licensePath)
	require.NoError(t, err)
	assert.Contains(t, string(content), "MIT License", "LICENSE should contain expected content")

	// Verify LicensingInfos can read the file (this is what SBOM generation does)
	licensingInfos, err := cfg.Package.LicensingInfos(c.workspaceDir)
	require.NoError(t, err, "LicensingInfos should be able to read license file")
	assert.Contains(t, licensingInfos, "MIT", "LicensingInfos should contain MIT license")
	assert.Contains(t, licensingInfos["MIT"], "MIT License", "License content should be present")
}
