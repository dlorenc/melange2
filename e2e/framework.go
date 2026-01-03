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

// Package e2e provides a fixture-driven end-to-end test framework.
//
// Tests are defined as standard melange YAML files. Each fixture is:
// 1. Built using production Build.BuildPackage() (exercises full pkg/build workflow)
// 2. Tested using production Builder.TestWithImage() (if test: section exists)
//
// Build success = test passes. Use the test: section to verify APK structure.
package e2e

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	apko_types "chainguard.dev/apko/pkg/build/types"

	"github.com/dlorenc/melange2/e2e/harness"
	"github.com/dlorenc/melange2/pkg/build"
	"github.com/dlorenc/melange2/pkg/buildkit"
	"github.com/dlorenc/melange2/pkg/config"
	"github.com/dlorenc/melange2/pkg/service/types"
)

// BuildMode defines how a fixture should be built.
type BuildMode string

const (
	BuildModeLocal  BuildMode = "local"
	BuildModeRemote BuildMode = "remote"
)

// Fixture represents a test fixture loaded from a melange YAML.
type Fixture struct {
	Config *config.Configuration
	Name   string
	Path   string
}

// LoadFixture loads a fixture from a melange YAML file.
func LoadFixture(ctx context.Context, path string) (*Fixture, error) {
	cfg, err := config.ParseConfiguration(ctx, path)
	if err != nil {
		return nil, err
	}

	return &Fixture{
		Config: cfg,
		Name:   strings.TrimSuffix(filepath.Base(path), ".yaml"),
		Path:   path,
	}, nil
}

// LoadFixtures loads all fixtures from a directory.
func LoadFixtures(ctx context.Context, dir string) ([]*Fixture, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	fixtures := make([]*Fixture, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		fixture, err := LoadFixture(ctx, filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		fixtures = append(fixtures, fixture)
	}

	return fixtures, nil
}

// Runner executes fixtures through the test matrix.
type Runner struct {
	t   *testing.T
	h   *harness.Harness
	ctx context.Context
}

// NewRunner creates a new fixture runner.
func NewRunner(t *testing.T, h *harness.Harness) *Runner {
	return &Runner{t: t, h: h, ctx: h.Context()}
}

// RunLocal runs a fixture using local BuildKit via production Build.BuildPackage().
// This exercises the full pkg/build workflow including SBOM initialization,
// workspace setup, and BuildKit execution.
func (r *Runner) RunLocal(f *Fixture) {
	r.t.Helper()

	// Create output directory
	outDir := filepath.Join(r.h.TempDir(), "output", f.Name)
	require.NoError(r.t, os.MkdirAll(outDir, 0755))

	// Create workspace directory
	workspaceDir := filepath.Join(r.h.TempDir(), "workspace", f.Name)
	require.NoError(r.t, os.MkdirAll(workspaceDir, 0755))

	// Build using production Build.BuildPackage() with BaseImage to bypass apko
	b := &build.Build{
		Configuration:       f.Config,
		ConfigFile:          f.Path,
		PipelineDirs:        []string{},
		Arch:                apko_types.Architecture("amd64"),
		EnabledBuildOptions: []string{},
		Libc:                "gnu",
		BuildKitAddr:        r.h.BuildKitAddr(),
		WorkspaceDir:        workspaceDir,
		OutDir:              outDir,
		BaseImage:           harness.TestBaseImage, // Use pre-built image instead of apko
		EmptyWorkspace:      true,                  // No source files to copy
	}

	require.NoError(r.t, b.BuildPackage(r.ctx), "BuildPackage")

	// Note: We don't run test: sections here because they expect the built package
	// to be installed, but we're only building (not installing) the package.
	// The build success itself validates the fixture.
	// Use RunTestOnly() for fixtures specifically testing the test runner.
}

// RunRemote runs a fixture using the remote build server.
func (r *Runner) RunRemote(f *Fixture) {
	r.t.Helper()

	if r.h.ServerURL() == "" {
		r.t.Skip("remote server not enabled")
	}

	client := r.h.Client()

	// Read the fixture file content
	configYAML, err := os.ReadFile(f.Path)
	require.NoError(r.t, err, "read fixture")

	// Submit build
	req := types.CreateBuildRequest{
		ConfigYAML: string(configYAML),
		Arch:       "x86_64",
	}
	resp, err := client.SubmitBuild(r.ctx, req)
	require.NoError(r.t, err, "submit")

	// Wait for completion
	result, err := client.WaitForBuild(r.ctx, resp.ID, 500*time.Millisecond)
	require.NoError(r.t, err, "wait")
	require.Equal(r.t, types.BuildStatusSuccess, result.Status, "build status: %s", result.Status)
}

// RunTestOnly runs only the test pipelines for a fixture (skips build).
// This is useful for testing the test runner in isolation.
func (r *Runner) RunTestOnly(f *Fixture) {
	r.t.Helper()

	// Compile using production code
	b := &build.Build{
		Configuration:       f.Config,
		PipelineDirs:        []string{},
		Arch:                apko_types.Architecture("amd64"),
		EnabledBuildOptions: []string{},
		Libc:                "gnu",
	}
	require.NoError(r.t, b.Compile(r.ctx), "compile")

	// Skip if no tests
	if f.Config.Test == nil || len(f.Config.Test.Pipeline) == 0 {
		r.t.Skip("no test pipelines")
	}

	// Create output directory
	outDir := filepath.Join(r.h.TempDir(), "test-output", f.Name)
	require.NoError(r.t, os.MkdirAll(outDir, 0755))

	// Build using production TestWithImage
	builder, err := buildkit.NewBuilder(r.h.BuildKitAddr())
	require.NoError(r.t, err)
	defer builder.Close()

	testCfg := &buildkit.TestConfig{
		PackageName:   f.Config.Package.Name,
		Arch:          apko_types.Architecture("amd64"),
		TestPipelines: f.Config.Test.Pipeline,
		BaseEnv:       f.Config.Environment.Environment,
		WorkspaceDir:  outDir,
	}

	// Collect subpackage tests
	for _, sp := range f.Config.Subpackages {
		if sp.Test != nil && len(sp.Test.Pipeline) > 0 {
			testCfg.SubpackageTests = append(testCfg.SubpackageTests, buildkit.SubpackageTestConfig{
				Name:      sp.Name,
				Pipelines: sp.Test.Pipeline,
			})
		}
	}

	require.NoError(r.t, builder.TestWithImage(r.ctx, harness.TestBaseImage, testCfg), "test")
}

// RunTestFixtures loads and runs all test fixtures from a directory.
// Unlike RunAllFixtures, this only runs the test pipelines (not build pipelines).
func RunTestFixtures(t *testing.T, fixturesDir string) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping e2e tests in short mode")
	}

	ctx := context.Background()

	fixtures, err := LoadFixtures(ctx, fixturesDir)
	require.NoError(t, err)

	h := harness.New(t)
	runner := NewRunner(t, h)

	for _, f := range fixtures {
		f := f
		t.Run(f.Name, func(t *testing.T) {
			runner.RunTestOnly(f)
		})
	}
}

// RunAllFixtures loads and runs all fixtures from a directory.
func RunAllFixtures(t *testing.T, fixturesDir string, modes ...BuildMode) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping e2e tests in short mode")
	}

	ctx := context.Background()

	fixtures, err := LoadFixtures(ctx, fixturesDir)
	require.NoError(t, err)

	if len(modes) == 0 {
		modes = []BuildMode{BuildModeLocal}
	}

	// Check if remote mode requested
	runRemote := false
	for _, m := range modes {
		if m == BuildModeRemote {
			runRemote = true
			break
		}
	}

	// Create harness
	var opts []harness.Option
	if runRemote {
		opts = append(opts, harness.WithServer())
	}
	h := harness.New(t, opts...)

	if runRemote {
		require.NoError(t, h.WaitForServerReady())
	}

	runner := NewRunner(t, h)

	// Run each fixture through the matrix
	for _, f := range fixtures {
		f := f
		t.Run(f.Name, func(t *testing.T) {
			for _, mode := range modes {
				mode := mode
				t.Run(string(mode), func(t *testing.T) {
					switch mode {
					case BuildModeLocal:
						runner.RunLocal(f)
					case BuildModeRemote:
						runner.RunRemote(f)
					}
				})
			}
		})
	}
}
