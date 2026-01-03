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
	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/e2e/harness"
	"github.com/dlorenc/melange2/pkg/build"
	"github.com/dlorenc/melange2/pkg/buildkit"
	"github.com/dlorenc/melange2/pkg/config"
)

// TestTestFixtures runs all test fixtures through the test runner.
// Each fixture is:
// 1. Compiled using production Build.Compile()
// 2. Tested using production Builder.TestWithImage()
//
// Note: failure.yaml is excluded - it's tested separately in TestTestPipeline_FailureDetection.
func TestTestFixtures(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e tests in short mode")
	}

	ctx := context.Background()

	// Load fixtures, excluding failure.yaml (tested separately)
	fixtures, err := LoadFixtures(ctx, "fixtures/test")
	require.NoError(t, err)

	var filtered []*Fixture
	for _, f := range fixtures {
		if f.Name != "failure" {
			filtered = append(filtered, f)
		}
	}

	h := harness.New(t)
	runner := NewRunner(t, h)

	for _, f := range filtered {
		f := f
		t.Run(f.Name, func(t *testing.T) {
			runner.RunTestOnly(f)
		})
	}
}

// TestTestPipeline_FailureDetection tests that failing tests are detected.
func TestTestPipeline_FailureDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	h := harness.New(t)
	ctx := h.Context()

	// Load the failure fixture
	f, err := LoadFixture(ctx, "fixtures/test/failure.yaml")
	require.NoError(t, err)

	// Compile using production code
	b := &build.Build{
		Configuration:       f.Config,
		PipelineDirs:        []string{},
		Arch:                apko_types.Architecture("amd64"),
		EnabledBuildOptions: []string{},
		Libc:                "gnu",
	}
	require.NoError(t, b.Compile(ctx), "compile")

	// Create output directory
	outDir := filepath.Join(h.TempDir(), "test-output")
	require.NoError(t, os.MkdirAll(outDir, 0755))

	// Build using production TestWithImage
	builder, err := buildkit.NewBuilder(h.BuildKitAddr())
	require.NoError(t, err)
	defer builder.Close()

	testCfg := &buildkit.TestConfig{
		PackageName:   f.Config.Package.Name,
		Arch:          apko_types.Architecture("amd64"),
		TestPipelines: f.Config.Test.Pipeline,
		WorkspaceDir:  outDir,
	}

	// This should fail
	err = builder.TestWithImage(ctx, harness.TestBaseImage, testCfg)
	require.Error(t, err, "test should fail")
	require.Contains(t, err.Error(), "failed", "error should indicate test failure")
}

// TestTestPipeline_NoTests tests handling of configs with no test pipelines.
func TestTestPipeline_NoTests(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	h := harness.New(t)
	ctx := h.Context()

	// Create a config with no test pipelines
	cfg := &config.Configuration{
		Package: config.Package{
			Name:    "no-tests",
			Version: "1.0.0",
		},
	}

	// Compile using production code
	b := &build.Build{
		Configuration:       cfg,
		PipelineDirs:        []string{},
		Arch:                apko_types.Architecture("amd64"),
		EnabledBuildOptions: []string{},
		Libc:                "gnu",
	}
	require.NoError(t, b.Compile(ctx), "compile")

	// Create output directory
	outDir := filepath.Join(h.TempDir(), "test-output")
	require.NoError(t, os.MkdirAll(outDir, 0755))

	// Build using production TestWithImage - should succeed with no tests
	builder, err := buildkit.NewBuilder(h.BuildKitAddr())
	require.NoError(t, err)
	defer builder.Close()

	testCfg := &buildkit.TestConfig{
		PackageName:   cfg.Package.Name,
		Arch:          apko_types.Architecture("amd64"),
		TestPipelines: nil, // No tests
		WorkspaceDir:  outDir,
	}

	// Should succeed - no tests means nothing to run
	err = builder.TestWithImage(ctx, harness.TestBaseImage, testCfg)
	require.NoError(t, err, "should succeed with no tests")
}
