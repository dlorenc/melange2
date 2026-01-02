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
	"github.com/dlorenc/melange2/pkg/buildkit"
	"github.com/dlorenc/melange2/pkg/config"
)

// testPipelineContext holds shared resources for test pipeline tests.
type testPipelineContext struct {
	t      *testing.T
	h      *harness.Harness
	ctx    context.Context
	outDir string
}

// newTestPipelineContext creates a new test pipeline context with BuildKit running.
func newTestPipelineContext(t *testing.T) *testPipelineContext {
	t.Helper()

	h := harness.New(t)

	outDir := filepath.Join(h.TempDir(), "test-output")
	require.NoError(t, os.MkdirAll(outDir, 0755))

	return &testPipelineContext{
		t:      t,
		h:      h,
		ctx:    h.Context(),
		outDir: outDir,
	}
}

// loadTestConfig loads a test configuration from the test fixtures directory.
func (c *testPipelineContext) loadTestConfig(name string) *config.Configuration {
	c.t.Helper()

	configPath := filepath.Join("fixtures", "test", name)
	cfg, err := config.ParseConfiguration(c.ctx, configPath)
	require.NoError(c.t, err, "should parse config %s", name)

	return cfg
}

// runTests executes test pipelines for the config and returns the output directory.
func (c *testPipelineContext) runTests(cfg *config.Configuration) (string, error) {
	builder, err := buildkit.NewBuilder(c.h.BuildKitAddr())
	if err != nil {
		return "", err
	}
	defer builder.Close()

	// Substitute variables in test pipelines
	var testPipelines []config.Pipeline
	if cfg.Test != nil {
		testPipelines = substituteVars(cfg, cfg.Test.Pipeline, "")
	}

	// Build subpackage test configs
	var subpackageTests []buildkit.SubpackageTestConfig
	for _, sp := range cfg.Subpackages {
		if sp.Test != nil && len(sp.Test.Pipeline) > 0 {
			subpackageTests = append(subpackageTests, buildkit.SubpackageTestConfig{
				Name:      sp.Name,
				Pipelines: substituteVars(cfg, sp.Test.Pipeline, sp.Name),
			})
		}
	}

	// Skip if no tests
	if len(testPipelines) == 0 && len(subpackageTests) == 0 {
		return c.outDir, nil
	}

	// Configure test
	testCfg := &buildkit.TestConfig{
		PackageName:     cfg.Package.Name,
		Arch:            apko_types.Architecture("amd64"),
		TestPipelines:   testPipelines,
		SubpackageTests: subpackageTests,
		BaseEnv: map[string]string{
			"HOME": "/home/build",
		},
		WorkspaceDir: c.outDir,
	}

	// Run tests using the test base image
	if err := builder.TestWithImage(c.ctx, harness.TestBaseImage, testCfg); err != nil {
		return "", err
	}

	return c.outDir, nil
}

// =============================================================================
// Test Pipeline Tests
// =============================================================================

func TestTestPipeline_Simple(t *testing.T) {
	c := newTestPipelineContext(t)
	cfg := c.loadTestConfig("simple-test.yaml")

	outDir, err := c.runTests(cfg)
	require.NoError(t, err, "test should succeed")

	// Verify test results were exported
	harness.FileExists(t, outDir, "test-results/simple-test-pkg/status.txt")
	harness.FileContains(t, outDir, "test-results/simple-test-pkg/status.txt", "PASSED")
}

func TestTestPipeline_SubpackageIsolation(t *testing.T) {
	c := newTestPipelineContext(t)
	cfg := c.loadTestConfig("isolation.yaml")

	outDir, err := c.runTests(cfg)
	require.NoError(t, err, "all tests should succeed - isolation is maintained")

	// Verify main package test ran
	harness.FileExists(t, outDir, "test-results/isolation-test/status.txt")
	harness.FileContains(t, outDir, "test-results/isolation-test/status.txt", "PASSED")

	// Verify sub1 test ran (and passed isolation check)
	harness.FileExists(t, outDir, "test-results/isolation-test-sub1/status.txt")
	harness.FileContains(t, outDir, "test-results/isolation-test-sub1/status.txt", "PASSED")

	// Verify sub2 test ran (and passed isolation check)
	harness.FileExists(t, outDir, "test-results/isolation-test-sub2/status.txt")
	harness.FileContains(t, outDir, "test-results/isolation-test-sub2/status.txt", "PASSED")
}

func TestTestPipeline_FailureDetection(t *testing.T) {
	c := newTestPipelineContext(t)
	cfg := c.loadTestConfig("failure.yaml")

	_, err := c.runTests(cfg)
	require.Error(t, err, "test should fail")
	require.Contains(t, err.Error(), "failed", "error should indicate test failure")
}

func TestTestPipeline_NoTests(t *testing.T) {
	c := newTestPipelineContext(t)

	// Create a config with no test pipelines
	cfg := &config.Configuration{
		Package: config.Package{
			Name:    "no-tests",
			Version: "1.0.0",
		},
		// No Test section
	}

	outDir, err := c.runTests(cfg)
	require.NoError(t, err, "should succeed with no tests")

	// test-results directory should exist but be empty or not exist
	_, err = os.Stat(filepath.Join(outDir, "test-results"))
	// It's ok if the directory doesn't exist - no tests means nothing to export
	require.True(t, err == nil || os.IsNotExist(err))
}

func TestTestPipeline_ProcessStatePersistence(t *testing.T) {
	// This test verifies that process state (background processes, files) is
	// maintained between test steps, matching the old QEMU runner behavior.
	// Environment variables should NOT leak between steps.
	c := newTestPipelineContext(t)
	cfg := c.loadTestConfig("process-state.yaml")

	outDir, err := c.runTests(cfg)
	require.NoError(t, err, "test should succeed - process state should persist between steps while env vars are isolated")

	// Verify test results were exported
	harness.FileExists(t, outDir, "test-results/process-state-test/status.txt")
	harness.FileContains(t, outDir, "test-results/process-state-test/status.txt", "PASSED")
}
