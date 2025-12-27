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
	"fmt"
	"os"
	"path/filepath"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/errgroup"

	"github.com/dlorenc/melange2/pkg/config"
)

// Builder executes melange builds using BuildKit.
type Builder struct {
	client   *Client
	loader   *ImageLoader
	pipeline *PipelineBuilder

	// ProgressMode controls how build progress is displayed.
	ProgressMode ProgressMode
	// ShowLogs enables display of stdout/stderr from build steps.
	ShowLogs bool
}

// NewBuilder creates a new BuildKit builder.
func NewBuilder(addr string) (*Builder, error) {
	c, err := New(context.Background(), addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to buildkit: %w", err)
	}

	return &Builder{
		client:       c,
		loader:       NewImageLoader(""),
		pipeline:     NewPipelineBuilder(),
		ProgressMode: ProgressModeAuto,
		ShowLogs:     false,
	}, nil
}

// WithProgressMode sets the progress display mode.
func (b *Builder) WithProgressMode(mode ProgressMode) *Builder {
	b.ProgressMode = mode
	return b
}

// WithShowLogs enables or disables log output from build steps.
func (b *Builder) WithShowLogs(show bool) *Builder {
	b.ShowLogs = show
	return b
}

// WithCacheMounts sets the cache mounts to use for build steps.
func (b *Builder) WithCacheMounts(mounts []CacheMount) *Builder {
	b.pipeline.CacheMounts = mounts
	return b
}

// WithDefaultCacheMounts enables the default cache mounts for common
// package managers (Go, Python, Rust, Node.js, etc.).
func (b *Builder) WithDefaultCacheMounts() *Builder {
	b.pipeline.CacheMounts = DefaultCacheMounts()
	return b
}

// Close closes the BuildKit connection.
func (b *Builder) Close() error {
	return b.client.Close()
}

// BuildConfig contains configuration for a build.
type BuildConfig struct {
	// PackageName is the name of the package being built.
	PackageName string

	// Arch is the target architecture.
	Arch apko_types.Architecture

	// Pipelines are the main package pipelines to execute.
	Pipelines []config.Pipeline

	// Subpackages are the subpackage configurations.
	Subpackages []config.Subpackage

	// BaseEnv is the base environment for pipeline execution.
	BaseEnv map[string]string

	// SourceDir is the directory containing source files to copy into the build.
	SourceDir string

	// WorkspaceDir is the directory where build output will be exported.
	WorkspaceDir string

	// CacheDir is the host directory to mount at /var/cache/melange.
	// This enables sharing cached artifacts (fetch downloads, Go modules, etc.)
	// from the host filesystem into the build.
	CacheDir string

	// Debug enables shell debugging (set -x).
	Debug bool
}

// Build executes a build using BuildKit.
// It takes an apko layer, runs the pipelines, and exports the workspace.
func (b *Builder) Build(ctx context.Context, layer v1.Layer, cfg *BuildConfig) error {
	log := clog.FromContext(ctx)

	// Load the apko layer
	log.Info("loading apko layer into BuildKit")
	loadResult, err := b.loader.LoadLayer(ctx, layer, cfg.PackageName)
	if err != nil {
		return fmt.Errorf("loading apko layer: %w", err)
	}
	defer func() {
		if err := loadResult.Cleanup(); err != nil {
			log.Warnf("cleanup failed: %v", err)
		}
	}()

	// Start from scratch and copy the apko rootfs
	log.Info("building LLB graph")
	state := llb.Scratch().File(
		llb.Copy(llb.Local(loadResult.LocalName), "/", "/"),
		llb.WithCustomName("copy apko rootfs"),
	)

	// Prepare workspace directories
	state = PrepareWorkspace(state, cfg.PackageName)

	// If we have source files, copy them to the workspace
	localDirs := map[string]string{
		loadResult.LocalName: loadResult.ExtractDir,
	}

	if cfg.SourceDir != "" {
		// Only mount source directory if it exists
		if _, err := os.Stat(cfg.SourceDir); err == nil {
			sourceLocalName := "source"
			state = CopySourceToWorkspace(state, sourceLocalName)
			localDirs[sourceLocalName] = cfg.SourceDir
		}
	}

	// If we have a cache directory, copy it to /var/cache/melange
	if cfg.CacheDir != "" {
		log.Infof("copying cache from %s to %s", cfg.CacheDir, DefaultCacheDir)
		state = CopyCacheToWorkspace(state, CacheLocalName)
		localDirs[CacheLocalName] = cfg.CacheDir
	}

	// Create subpackage output directories
	for _, sp := range cfg.Subpackages {
		state = state.File(
			llb.Mkdir(WorkspaceOutputDir(sp.Name), 0755, llb.WithParents(true)),
			llb.WithCustomName(fmt.Sprintf("create output directory for %s", sp.Name)),
		)
	}

	// Configure the pipeline builder
	b.pipeline.Debug = cfg.Debug
	if cfg.BaseEnv != nil {
		b.pipeline.BaseEnv = MergeEnv(b.pipeline.BaseEnv, cfg.BaseEnv)
	}

	// Run main pipelines
	log.Info("running main pipelines")
	state, err = b.pipeline.BuildPipelines(state, cfg.Pipelines)
	if err != nil {
		return fmt.Errorf("building main pipelines: %w", err)
	}

	// Run subpackage pipelines
	for _, sp := range cfg.Subpackages {
		log.Infof("running pipelines for subpackage %s", sp.Name)
		state, err = b.pipeline.BuildPipelines(state, sp.Pipeline)
		if err != nil {
			return fmt.Errorf("building subpackage %s pipelines: %w", sp.Name, err)
		}
	}

	// Export the workspace
	log.Info("exporting workspace")
	exportState := ExportWorkspace(state)

	// Marshal to LLB definition
	ociPlatform := cfg.Arch.ToOCIPlatform()
	platform := llb.Platform(ocispecs.Platform{
		OS:           ociPlatform.OS,
		Architecture: ociPlatform.Architecture,
		Variant:      ociPlatform.Variant,
	})
	def, err := exportState.Marshal(ctx, platform)
	if err != nil {
		return fmt.Errorf("marshaling LLB: %w", err)
	}

	// Ensure output directory exists
	if err := os.MkdirAll(cfg.WorkspaceDir, 0755); err != nil {
		return fmt.Errorf("creating workspace dir: %w", err)
	}

	melangeOutDir := filepath.Join(cfg.WorkspaceDir, "melange-out")
	if err := os.MkdirAll(melangeOutDir, 0755); err != nil {
		return fmt.Errorf("creating melange-out dir: %w", err)
	}

	// Create progress writer
	progress := NewProgressWriter(os.Stderr, b.ProgressMode, b.ShowLogs)

	// Solve and export with progress tracking
	log.Info("solving build graph")

	statusCh := make(chan *client.SolveStatus)
	eg, egCtx := errgroup.WithContext(ctx)

	// Progress display goroutine
	eg.Go(func() error {
		return progress.Write(egCtx, statusCh)
	})

	// Solve goroutine
	eg.Go(func() error {
		_, err := b.client.Client().Solve(ctx, def, client.SolveOpt{
			LocalDirs: localDirs,
			Exports: []client.ExportEntry{{
				Type:      client.ExporterLocal,
				OutputDir: melangeOutDir,
			}},
		}, statusCh)
		return err
	})

	if err := eg.Wait(); err != nil {
		return fmt.Errorf("solving build: %w", err)
	}

	log.Info("build completed successfully")
	return nil
}

// TestConfig contains configuration for running tests.
type TestConfig struct {
	// PackageName is the name of the package being tested.
	PackageName string

	// Arch is the target architecture.
	Arch apko_types.Architecture

	// TestPipelines are the main package test pipelines to execute.
	TestPipelines []config.Pipeline

	// SubpackageTests are the subpackage test configurations.
	// IMPORTANT: Each subpackage test runs in a FRESH container to ensure
	// isolation and avoid masking missing dependencies.
	SubpackageTests []SubpackageTestConfig

	// BaseEnv is the base environment for test execution.
	BaseEnv map[string]string

	// SourceDir is the directory containing test fixtures to copy into the workspace.
	SourceDir string

	// WorkspaceDir is the directory where test results will be exported.
	// Unlike builds, tests only export marker files to indicate success.
	WorkspaceDir string

	// CacheDir is the host directory to mount at /var/cache/melange.
	CacheDir string

	// Debug enables shell debugging (set -x).
	Debug bool
}

// SubpackageTestConfig contains test configuration for a single subpackage.
type SubpackageTestConfig struct {
	// Name is the subpackage name.
	Name string

	// Pipelines are the test pipelines for this subpackage.
	Pipelines []config.Pipeline
}

// Test executes tests using BuildKit.
// Unlike Build, Test:
// - Runs in an environment with the package already installed
// - Each subpackage test runs in a FRESH container (isolation)
// - Exports test result markers instead of package files
func (b *Builder) Test(ctx context.Context, layer v1.Layer, cfg *TestConfig) error {
	log := clog.FromContext(ctx)

	// Run main package tests if any
	if len(cfg.TestPipelines) > 0 {
		log.Info("running main package tests")
		if err := b.runTestPipelines(ctx, layer, cfg.PackageName, cfg.TestPipelines, cfg); err != nil {
			return fmt.Errorf("main package tests failed: %w", err)
		}
		log.Info("main package tests passed")
	}

	// Run each subpackage test in isolation
	// CRITICAL: Each subpackage gets a fresh container to avoid masking
	// missing dependencies
	for _, spTest := range cfg.SubpackageTests {
		if len(spTest.Pipelines) == 0 {
			continue
		}

		log.Infof("running tests for subpackage %s", spTest.Name)
		if err := b.runTestPipelines(ctx, layer, spTest.Name, spTest.Pipelines, cfg); err != nil {
			return fmt.Errorf("subpackage %s tests failed: %w", spTest.Name, err)
		}
		log.Infof("subpackage %s tests passed", spTest.Name)
	}

	log.Info("all tests passed")
	return nil
}

// runTestPipelines runs test pipelines for a single package/subpackage.
// Each invocation uses a fresh container to ensure isolation.
func (b *Builder) runTestPipelines(ctx context.Context, layer v1.Layer, pkgName string, pipelines []config.Pipeline, cfg *TestConfig) error {
	log := clog.FromContext(ctx)

	// Load the apko layer (fresh for each test to ensure isolation)
	loadResult, err := b.loader.LoadLayer(ctx, layer, pkgName+"-test")
	if err != nil {
		return fmt.Errorf("loading apko layer: %w", err)
	}
	defer func() {
		if err := loadResult.Cleanup(); err != nil {
			log.Warnf("cleanup failed: %v", err)
		}
	}()

	// Start from scratch and copy the apko rootfs
	state := llb.Scratch().File(
		llb.Copy(llb.Local(loadResult.LocalName), "/", "/"),
		llb.WithCustomName(fmt.Sprintf("copy test environment for %s", pkgName)),
	)

	// Prepare workspace (simpler than build - no output dirs needed)
	state = state.File(
		llb.Mkdir(DefaultWorkDir, 0755, llb.WithParents(true)),
		llb.WithCustomName("create workspace"),
	)

	localDirs := map[string]string{
		loadResult.LocalName: loadResult.ExtractDir,
	}

	// Copy test fixtures from source directory if provided
	if cfg.SourceDir != "" {
		// Only mount source directory if it exists
		if _, err := os.Stat(cfg.SourceDir); err == nil {
			sourceLocalName := "test-source"
			state = state.File(
				llb.Copy(llb.Local(sourceLocalName), "/", DefaultWorkDir, &llb.CopyInfo{
					CopyDirContentsOnly: true,
				}),
				llb.WithCustomName("copy test fixtures"),
			)
			localDirs[sourceLocalName] = cfg.SourceDir
		}
	}

	// Copy cache directory if provided
	if cfg.CacheDir != "" {
		state = CopyCacheToWorkspace(state, CacheLocalName)
		localDirs[CacheLocalName] = cfg.CacheDir
	}

	// Configure pipeline builder for this test run
	pipelineBuilder := NewPipelineBuilder()
	pipelineBuilder.Debug = cfg.Debug
	if cfg.BaseEnv != nil {
		pipelineBuilder.BaseEnv = MergeEnv(pipelineBuilder.BaseEnv, cfg.BaseEnv)
	}
	pipelineBuilder.CacheMounts = b.pipeline.CacheMounts

	// Run test pipelines
	state, err = pipelineBuilder.BuildPipelines(state, pipelines)
	if err != nil {
		return fmt.Errorf("building test pipelines: %w", err)
	}

	// Create a marker file to indicate test success
	// This allows e2e tests to verify that tests actually ran
	testResultDir := fmt.Sprintf("/test-results/%s", pkgName)
	state = state.Run(
		llb.Args([]string{"/bin/sh", "-c", fmt.Sprintf(
			"mkdir -p %s && echo 'PASSED' > %s/status.txt",
			testResultDir, testResultDir,
		)}),
		llb.WithCustomName(fmt.Sprintf("mark %s tests as passed", pkgName)),
	).Root()

	// Export test results
	exportState := llb.Scratch().File(
		llb.Copy(state, "/test-results/", "/", &llb.CopyInfo{
			CopyDirContentsOnly: true,
		}),
		llb.WithCustomName("export test results"),
	)

	// Marshal to LLB definition
	ociPlatform := cfg.Arch.ToOCIPlatform()
	platform := llb.Platform(ocispecs.Platform{
		OS:           ociPlatform.OS,
		Architecture: ociPlatform.Architecture,
		Variant:      ociPlatform.Variant,
	})
	def, err := exportState.Marshal(ctx, platform)
	if err != nil {
		return fmt.Errorf("marshaling LLB: %w", err)
	}

	// Ensure output directory exists
	if err := os.MkdirAll(cfg.WorkspaceDir, 0755); err != nil {
		return fmt.Errorf("creating workspace dir: %w", err)
	}

	testResultsDir := filepath.Join(cfg.WorkspaceDir, "test-results")
	if err := os.MkdirAll(testResultsDir, 0755); err != nil {
		return fmt.Errorf("creating test-results dir: %w", err)
	}

	// Create progress writer
	progress := NewProgressWriter(os.Stderr, b.ProgressMode, b.ShowLogs)

	// Solve and export
	statusCh := make(chan *client.SolveStatus)
	eg, egCtx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		return progress.Write(egCtx, statusCh)
	})

	eg.Go(func() error {
		_, err := b.client.Client().Solve(ctx, def, client.SolveOpt{
			LocalDirs: localDirs,
			Exports: []client.ExportEntry{{
				Type:      client.ExporterLocal,
				OutputDir: testResultsDir,
			}},
		}, statusCh)
		return err
	})

	if err := eg.Wait(); err != nil {
		return fmt.Errorf("test execution failed: %w", err)
	}

	return nil
}
