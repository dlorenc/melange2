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
	"time"

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
// Also sets the corresponding environment variables so tools use the
// correct cache paths.
func (b *Builder) WithDefaultCacheMounts() *Builder {
	b.pipeline.CacheMounts = DefaultCacheMounts()
	// Set environment variables so tools use the cache mount paths
	b.pipeline.BaseEnv = MergeEnv(b.pipeline.BaseEnv, CacheEnvironment())
	return b
}

// Close closes the BuildKit connection.
func (b *Builder) Close() error {
	return b.client.Close()
}

// CacheConfig specifies remote cache configuration for BuildKit.
type CacheConfig struct {
	// Registry is the registry URL for cache storage.
	// Example: "registry:5000/melange-cache"
	// If empty, caching is disabled.
	Registry string

	// Mode controls cache export behavior.
	// "min" - only export layers for final result (smaller, faster export)
	// "max" - export all intermediate layers (better cache hit rate)
	// Defaults to "max" if empty.
	Mode string
}

// ApkoRegistryConfig specifies configuration for caching apko base images in a registry.
// When configured, apko layers are pushed to the registry and referenced via llb.Image()
// instead of being extracted to disk and referenced via llb.Local(). This provides
// significant performance benefits:
// - BuildKit can cache layers by content address
// - Subsequent builds with same environment skip apko entirely
// - No disk extraction overhead
type ApkoRegistryConfig struct {
	// Registry is the registry URL for cached apko images.
	// Example: "registry:5000/apko-cache"
	// If empty, the traditional llb.Local() approach is used.
	Registry string

	// Insecure allows connecting to registries over HTTP.
	Insecure bool
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

	// ExportOnFailure specifies how to export the build environment on failure.
	// Valid values: "" (disabled), "tarball", "docker", "registry"
	ExportOnFailure string

	// ExportRef is the path or image reference for debug image export.
	// For tarball: file path (e.g., "/tmp/debug.tar")
	// For docker/registry: image reference (e.g., "debug:failed")
	ExportRef string

	// CacheConfig specifies remote cache configuration.
	// If nil or Registry is empty, caching is disabled.
	CacheConfig *CacheConfig

	// ApkoRegistryConfig specifies configuration for caching apko base images.
	// When set with a non-empty Registry, apko layers are pushed to the registry
	// and referenced via llb.Image() for better caching. If nil or Registry is
	// empty, the traditional llb.Local() approach is used.
	ApkoRegistryConfig *ApkoRegistryConfig

	// ImgConfig is the apko image configuration used to generate the layers.
	// This is used for cache key generation when ApkoRegistryConfig is set.
	ImgConfig *apko_types.ImageConfiguration
}

// Build executes a build using BuildKit.
// It takes a single apko layer, runs the pipelines, and exports the workspace.
// For better cache efficiency, consider using BuildWithLayers instead.
func (b *Builder) Build(ctx context.Context, layer v1.Layer, cfg *BuildConfig) error {
	return b.BuildWithLayers(ctx, []v1.Layer{layer}, cfg)
}

// BuildWithLayers executes a build using BuildKit with multi-layer support.
// It takes multiple apko layers (as produced by apko's BuildLayers), runs the
// pipelines, and exports the workspace.
//
// Using multiple layers provides better BuildKit cache efficiency:
// - Base OS layers (glibc, busybox) change rarely and can be cached
// - Compiler layers (gcc, binutils) change occasionally
// - Package-specific dependencies change more frequently
// Only changed layers need to be rebuilt/transferred.
//
// When ApkoRegistryConfig is set with a non-empty Registry, layers are pushed
// to the registry and referenced via llb.Image() for even better caching.
func (b *Builder) BuildWithLayers(ctx context.Context, layers []v1.Layer, cfg *BuildConfig) error {
	log := clog.FromContext(ctx)

	if len(layers) == 0 {
		return fmt.Errorf("at least one layer is required")
	}

	var state llb.State
	var localDirs map[string]string
	var cleanup func()

	// Check if we should use registry-based caching for apko layers
	if cfg.ApkoRegistryConfig != nil && cfg.ApkoRegistryConfig.Registry != "" && cfg.ImgConfig != nil {
		// Use registry-based approach: push layers to registry, reference via llb.Image()
		log.Infof("using apko registry cache: %s", cfg.ApkoRegistryConfig.Registry)
		loadStart := time.Now()

		cache := NewApkoImageCache(cfg.ApkoRegistryConfig.Registry, cfg.ApkoRegistryConfig.Insecure)
		imgRef, cacheHit, err := cache.GetOrCreate(ctx, *cfg.ImgConfig, layers)
		if err != nil {
			return fmt.Errorf("caching apko image: %w", err)
		}

		loadDuration := time.Since(loadStart)
		if cacheHit {
			log.Infof("apko_registry_cache_hit took %s", loadDuration)
		} else {
			log.Infof("apko_registry_push took %s", loadDuration)
		}

		// Use llb.Image() to reference the cached image
		// BuildKit handles all layer caching automatically
		state = llb.Image(imgRef, llb.WithCustomName("apko base image (cached)"))
		localDirs = make(map[string]string)
		cleanup = func() {} // No cleanup needed for registry-based approach
	} else {
		// Use traditional llb.Local() approach: extract layers to disk
		log.Infof("loading %d apko layer(s) into BuildKit (local mode)", len(layers))
		loadStart := time.Now()
		loadResult, err := b.loader.LoadLayers(ctx, layers, cfg.PackageName)
		loadDuration := time.Since(loadStart)
		if err != nil {
			return fmt.Errorf("loading apko layers: %w", err)
		}
		log.Infof("layer_load took %s", loadDuration)

		state = loadResult.State
		localDirs = make(map[string]string, len(loadResult.LocalDirs))
		for k, v := range loadResult.LocalDirs {
			localDirs[k] = v
		}
		cleanup = func() {
			if err := loadResult.Cleanup(); err != nil {
				log.Warnf("cleanup failed: %v", err)
			}
		}

		log.Infof("building LLB graph with %d layer(s)", loadResult.LayerCount)
	}
	defer cleanup()

	// Prepare workspace directories
	state = PrepareWorkspace(state, cfg.PackageName)

	// If we have source files, copy them to the workspace
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

	// Create subpackage output directories with proper ownership
	for _, sp := range cfg.Subpackages {
		state = state.File(
			llb.Mkdir(WorkspaceOutputDir(sp.Name), 0755,
				llb.WithParents(true),
				llb.WithUIDGID(BuildUserUID, BuildUserGID),
			),
			llb.WithCustomName(fmt.Sprintf("create output directory for %s", sp.Name)),
		)
	}

	// Configure the pipeline builder
	b.pipeline.Debug = cfg.Debug
	if cfg.BaseEnv != nil {
		b.pipeline.BaseEnv = MergeEnv(b.pipeline.BaseEnv, cfg.BaseEnv)
	}

	// Helper to export debug image on failure
	exportOnFailure := func(lastGoodState llb.State, pipelineErr error, context string) error {
		if cfg.ExportOnFailure == "" {
			return fmt.Errorf("%s: %w", context, pipelineErr)
		}

		log.Warnf("build failed at %s, exporting debug image...", context)
		exportCfg := &ExportConfig{
			Type:      ExportType(cfg.ExportOnFailure),
			Ref:       cfg.ExportRef,
			Arch:      cfg.Arch,
			LocalDirs: localDirs,
		}
		if exportErr := b.ExportDebugImage(ctx, lastGoodState, exportCfg); exportErr != nil {
			log.Errorf("failed to export debug image: %v", exportErr)
		}
		return fmt.Errorf("%s: %w", context, pipelineErr)
	}

	// Run main pipelines with recovery support
	log.Info("running main pipelines")
	result := b.pipeline.BuildPipelinesWithRecovery(state, cfg.Pipelines)
	if result.Error != nil {
		return exportOnFailure(result.State, result.Error, "building main pipelines")
	}
	state = result.State

	// Run subpackage pipelines
	for _, sp := range cfg.Subpackages {
		log.Infof("running pipelines for subpackage %s", sp.Name)
		result := b.pipeline.BuildPipelinesWithRecovery(state, sp.Pipeline)
		if result.Error != nil {
			return exportOnFailure(result.State, result.Error, fmt.Sprintf("building subpackage %s pipelines", sp.Name))
		}
		state = result.State
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
	solveStart := time.Now()

	statusCh := make(chan *client.SolveStatus)
	eg, egCtx := errgroup.WithContext(ctx)

	// Progress display goroutine
	eg.Go(func() error {
		return progress.Write(egCtx, statusCh)
	})

	// Solve goroutine
	eg.Go(func() error {
		solveOpt := client.SolveOpt{
			LocalDirs: localDirs,
			Exports: []client.ExportEntry{{
				Type:      client.ExporterLocal,
				OutputDir: melangeOutDir,
			}},
		}

		// Add cache import/export if configured
		if cfg.CacheConfig != nil && cfg.CacheConfig.Registry != "" {
			cacheRef := cfg.CacheConfig.Registry
			mode := cfg.CacheConfig.Mode
			if mode == "" {
				mode = "max"
			}

			log.Infof("using registry cache: %s (mode=%s)", cacheRef, mode)

			// Import from cache
			solveOpt.CacheImports = []client.CacheOptionsEntry{{
				Type: "registry",
				Attrs: map[string]string{
					"ref": cacheRef,
				},
			}}

			// Export to cache
			solveOpt.CacheExports = []client.CacheOptionsEntry{{
				Type: "registry",
				Attrs: map[string]string{
					"ref":  cacheRef,
					"mode": mode,
				},
			}}
		}

		_, err := b.client.Client().Solve(ctx, def, solveOpt, statusCh)
		return err
	})

	if err := eg.Wait(); err != nil {
		return fmt.Errorf("solving build: %w", err)
	}
	solveDuration := time.Since(solveStart)
	log.Infof("graph_solve took %s", solveDuration)

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
	return b.TestWithLayers(ctx, []v1.Layer{layer}, cfg)
}

// TestWithLayers executes tests using BuildKit with multi-layer support.
// Unlike Build, Test:
// - Runs in an environment with the package already installed
// - Each subpackage test runs in a FRESH container (isolation)
// - Exports test result markers instead of package files
//
// Using multiple layers provides better BuildKit cache efficiency.
func (b *Builder) TestWithLayers(ctx context.Context, layers []v1.Layer, cfg *TestConfig) error {
	log := clog.FromContext(ctx)

	if len(layers) == 0 {
		return fmt.Errorf("at least one layer is required")
	}

	// Run main package tests if any
	if len(cfg.TestPipelines) > 0 {
		log.Info("running main package tests")
		if err := b.runTestPipelinesWithLayers(ctx, layers, cfg.PackageName, cfg.TestPipelines, cfg); err != nil {
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
		if err := b.runTestPipelinesWithLayers(ctx, layers, spTest.Name, spTest.Pipelines, cfg); err != nil {
			return fmt.Errorf("subpackage %s tests failed: %w", spTest.Name, err)
		}
		log.Infof("subpackage %s tests passed", spTest.Name)
	}

	log.Info("all tests passed")
	return nil
}

// runTestPipelinesWithLayers runs test pipelines for a single package/subpackage with multi-layer support.
// Each invocation uses fresh layers to ensure isolation.
func (b *Builder) runTestPipelinesWithLayers(ctx context.Context, layers []v1.Layer, pkgName string, pipelines []config.Pipeline, cfg *TestConfig) error {
	log := clog.FromContext(ctx)

	// Load the apko layers (fresh for each test to ensure isolation)
	loadResult, err := b.loader.LoadLayers(ctx, layers, pkgName+"-test")
	if err != nil {
		return fmt.Errorf("loading apko layers: %w", err)
	}
	defer func() {
		if err := loadResult.Cleanup(); err != nil {
			log.Warnf("cleanup failed: %v", err)
		}
	}()

	// Use the pre-built state from LoadLayers which already combines all layers
	state := loadResult.State

	// Ensure build user exists (for images that don't have it, like plain alpine)
	// This is idempotent - if the user already exists, adduser/addgroup will succeed silently
	state = SetupBuildUser(state)

	// Prepare workspace (simpler than build - no output dirs needed)
	// Owned by build user for permission parity with baseline melange
	state = state.File(
		llb.Mkdir(DefaultWorkDir, 0755,
			llb.WithParents(true),
			llb.WithUIDGID(BuildUserUID, BuildUserGID),
		),
		llb.WithCustomName("create workspace"),
	)

	// Start with the layer local dirs from LoadLayers
	localDirs := make(map[string]string, len(loadResult.LocalDirs)+2)
	for k, v := range loadResult.LocalDirs {
		localDirs[k] = v
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

// TestWithImage executes tests using an image reference instead of a layer.
// This is useful for testing when you don't have an apko-built layer,
// such as in e2e tests that use a base image directly.
func (b *Builder) TestWithImage(ctx context.Context, imageRef string, cfg *TestConfig) error {
	log := clog.FromContext(ctx)

	// Run main package tests if any
	if len(cfg.TestPipelines) > 0 {
		log.Info("running main package tests")
		if err := b.runTestPipelinesWithImage(ctx, imageRef, cfg.PackageName, cfg.TestPipelines, cfg); err != nil {
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
		if err := b.runTestPipelinesWithImage(ctx, imageRef, spTest.Name, spTest.Pipelines, cfg); err != nil {
			return fmt.Errorf("subpackage %s tests failed: %w", spTest.Name, err)
		}
		log.Infof("subpackage %s tests passed", spTest.Name)
	}

	log.Info("all tests passed")
	return nil
}

// runTestPipelinesWithImage runs test pipelines using an image reference as the base.
// Each invocation starts fresh from the image to ensure isolation.
func (b *Builder) runTestPipelinesWithImage(ctx context.Context, imageRef string, pkgName string, pipelines []config.Pipeline, cfg *TestConfig) error {
	// Start from the image reference
	state := llb.Image(imageRef)

	// Ensure build user exists (idempotent)
	state = SetupBuildUser(state)

	// Prepare workspace
	state = state.File(
		llb.Mkdir(DefaultWorkDir, 0755,
			llb.WithParents(true),
			llb.WithUIDGID(BuildUserUID, BuildUserGID),
		),
		llb.WithCustomName("create workspace"),
	)

	localDirs := map[string]string{}

	// Copy test fixtures from source directory if provided
	if cfg.SourceDir != "" {
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
	var err error
	state, err = pipelineBuilder.BuildPipelines(state, pipelines)
	if err != nil {
		return fmt.Errorf("building test pipelines: %w", err)
	}

	// Create a marker file to indicate test success
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
