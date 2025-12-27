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
		sourceLocalName := "source"
		state = CopySourceToWorkspace(state, sourceLocalName)
		localDirs[sourceLocalName] = cfg.SourceDir
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
