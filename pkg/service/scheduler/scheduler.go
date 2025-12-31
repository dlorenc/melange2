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

// Package scheduler provides build scheduling and execution.
package scheduler

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dlorenc/melange2/pkg/build"
	"github.com/dlorenc/melange2/pkg/service/buildkit"
	"github.com/dlorenc/melange2/pkg/service/storage"
	"github.com/dlorenc/melange2/pkg/service/store"
	"github.com/dlorenc/melange2/pkg/service/tracing"
	"github.com/dlorenc/melange2/pkg/service/types"
)

// Config holds scheduler configuration.
type Config struct {
	// OutputDir is the base directory for build outputs (used with local storage).
	OutputDir string
	// PollInterval is how often to check for new builds.
	PollInterval time.Duration
	// MaxParallel is the maximum number of concurrent package builds.
	// Defaults to number of CPUs.
	MaxParallel int
	// CacheRegistry is the registry URL for BuildKit cache.
	// If empty, caching is disabled.
	// Example: "registry:5000/melange-cache"
	CacheRegistry string
	// CacheMode is the cache export mode: "min" or "max".
	// Defaults to "max" if empty.
	CacheMode string
	// ApkoRegistry is the registry URL for caching apko base images.
	// When set, apko-generated layers are pushed to this registry and
	// referenced via llb.Image() instead of being extracted to disk.
	// This provides significant performance benefits for subsequent builds.
	// Example: "registry:5000/apko-cache"
	ApkoRegistry string
	// ApkoRegistryInsecure allows connecting to the apko registry over HTTP.
	// This should only be used for in-cluster registries.
	ApkoRegistryInsecure bool
}

// Scheduler processes builds.
type Scheduler struct {
	buildStore store.BuildStore
	storage    storage.Storage
	pool       *buildkit.Pool
	config     Config

	// sem is a semaphore for limiting concurrent builds
	sem chan struct{}
	// buildMu protects concurrent build processing
	buildMu sync.Mutex
	// activeBuilds tracks which builds are being processed
	activeBuilds map[string]bool
}

// New creates a new scheduler.
func New(buildStore store.BuildStore, storageBackend storage.Storage, pool *buildkit.Pool, config Config) *Scheduler {
	if config.PollInterval == 0 {
		config.PollInterval = time.Second
	}
	if config.OutputDir == "" {
		config.OutputDir = "/var/lib/melange/output"
	}
	if config.MaxParallel == 0 {
		// Default to pool's total capacity for optimal throughput.
		// Falls back to NumCPU if pool capacity is somehow 0.
		config.MaxParallel = pool.TotalCapacity()
		if config.MaxParallel == 0 {
			config.MaxParallel = runtime.NumCPU()
		}
	}
	return &Scheduler{
		buildStore:   buildStore,
		storage:      storageBackend,
		pool:         pool,
		config:       config,
		sem:          make(chan struct{}, config.MaxParallel),
		activeBuilds: make(map[string]bool),
	}
}

// Run starts the scheduler loop. It blocks until the context is cancelled.
func (s *Scheduler) Run(ctx context.Context) error {
	log := clog.FromContext(ctx)
	log.Info("scheduler started")

	ticker := time.NewTicker(s.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("scheduler stopping")
			return ctx.Err()
		case <-ticker.C:
			// Process builds
			if err := s.processBuilds(ctx); err != nil {
				log.Errorf("error processing builds: %v", err)
			}
		}
	}
}

// processBuilds processes builds.
func (s *Scheduler) processBuilds(ctx context.Context) error {
	builds, err := s.buildStore.ListBuilds(ctx)
	if err != nil {
		return fmt.Errorf("listing builds: %w", err)
	}

	for _, build := range builds {
		// Only process pending or running builds
		if build.Status != types.BuildStatusPending && build.Status != types.BuildStatusRunning {
			continue
		}

		// Check if we're already processing this build
		s.buildMu.Lock()
		if s.activeBuilds[build.ID] {
			s.buildMu.Unlock()
			continue
		}
		s.activeBuilds[build.ID] = true
		s.buildMu.Unlock()

		// Process the build in a goroutine
		go func(b *types.Build) {
			defer func() {
				s.buildMu.Lock()
				delete(s.activeBuilds, b.ID)
				s.buildMu.Unlock()
			}()
			s.processBuild(ctx, b)
		}(build)
	}

	return nil
}

// processBuild processes a single multi-package build.
func (s *Scheduler) processBuild(ctx context.Context, build *types.Build) {
	ctx, span := tracing.StartSpan(ctx, "scheduler.processBuild",
		trace.WithAttributes(
			attribute.String("build_id", build.ID),
			attribute.Int("package_count", len(build.Packages)),
		),
	)
	defer span.End()

	buildTimer := tracing.NewTimer(ctx, "processBuild")
	defer func() {
		buildTimer.StopWithAttrs(
			attribute.String("build_id", build.ID),
			attribute.String("status", string(build.Status)),
		)
	}()

	log := clog.FromContext(ctx)
	log.Infof("processing build %s with %d packages", build.ID, len(build.Packages))

	// Update build status to running if pending
	if build.Status == types.BuildStatusPending {
		now := time.Now()
		build.Status = types.BuildStatusRunning
		build.StartedAt = &now
		if err := s.buildStore.UpdateBuild(ctx, build); err != nil {
			log.Errorf("failed to update build %s to running: %v", build.ID, err)
			tracing.RecordError(ctx, err)
			return
		}
	}

	// Process packages until no more are ready
	var wg sync.WaitGroup
	for {
		// Try to acquire a semaphore slot
		select {
		case s.sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return
		}

		// Try to claim a ready package
		pkg, err := s.buildStore.ClaimReadyPackage(ctx, build.ID)
		if err != nil {
			<-s.sem // Release slot
			log.Errorf("error claiming package for build %s: %v", build.ID, err)
			break
		}
		if pkg == nil {
			<-s.sem // Release slot
			// No ready packages, check if we're done
			break
		}

		// Execute package build in goroutine
		wg.Add(1)
		go func(p *types.PackageJob) {
			defer wg.Done()
			defer func() { <-s.sem }()
			s.executePackageBuild(ctx, build.ID, p)
		}(pkg)
	}

	// Wait for all in-flight builds
	wg.Wait()

	// Check if more packages are ready (dependencies may have completed)
	pkg, _ := s.buildStore.ClaimReadyPackage(ctx, build.ID)
	if pkg != nil {
		// More work to do, will be picked up on next tick
		// Release the claimed package back to pending
		pkg.Status = types.PackageStatusPending
		pkg.StartedAt = nil
		_ = s.buildStore.UpdatePackageJob(ctx, build.ID, pkg)
		return
	}

	// Update final build status
	s.updateBuildStatus(ctx, build.ID)
}

// executePackageBuild executes a single package build within a multi-package build.
func (s *Scheduler) executePackageBuild(ctx context.Context, buildID string, pkg *types.PackageJob) {
	ctx, span := tracing.StartSpan(ctx, "scheduler.executePackageBuild",
		trace.WithAttributes(
			attribute.String("build_id", buildID),
			attribute.String("package_name", pkg.Name),
		),
	)
	defer span.End()

	pkgTimer := tracing.NewTimer(ctx, fmt.Sprintf("package_build[%s]", pkg.Name))

	log := clog.FromContext(ctx)
	log.Infof("building package %s in build %s", pkg.Name, buildID)

	// Get the build spec for common options
	build, err := s.buildStore.GetBuild(ctx, buildID)
	if err != nil {
		log.Errorf("failed to get build %s: %v", buildID, err)
		tracing.RecordError(ctx, err)
		s.markPackageFailed(ctx, buildID, pkg, fmt.Errorf("getting build: %w", err))
		return
	}

	// Create a job-like structure for the package build
	jobID := fmt.Sprintf("%s-%s", buildID, pkg.Name)

	// Execute the build
	buildErr := s.executePackageJob(ctx, jobID, pkg, build.Spec)

	// Update package status
	now := time.Now()
	pkg.FinishedAt = &now

	duration := pkgTimer.Stop()

	if buildErr != nil {
		pkg.Status = types.PackageStatusFailed
		pkg.Error = buildErr.Error()
		span.SetAttributes(attribute.String("error", buildErr.Error()))
		tracing.RecordError(ctx, buildErr)
		log.Errorf("package %s failed after %s: %v", pkg.Name, duration, buildErr)

		// Mark dependent packages as skipped
		s.cascadeFailure(ctx, buildID, pkg.Name)
	} else {
		pkg.Status = types.PackageStatusSuccess
		log.Infof("package %s completed successfully in %s", pkg.Name, duration)
	}

	span.SetAttributes(
		attribute.String("status", string(pkg.Status)),
		attribute.String("duration", duration.String()),
	)

	if err := s.buildStore.UpdatePackageJob(ctx, buildID, pkg); err != nil {
		log.Errorf("failed to update package %s: %v", pkg.Name, err)
	}
}

// executePackageJob executes a package build with the given spec.
func (s *Scheduler) executePackageJob(ctx context.Context, jobID string, pkg *types.PackageJob, spec types.BuildSpec) error {
	ctx, span := tracing.StartSpan(ctx, "scheduler.executePackageJob",
		trace.WithAttributes(
			attribute.String("job_id", jobID),
			attribute.String("package_name", pkg.Name),
		),
	)
	defer span.End()

	log := clog.FromContext(ctx)

	// Phase 1: Setup temp files
	setupTimer := tracing.NewTimer(ctx, "phase_setup")

	// Create temp directory for the config file
	tmpDir, err := os.MkdirTemp("", "melange-pkg-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write the config YAML to a temp file
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(pkg.ConfigYAML), 0600); err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}

	// Write inline pipelines to a temp directory
	pipelineDir := filepath.Join(tmpDir, "pipelines")
	pipelines := pkg.Pipelines
	if pipelines == nil {
		pipelines = spec.Pipelines
	}
	if len(pipelines) > 0 {
		for pipelinePath, pipelineContent := range pipelines {
			fullPath := filepath.Join(pipelineDir, pipelinePath)
			if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
				return fmt.Errorf("creating pipeline dir for %s: %w", pipelinePath, err)
			}
			if err := os.WriteFile(fullPath, []byte(pipelineContent), 0600); err != nil {
				return fmt.Errorf("writing pipeline %s: %w", pipelinePath, err)
			}
		}
	}

	// Write inline source files to a temp directory
	sourceDir := filepath.Join(tmpDir, "sources")
	sourceFiles := pkg.SourceFiles
	if sourceFiles == nil && spec.SourceFiles != nil {
		// Fall back to build-level source files for this package
		sourceFiles = spec.SourceFiles[pkg.Name]
	}
	if len(sourceFiles) > 0 {
		for filePath, fileContent := range sourceFiles {
			fullPath := filepath.Join(sourceDir, filePath)
			if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
				return fmt.Errorf("creating source dir for %s: %w", filePath, err)
			}
			if err := os.WriteFile(fullPath, []byte(fileContent), 0600); err != nil {
				return fmt.Errorf("writing source file %s: %w", filePath, err)
			}
		}
	}

	// Get output directory from storage backend
	outputDir, err := s.storage.OutputDir(ctx, jobID)
	if err != nil {
		return fmt.Errorf("getting output dir: %w", err)
	}
	defer func() {
		if outputDir != filepath.Join(s.config.OutputDir, jobID) {
			os.RemoveAll(outputDir)
		}
	}()
	pkg.OutputPath = outputDir

	// Create log directory
	logDir := filepath.Join(outputDir, "logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("creating log dir: %w", err)
	}

	// Create log file
	logPath := filepath.Join(logDir, "build.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("creating log file: %w", err)
	}
	defer logFile.Close()
	pkg.LogPath = logPath

	setupDuration := setupTimer.Stop()
	span.AddEvent("setup_complete", trace.WithAttributes(
		attribute.String("duration", setupDuration.String()),
	))

	// Create a multi-writer logger
	multiWriter := io.MultiWriter(os.Stderr, logFile)
	buildLogger := clog.New(slog.NewTextHandler(multiWriter, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx = clog.WithLogger(ctx, buildLogger)

	// Write build header
	fmt.Fprintf(logFile, "=== Package build started at %s ===\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(logFile, "Package: %s\n", pkg.Name)
	fmt.Fprintf(logFile, "Job ID: %s\n", jobID)

	// Determine architecture
	arch := spec.Arch
	if arch == "" {
		arch = runtime.GOARCH
		if arch == "arm64" {
			arch = "aarch64"
		} else if arch == "amd64" {
			arch = "x86_64"
		}
	}
	targetArch := apko_types.ParseArchitecture(arch)
	span.SetAttributes(attribute.String("arch", arch))

	// Phase 2: Backend selection
	backendTimer := tracing.NewTimer(ctx, "phase_backend_selection")

	// Atomically select and acquire a backend slot
	backend, err := s.pool.SelectAndAcquireWithContext(ctx, arch, spec.BackendSelector)
	if err != nil {
		return fmt.Errorf("selecting backend: %w", err)
	}

	backendDuration := backendTimer.Stop()
	span.AddEvent("backend_selected", trace.WithAttributes(
		attribute.String("backend_addr", backend.Addr),
		attribute.String("duration", backendDuration.String()),
	))

	// Track build success for circuit breaker
	var buildSuccess bool
	defer func() {
		s.pool.Release(backend.Addr, buildSuccess)
	}()

	pkg.Backend = &types.Backend{
		Addr:   backend.Addr,
		Arch:   backend.Arch,
		Labels: backend.Labels,
	}

	span.SetAttributes(attribute.String("backend_addr", backend.Addr))
	log.Infof("building package %s for architecture: %s on backend %s", pkg.Name, targetArch, backend.Addr)

	// Create cache directory
	cacheDir := filepath.Join(tmpDir, "cache")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return fmt.Errorf("creating cache dir: %w", err)
	}

	// Set up build options
	opts := []build.Option{
		build.WithConfig(configPath),
		build.WithArch(targetArch),
		build.WithOutDir(outputDir),
		build.WithCacheDir(cacheDir),
		build.WithBuildKitAddr(backend.Addr),
		build.WithDebug(spec.Debug),
		build.WithGenerateIndex(true),
		build.WithExtraRepos([]string{"https://packages.wolfi.dev/os"}),
		build.WithExtraKeys([]string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"}),
		build.WithIgnoreSignatures(true),
		build.WithConfigFileRepositoryURL("https://melange-service/inline"),
		build.WithConfigFileRepositoryCommit("inline-" + jobID),
		build.WithConfigFileLicense("Apache-2.0"),
		build.WithNamespace("wolfi"),
	}

	// Add cache config if registry is configured
	if s.config.CacheRegistry != "" {
		opts = append(opts, build.WithCacheRegistry(s.config.CacheRegistry))
		if s.config.CacheMode != "" {
			opts = append(opts, build.WithCacheMode(s.config.CacheMode))
		}
	}

	// Add apko registry config if configured
	// This enables caching apko base images for faster subsequent builds
	if s.config.ApkoRegistry != "" {
		opts = append(opts, build.WithApkoRegistry(s.config.ApkoRegistry))
		opts = append(opts, build.WithApkoRegistryInsecure(s.config.ApkoRegistryInsecure))
	}

	if len(pipelines) > 0 {
		opts = append(opts, build.WithPipelineDir(pipelineDir))
	}

	// Add source directory if source files were provided
	if len(sourceFiles) > 0 {
		opts = append(opts, build.WithSourceDir(sourceDir))
	}

	// Phase 3: Build initialization
	initTimer := tracing.NewTimer(ctx, "phase_build_init")

	// Create the build context
	bc, err := build.New(ctx, opts...)
	if err != nil {
		return fmt.Errorf("initializing build: %w", err)
	}
	defer bc.Close(ctx)

	initDuration := initTimer.Stop()
	span.AddEvent("build_initialized", trace.WithAttributes(
		attribute.String("duration", initDuration.String()),
	))

	// Phase 4: BuildKit execution
	buildkitTimer := tracing.NewTimer(ctx, "phase_buildkit_execution")
	log.Infof("starting BuildKit execution for package %s", pkg.Name)

	// Execute the build
	if err := bc.BuildPackage(ctx); err != nil {
		buildkitDuration := buildkitTimer.Stop()
		span.AddEvent("buildkit_failed", trace.WithAttributes(
			attribute.String("duration", buildkitDuration.String()),
			attribute.String("error", err.Error()),
		))
		log.Errorf("BuildKit execution failed after %s: %v", buildkitDuration, err)

		if syncErr := s.storage.SyncOutputDir(ctx, jobID, outputDir); syncErr != nil {
			log.Errorf("failed to sync output on error: %v", syncErr)
		}
		return fmt.Errorf("building package: %w", err)
	}

	buildkitDuration := buildkitTimer.Stop()
	span.AddEvent("buildkit_complete", trace.WithAttributes(
		attribute.String("duration", buildkitDuration.String()),
	))
	log.Infof("BuildKit execution completed in %s for package %s", buildkitDuration, pkg.Name)

	// Phase 5: Storage sync
	syncTimer := tracing.NewTimer(ctx, "phase_storage_sync")
	log.Infof("syncing output to storage for package %s", pkg.Name)

	// Sync output to storage backend
	if err := s.storage.SyncOutputDir(ctx, jobID, outputDir); err != nil {
		return fmt.Errorf("syncing output to storage: %w", err)
	}

	syncDuration := syncTimer.Stop()
	span.AddEvent("storage_sync_complete", trace.WithAttributes(
		attribute.String("duration", syncDuration.String()),
	))
	log.Infof("storage sync completed in %s for package %s", syncDuration, pkg.Name)

	// Log phase breakdown
	log.Infof("package %s phase breakdown: setup=%s, backend=%s, init=%s, buildkit=%s, sync=%s",
		pkg.Name, setupDuration, backendDuration, initDuration, buildkitDuration, syncDuration)

	buildSuccess = true
	return nil
}

// markPackageFailed marks a package as failed.
func (s *Scheduler) markPackageFailed(ctx context.Context, buildID string, pkg *types.PackageJob, err error) {
	now := time.Now()
	pkg.Status = types.PackageStatusFailed
	pkg.FinishedAt = &now
	pkg.Error = err.Error()
	_ = s.buildStore.UpdatePackageJob(ctx, buildID, pkg)
	s.cascadeFailure(ctx, buildID, pkg.Name)
}

// cascadeFailure marks packages that depend on the failed package as skipped.
func (s *Scheduler) cascadeFailure(ctx context.Context, buildID, failedPkg string) {
	log := clog.FromContext(ctx)

	build, err := s.buildStore.GetBuild(ctx, buildID)
	if err != nil {
		log.Errorf("failed to get build for cascade: %v", err)
		return
	}

	// Build a set of packages in this build
	inBuild := make(map[string]bool)
	for _, pkg := range build.Packages {
		inBuild[pkg.Name] = true
	}

	// Find and mark dependent packages
	for i := range build.Packages {
		pkg := &build.Packages[i]
		if pkg.Status != types.PackageStatusPending && pkg.Status != types.PackageStatusBlocked {
			continue
		}

		// Check if this package depends on the failed one
		for _, dep := range pkg.Dependencies {
			if !inBuild[dep] {
				continue
			}
			if dep == failedPkg {
				pkg.Status = types.PackageStatusSkipped
				pkg.Error = fmt.Sprintf("dependency %s failed", failedPkg)
				if err := s.buildStore.UpdatePackageJob(ctx, buildID, pkg); err != nil {
					log.Errorf("failed to mark %s as skipped: %v", pkg.Name, err)
				}
				// Cascade further
				s.cascadeFailure(ctx, buildID, pkg.Name)
				break
			}
		}
	}
}

// updateBuildStatus updates the overall build status based on package statuses.
func (s *Scheduler) updateBuildStatus(ctx context.Context, buildID string) {
	log := clog.FromContext(ctx)

	build, err := s.buildStore.GetBuild(ctx, buildID)
	if err != nil {
		log.Errorf("failed to get build for status update: %v", err)
		return
	}

	var (
		pending   int
		running   int
		success   int
		failed    int
		skipped   int
	)

	for _, pkg := range build.Packages {
		switch pkg.Status {
		case types.PackageStatusPending, types.PackageStatusBlocked:
			pending++
		case types.PackageStatusRunning:
			running++
		case types.PackageStatusSuccess:
			success++
		case types.PackageStatusFailed:
			failed++
		case types.PackageStatusSkipped:
			skipped++
		}
	}

	total := len(build.Packages)

	// Determine overall status
	var newStatus types.BuildStatus
	switch {
	case running > 0 || pending > 0:
		newStatus = types.BuildStatusRunning
	case success == total:
		newStatus = types.BuildStatusSuccess
	case failed > 0 && success > 0:
		newStatus = types.BuildStatusPartial
	default:
		newStatus = types.BuildStatusFailed
	}

	// Update if changed
	if build.Status != newStatus {
		build.Status = newStatus
		if newStatus != types.BuildStatusRunning {
			now := time.Now()
			build.FinishedAt = &now
		}
		if err := s.buildStore.UpdateBuild(ctx, build); err != nil {
			log.Errorf("failed to update build status: %v", err)
		}
		log.Infof("build %s status: %s (%d success, %d failed, %d skipped)",
			buildID, newStatus, success, failed, skipped)
	}
}
