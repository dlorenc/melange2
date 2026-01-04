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

// Package orchestrator provides build orchestration using HTTP client.
// This is part of Phase 3 of the microservices architecture migration.
// The orchestrator uses HTTP client to communicate with the API server
// for build/package state management, while still using the BuildKit pool
// directly for backend selection (temporary until Phase 5/6).
package orchestrator

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/dlorenc/melange2/pkg/build"
	"github.com/dlorenc/melange2/pkg/service/apko"
	"github.com/dlorenc/melange2/pkg/service/buildkit"
	"github.com/dlorenc/melange2/pkg/service/client"
	"github.com/dlorenc/melange2/pkg/service/metrics"
	"github.com/dlorenc/melange2/pkg/service/scheduler"
	"github.com/dlorenc/melange2/pkg/service/storage"
	"github.com/dlorenc/melange2/pkg/service/tracing"
	"github.com/dlorenc/melange2/pkg/service/types"
)

// Config holds orchestrator configuration.
type Config struct {
	// APIServerURL is the URL of the melange API server.
	// Required for HTTP client communication.
	APIServerURL string
	// OutputDir is the base directory for build outputs (used with local storage).
	OutputDir string
	// PollInterval is how often to check for new builds.
	PollInterval time.Duration
	// MaxParallel is the maximum number of concurrent package builds.
	// Defaults to number of CPUs.
	MaxParallel int
	// CacheRegistry is the registry URL for BuildKit cache.
	// If empty, caching is disabled.
	CacheRegistry string
	// CacheMode is the cache export mode: "min" or "max".
	// Defaults to "max" if empty.
	CacheMode string
	// ApkoRegistry is the registry URL for caching apko base images.
	ApkoRegistry string
	// ApkoRegistryInsecure allows connecting to the apko registry over HTTP.
	ApkoRegistryInsecure bool
	// ApkCacheDir is the directory for caching APK packages.
	ApkCacheDir string
	// ApkCacheTTL is how long to keep APK cache files before eviction.
	ApkCacheTTL time.Duration
	// ApkoServiceAddr is the gRPC address of the apko service.
	ApkoServiceAddr string
	// SecretEnv contains server-side environment variables to inject into all builds.
	SecretEnv map[string]string
	// RetryConfig configures retry behavior for transient BuildKit errors.
	RetryConfig *scheduler.RetryConfig
}

// Orchestrator processes builds using HTTP client for state management.
type Orchestrator struct {
	client      *client.Client
	storage     storage.Storage
	manager     buildkit.Manager
	apkoManager apko.Manager // Optional: Apko Manager for Phase 7 microservices mode
	config      Config
	metrics     *metrics.MelangeMetrics

	// sem is a semaphore for limiting concurrent builds
	sem chan struct{}
	// buildMu protects concurrent build processing
	buildMu sync.Mutex
	// activeBuilds tracks which builds are being processed
	activeBuilds map[string]bool
	// retryConfig configures retry behavior for transient BuildKit errors
	retryConfig scheduler.RetryConfig
}

// OrchestratorOption configures an Orchestrator.
type OrchestratorOption func(*Orchestrator)

// WithMetrics sets the Prometheus metrics for the orchestrator.
func WithMetrics(m *metrics.MelangeMetrics) OrchestratorOption {
	return func(o *Orchestrator) {
		o.metrics = m
	}
}

// WithApkoManager sets the Apko Manager for the orchestrator.
// When set, the orchestrator will use the manager to acquire/release
// apko instances for load balancing and circuit breaking.
func WithApkoManager(m apko.Manager) OrchestratorOption {
	return func(o *Orchestrator) {
		o.apkoManager = m
	}
}

// New creates a new orchestrator with a BuildKit Manager.
// The manager abstracts backend management, allowing for static pools,
// Kubernetes autoscaling, or other implementations.
func New(apiClient *client.Client, storageBackend storage.Storage, manager buildkit.Manager, config Config, opts ...OrchestratorOption) *Orchestrator {
	if config.PollInterval == 0 {
		config.PollInterval = time.Second
	}
	if config.OutputDir == "" {
		config.OutputDir = "/var/lib/melange/output"
	}
	if config.MaxParallel == 0 {
		config.MaxParallel = manager.TotalCapacity()
		if config.MaxParallel == 0 {
			config.MaxParallel = runtime.NumCPU()
		}
	}

	retryConfig := scheduler.DefaultRetryConfig()
	if config.RetryConfig != nil {
		retryConfig = *config.RetryConfig
	}
	if retryConfig.MaxAttempts < 1 {
		retryConfig.MaxAttempts = 1
	}

	o := &Orchestrator{
		client:       apiClient,
		storage:      storageBackend,
		manager:      manager,
		config:       config,
		sem:          make(chan struct{}, config.MaxParallel),
		activeBuilds: make(map[string]bool),
		retryConfig:  retryConfig,
	}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// Run starts the orchestrator loop. It blocks until the context is cancelled.
func (o *Orchestrator) Run(ctx context.Context) error {
	log := clog.FromContext(ctx)
	log.Info("orchestrator started (using HTTP client)")

	// Add jitter to prevent thundering herd
	// #nosec G404 -- math/rand is sufficient for jitter
	jitter := time.Duration(rand.Int63n(int64(o.config.PollInterval / 5)))
	ticker := time.NewTicker(o.config.PollInterval + jitter)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("orchestrator stopping")
			return ctx.Err()
		case <-ticker.C:
			if err := o.processBuilds(ctx); err != nil {
				log.Errorf("error processing builds: %v", err)
			}
		}
	}
}

// processBuilds processes builds via HTTP client.
func (o *Orchestrator) processBuilds(ctx context.Context) error {
	// Use HTTP client to get active builds
	builds, err := o.client.ListActiveBuilds(ctx)
	if err != nil {
		return fmt.Errorf("listing active builds: %w", err)
	}

	// Update metrics
	if o.metrics != nil {
		pendingCount := 0
		for _, b := range builds {
			if b.Status == types.BuildStatusPending {
				pendingCount++
			}
		}
		o.metrics.UpdateQueueDepth(pendingCount)

		managerStatus := o.manager.Status()
		activeJobs := make(map[string]int)
		archByAddr := make(map[string]string)
		for _, ws := range managerStatus.Workers {
			archByAddr[ws.Addr] = ws.Arch
			activeJobs[ws.Addr] = ws.ActiveJobs
		}
		o.metrics.UpdateBackendMetrics(managerStatus.TotalWorkers, managerStatus.AvailableWorkers, activeJobs, archByAddr)
	}

	for _, build := range builds {
		if build.Status != types.BuildStatusPending && build.Status != types.BuildStatusRunning {
			continue
		}

		o.buildMu.Lock()
		if o.activeBuilds[build.ID] {
			o.buildMu.Unlock()
			continue
		}
		o.activeBuilds[build.ID] = true
		o.buildMu.Unlock()

		go func(b *types.Build) {
			defer func() {
				o.buildMu.Lock()
				delete(o.activeBuilds, b.ID)
				o.buildMu.Unlock()
			}()
			o.processBuild(ctx, b)
		}(build)
	}

	return nil
}

// processBuild processes a single multi-package build.
func (o *Orchestrator) processBuild(ctx context.Context, build *types.Build) {
	ctx, span := tracing.StartSpan(ctx, "orchestrator.processBuild",
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
	log.Infof("orchestrator processing build %s with %d packages", build.ID, len(build.Packages))

	// Update build status to running if pending (via HTTP client)
	if build.Status == types.BuildStatusPending {
		_, err := o.client.UpdateBuild(ctx, build.ID, &client.UpdateBuildRequest{
			Status: types.BuildStatusRunning,
		})
		if err != nil {
			log.Errorf("failed to update build %s to running: %v", build.ID, err)
			tracing.RecordError(ctx, err)
			return
		}
		if o.metrics != nil {
			o.metrics.RecordBuildStarted()
		}
	}

	// Process packages until no more are ready
	var wg sync.WaitGroup
	for {
		select {
		case o.sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return
		}

		// Try to claim a ready package via HTTP client
		pkg, err := o.client.ClaimReadyPackage(ctx, build.ID)
		if err != nil {
			<-o.sem
			log.Errorf("error claiming package for build %s: %v", build.ID, err)
			break
		}
		if pkg == nil {
			<-o.sem
			break
		}

		wg.Add(1)
		go func(p *types.PackageJob) {
			defer wg.Done()
			defer func() { <-o.sem }()
			o.executePackageBuild(ctx, build.ID, p)
		}(pkg)
	}

	wg.Wait()

	// Check if more packages are ready
	pkg, _ := o.client.ClaimReadyPackage(ctx, build.ID)
	if pkg != nil {
		// Release claimed package back to pending
		_, _ = o.client.UpdatePackage(ctx, build.ID, pkg.Name, &client.UpdatePackageRequest{
			Status: types.PackageStatusPending,
		})
		return
	}

	// Update final build status
	o.updateBuildStatus(ctx, build.ID)
}

// executePackageBuild executes a single package build.
func (o *Orchestrator) executePackageBuild(ctx context.Context, buildID string, pkg *types.PackageJob) {
	ctx, span := tracing.StartSpan(ctx, "orchestrator.executePackageBuild",
		trace.WithAttributes(
			attribute.String("build_id", buildID),
			attribute.String("package_name", pkg.Name),
		),
	)
	defer span.End()

	pkgTimer := tracing.NewTimer(ctx, fmt.Sprintf("package_build[%s]", pkg.Name))

	log := clog.FromContext(ctx)
	log.Infof("orchestrator building package %s in build %s", pkg.Name, buildID)

	// Get the build spec for common options (via HTTP client)
	build, err := o.client.GetBuild(ctx, buildID)
	if err != nil {
		log.Errorf("failed to get build %s: %v", buildID, err)
		tracing.RecordError(ctx, err)
		o.markPackageFailed(ctx, buildID, pkg, fmt.Errorf("getting build: %w", err))
		return
	}

	jobID := fmt.Sprintf("%s-%s", buildID, pkg.Name)
	buildErr := o.executePackageJob(ctx, jobID, pkg, build.Spec)

	now := time.Now()
	pkg.FinishedAt = &now
	duration := pkgTimer.Stop()

	if buildErr != nil {
		span.SetAttributes(attribute.String("error", buildErr.Error()))
		tracing.RecordError(ctx, buildErr)
		log.Errorf("package %s failed after %s: %v", pkg.Name, duration, buildErr)

		// Update package status to failed via HTTP client
		_, _ = o.client.UpdatePackage(ctx, buildID, pkg.Name, &client.UpdatePackageRequest{
			Status: types.PackageStatusFailed,
			Error:  buildErr.Error(),
		})

		// Cascade failure
		o.cascadeFailure(ctx, buildID, pkg.Name)
	} else {
		log.Infof("package %s completed successfully in %s", pkg.Name, duration)

		// Update package status to success via HTTP client
		_, _ = o.client.UpdatePackage(ctx, buildID, pkg.Name, &client.UpdatePackageRequest{
			Status:     types.PackageStatusSuccess,
			LogPath:    pkg.LogPath,
			OutputPath: pkg.OutputPath,
		})
	}

	// Record metrics
	if o.metrics != nil {
		arch := ""
		if pkg.Backend != nil {
			arch = pkg.Backend.Arch
		}
		if arch == "" {
			arch = build.Spec.Arch
		}
		if arch == "" {
			arch = runtime.GOARCH
			if arch == "arm64" {
				arch = "aarch64"
			} else if arch == "amd64" {
				arch = "x86_64"
			}
		}
		o.metrics.RecordPackageCompleted(string(pkg.Status), arch, duration.Seconds())
	}

	span.SetAttributes(
		attribute.String("status", string(pkg.Status)),
		attribute.String("duration", duration.String()),
	)

	apko_build.ClearPools()
}

// executePackageJob executes a package build with the given spec.
func (o *Orchestrator) executePackageJob(ctx context.Context, jobID string, pkg *types.PackageJob, spec types.BuildSpec) error {
	ctx, span := tracing.StartSpan(ctx, "orchestrator.executePackageJob",
		trace.WithAttributes(
			attribute.String("job_id", jobID),
			attribute.String("package_name", pkg.Name),
		),
	)
	defer span.End()

	log := clog.FromContext(ctx)

	// Phase 1: Setup temp files
	setupTimer := tracing.NewTimer(ctx, "phase_setup")

	tmpDir, err := os.MkdirTemp("", "melange-pkg-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(pkg.ConfigYAML), 0600); err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}

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

	sourceDir := filepath.Join(tmpDir, "sources")
	sourceFiles := pkg.SourceFiles
	if sourceFiles == nil && spec.SourceFiles != nil {
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

	outputDir, err := o.storage.OutputDir(ctx, jobID)
	if err != nil {
		return fmt.Errorf("getting output dir: %w", err)
	}
	defer func() {
		if outputDir != filepath.Join(o.config.OutputDir, jobID) {
			os.RemoveAll(outputDir)
		}
	}()
	pkg.OutputPath = outputDir

	logDir := filepath.Join(outputDir, "logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("creating log dir: %w", err)
	}

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
	if o.metrics != nil {
		o.metrics.RecordPhaseDuration("setup", setupDuration.Seconds())
	}

	multiWriter := io.MultiWriter(os.Stderr, logFile)
	buildLogger := clog.New(slog.NewTextHandler(multiWriter, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx = clog.WithLogger(ctx, buildLogger)

	fmt.Fprintf(logFile, "=== Package build started at %s ===\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(logFile, "Package: %s\n", pkg.Name)
	fmt.Fprintf(logFile, "Job ID: %s\n", jobID)

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

	cacheDir := filepath.Join(tmpDir, "cache")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return fmt.Errorf("creating cache dir: %w", err)
	}

	extraEnv := make(map[string]string)
	for k, v := range spec.Env {
		extraEnv[k] = v
	}
	for k, v := range o.config.SecretEnv {
		extraEnv[k] = v
	}

	// Phase 7: Acquire apko instance from manager if configured
	var apkoInstance *apko.Instance
	apkoServiceAddr := o.config.ApkoServiceAddr
	if o.apkoManager != nil {
		apkoTimer := tracing.NewTimer(ctx, "phase_apko_instance_request")
		inst, err := o.apkoManager.Request(ctx, apko.InstanceRequest{
			JobID: jobID,
		})
		if err != nil {
			return fmt.Errorf("requesting apko instance: %w", err)
		}
		apkoDuration := apkoTimer.Stop()
		apkoInstance = inst
		apkoServiceAddr = inst.Addr
		span.AddEvent("apko_instance_acquired", trace.WithAttributes(
			attribute.String("instance_id", inst.ID),
			attribute.String("instance_addr", inst.Addr),
			attribute.String("duration", apkoDuration.String()),
		))
		log.Infof("acquired apko instance %s at %s for job %s", inst.ID, inst.Addr, jobID)
	}

	// Track apko build result for release
	var apkoBuildSuccess bool
	defer func() {
		if apkoInstance != nil && o.apkoManager != nil {
			o.apkoManager.Release(apkoInstance, apko.BuildResult{
				Success:  apkoBuildSuccess,
				Duration: time.Since(apkoInstance.AcquiredAt),
			})
			log.Infof("released apko instance %s for job %s (success=%v)", apkoInstance.ID, jobID, apkoBuildSuccess)
		}
	}()

	buildCfgTemplate := build.RemoteBuildParams{
		ConfigPath:           configPath,
		PipelineDir:          func() string { if len(pipelines) > 0 { return pipelineDir }; return "" }(),
		SourceDir:            func() string { if len(sourceFiles) > 0 { return sourceDir }; return "" }(),
		OutputDir:            outputDir,
		CacheDir:             cacheDir,
		ApkCacheDir:          o.config.ApkCacheDir,
		Debug:                spec.Debug,
		JobID:                jobID,
		CacheRegistry:        o.config.CacheRegistry,
		CacheMode:            o.config.CacheMode,
		ApkoRegistry:         o.config.ApkoRegistry,
		ApkoRegistryInsecure: o.config.ApkoRegistryInsecure,
		ApkoServiceAddr:      apkoServiceAddr,
		ExtraEnv:             extraEnv,
	}

	var lastErr error
	var buildkitDuration time.Duration
	var backendDuration time.Duration
	var initDuration time.Duration
	var bc *build.Build
	var buildSuccess bool
	var currentWorker *buildkit.Worker

	for attempt := 1; attempt <= o.retryConfig.MaxAttempts; attempt++ {
		backendTimer := tracing.NewTimer(ctx, "phase_backend_selection")

		// Use the Manager interface to request a worker
		worker, err := o.manager.Request(ctx, buildkit.WorkerRequest{
			Arch:     arch,
			JobID:    jobID,
			Selector: spec.BackendSelector,
		})
		if err != nil {
			return fmt.Errorf("selecting backend: %w", err)
		}
		currentWorker = worker

		backendDuration = backendTimer.Stop()
		span.AddEvent("backend_selected", trace.WithAttributes(
			attribute.String("backend_addr", worker.Addr),
			attribute.String("duration", backendDuration.String()),
			attribute.Int("attempt", attempt),
		))
		if o.metrics != nil {
			o.metrics.RecordPhaseDuration("backend_selection", backendDuration.Seconds())
		}

		pkg.Backend = &types.Backend{
			Addr:   worker.Addr,
			Arch:   worker.Arch,
			Labels: worker.Labels,
		}

		span.SetAttributes(attribute.String("backend_addr", worker.Addr))
		log.Infof("building package %s for architecture: %s on backend %s (attempt %d/%d)",
			pkg.Name, targetArch, worker.Addr, attempt, o.retryConfig.MaxAttempts)

		initTimer := tracing.NewTimer(ctx, "phase_build_init")

		buildCfgTemplate.BackendAddr = worker.Addr
		buildCfg := build.NewBuildConfigForRemote(buildCfgTemplate)
		buildCfg.Arch = targetArch

		bc, err = build.NewFromConfig(ctx, buildCfg)
		if err != nil {
			o.manager.Release(worker, buildkit.BuildResult{Success: false, Error: err.Error()})
			return fmt.Errorf("initializing build: %w", err)
		}

		initDuration = initTimer.Stop()
		span.AddEvent("build_initialized", trace.WithAttributes(
			attribute.String("duration", initDuration.String()),
		))
		if o.metrics != nil {
			o.metrics.RecordPhaseDuration("init", initDuration.Seconds())
		}

		buildkitTimer := tracing.NewTimer(ctx, "phase_buildkit_execution")
		log.Infof("starting BuildKit execution for package %s (attempt %d/%d)", pkg.Name, attempt, o.retryConfig.MaxAttempts)

		buildErr := bc.BuildPackage(ctx)
		buildkitDuration = buildkitTimer.Stop()

		if buildErr != nil {
			bc.Close(ctx)

			if o.retryConfig.ShouldRetry(attempt, buildErr) {
				scheduler.LogRetryAttempt(ctx, attempt, o.retryConfig.MaxAttempts, buildErr)
				span.AddEvent("buildkit_retry", trace.WithAttributes(
					attribute.String("duration", buildkitDuration.String()),
					attribute.String("error", buildErr.Error()),
					attribute.Int("attempt", attempt),
				))

				o.manager.Release(worker, buildkit.BuildResult{Success: false, Duration: buildkitDuration, Error: buildErr.Error()})
				lastErr = buildErr

				if waitErr := o.retryConfig.WaitForBackoff(ctx, attempt); waitErr != nil {
					return fmt.Errorf("context cancelled during retry backoff: %w", waitErr)
				}
				continue
			}

			span.AddEvent("buildkit_failed", trace.WithAttributes(
				attribute.String("duration", buildkitDuration.String()),
				attribute.String("error", buildErr.Error()),
			))
			log.Errorf("BuildKit execution failed after %s: %v", buildkitDuration, buildErr)

			if syncErr := o.storage.SyncOutputDir(ctx, jobID, outputDir); syncErr != nil {
				log.Errorf("failed to sync output on error: %v", syncErr)
			}

			o.manager.Release(worker, buildkit.BuildResult{Success: false, Duration: buildkitDuration, Error: buildErr.Error()})
			return fmt.Errorf("building package: %w", buildErr)
		}

		buildSuccess = true
		if attempt > 1 {
			scheduler.LogRetrySuccess(ctx, attempt)
		}
		break
	}

	if !buildSuccess {
		if lastErr != nil {
			scheduler.LogRetryExhausted(ctx, o.retryConfig.MaxAttempts, lastErr)
			if syncErr := o.storage.SyncOutputDir(ctx, jobID, outputDir); syncErr != nil {
				log.Errorf("failed to sync output on error: %v", syncErr)
			}
			return fmt.Errorf("building package after %d attempts: %w", o.retryConfig.MaxAttempts, lastErr)
		}
		return fmt.Errorf("building package: unknown error")
	}

	defer func() {
		o.manager.Release(currentWorker, buildkit.BuildResult{Success: buildSuccess, Duration: buildkitDuration})
	}()
	defer bc.Close(ctx)

	span.AddEvent("buildkit_complete", trace.WithAttributes(
		attribute.String("duration", buildkitDuration.String()),
	))
	if o.metrics != nil {
		o.metrics.RecordPhaseDuration("buildkit", buildkitDuration.Seconds())
	}
	log.Infof("BuildKit execution completed in %s for package %s", buildkitDuration, pkg.Name)

	if bc.BuildKitSummary != nil {
		summary := bc.BuildKitSummary
		if pkg.Metrics == nil {
			pkg.Metrics = &types.PackageBuildMetrics{}
		}
		pkg.Metrics.BuildKitStepsTotal = summary.Total
		pkg.Metrics.BuildKitCached = summary.Cached
		pkg.Metrics.BuildKitCacheHit = summary.Cached > 0 && summary.Cached == summary.Total

		for _, step := range summary.Steps {
			pkg.Metrics.Steps = append(pkg.Metrics.Steps, types.StepTiming{
				Name:       step.Name,
				DurationMs: step.Duration.Milliseconds(),
				Cached:     step.Cached,
				Error:      step.Error,
			})
		}
		log.Infof("captured %d BuildKit steps for package %s", len(pkg.Metrics.Steps), pkg.Name)
	}

	syncTimer := tracing.NewTimer(ctx, "phase_storage_sync")
	log.Infof("syncing output to storage for package %s", pkg.Name)

	if err := o.storage.SyncOutputDir(ctx, jobID, outputDir); err != nil {
		return fmt.Errorf("syncing output to storage: %w", err)
	}

	syncDuration := syncTimer.Stop()
	span.AddEvent("storage_sync_complete", trace.WithAttributes(
		attribute.String("duration", syncDuration.String()),
	))
	if o.metrics != nil {
		o.metrics.RecordPhaseDuration("storage_sync", syncDuration.Seconds())
		o.metrics.RecordStorageSync(o.storage.Type(), syncDuration.Seconds())
	}
	log.Infof("storage sync completed in %s for package %s", syncDuration, pkg.Name)

	log.Infof("package %s phase breakdown: setup=%s, backend=%s, init=%s, buildkit=%s, sync=%s",
		pkg.Name, setupDuration, backendDuration, initDuration, buildkitDuration, syncDuration)

	// Mark apko build as successful for the defer release
	apkoBuildSuccess = true
	return nil
}

// markPackageFailed marks a package as failed via HTTP client.
func (o *Orchestrator) markPackageFailed(ctx context.Context, buildID string, pkg *types.PackageJob, err error) {
	_, _ = o.client.UpdatePackage(ctx, buildID, pkg.Name, &client.UpdatePackageRequest{
		Status: types.PackageStatusFailed,
		Error:  err.Error(),
	})
	o.cascadeFailure(ctx, buildID, pkg.Name)
}

// cascadeFailure marks packages that depend on the failed package as skipped.
func (o *Orchestrator) cascadeFailure(ctx context.Context, buildID, failedPkg string) {
	log := clog.FromContext(ctx)

	build, err := o.client.GetBuild(ctx, buildID)
	if err != nil {
		log.Errorf("failed to get build for cascade: %v", err)
		return
	}

	inBuild := make(map[string]bool)
	for _, pkg := range build.Packages {
		inBuild[pkg.Name] = true
	}

	for _, pkg := range build.Packages {
		if pkg.Status != types.PackageStatusPending && pkg.Status != types.PackageStatusBlocked {
			continue
		}

		for _, dep := range pkg.Dependencies {
			if !inBuild[dep] {
				continue
			}
			if dep == failedPkg {
				_, err := o.client.UpdatePackage(ctx, buildID, pkg.Name, &client.UpdatePackageRequest{
					Status: types.PackageStatusSkipped,
					Error:  fmt.Sprintf("dependency %s failed", failedPkg),
				})
				if err != nil {
					log.Errorf("failed to mark %s as skipped: %v", pkg.Name, err)
				}
				o.cascadeFailure(ctx, buildID, pkg.Name)
				break
			}
		}
	}
}

// updateBuildStatus updates the overall build status based on package statuses.
func (o *Orchestrator) updateBuildStatus(ctx context.Context, buildID string) {
	log := clog.FromContext(ctx)

	build, err := o.client.GetBuild(ctx, buildID)
	if err != nil {
		log.Errorf("failed to get build for status update: %v", err)
		return
	}

	var (
		pending int
		running int
		success int
		failed  int
		skipped int
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

	if build.Status != newStatus {
		oldStatus := build.Status
		_, err := o.client.UpdateBuild(ctx, buildID, &client.UpdateBuildRequest{
			Status: newStatus,
		})
		if err != nil {
			log.Errorf("failed to update build status: %v", err)
		}
		log.Infof("build %s status: %s (%d success, %d failed, %d skipped)",
			buildID, newStatus, success, failed, skipped)

		if o.metrics != nil && oldStatus == types.BuildStatusRunning && newStatus != types.BuildStatusRunning {
			var durationSeconds float64
			if build.StartedAt != nil && build.FinishedAt != nil {
				durationSeconds = build.FinishedAt.Sub(*build.StartedAt).Seconds()
			}
			mode := string(build.Spec.Mode)
			if mode == "" {
				mode = string(types.BuildModeFlat)
			}
			o.metrics.RecordBuildCompleted(string(newStatus), mode, durationSeconds)
		}
	}
}

// RunCacheCleanup runs periodic cleanup of the APK cache directory.
func (o *Orchestrator) RunCacheCleanup(ctx context.Context) error {
	if o.config.ApkCacheDir == "" {
		return nil
	}

	log := clog.FromContext(ctx)
	ttl := o.config.ApkCacheTTL
	if ttl == 0 {
		ttl = time.Hour
	}

	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	log.Infof("APK cache cleanup started: dir=%s ttl=%s", o.config.ApkCacheDir, ttl)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			evicted, freed, err := o.cleanupCacheDir(o.config.ApkCacheDir, ttl)
			if err != nil {
				log.Errorf("cache cleanup error: %v", err)
			} else if evicted > 0 {
				log.Infof("APK cache cleanup: evicted %d files, freed %s", evicted, formatBytes(freed))
			}
		}
	}
}

func (o *Orchestrator) cleanupCacheDir(cacheDir string, ttl time.Duration) (int, int64, error) {
	cutoff := time.Now().Add(-ttl)
	var evicted int
	var freed int64

	err := filepath.WalkDir(cacheDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		if info.ModTime().Before(cutoff) {
			size := info.Size()
			if err := os.Remove(path); err == nil {
				evicted++
				freed += size
			}
		}
		return nil
	})

	if err == nil {
		o.cleanupEmptyDirs(cacheDir)
	}

	return evicted, freed, err
}

func (o *Orchestrator) cleanupEmptyDirs(cacheDir string) {
	var dirs []string
	_ = filepath.WalkDir(cacheDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() && path != cacheDir {
			dirs = append(dirs, path)
		}
		return nil
	})

	for i := len(dirs) - 1; i >= 0; i-- {
		entries, err := os.ReadDir(dirs[i])
		if err == nil && len(entries) == 0 {
			_ = os.Remove(dirs[i])
		}
	}
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
