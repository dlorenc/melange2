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

// Package scheduler provides job scheduling and execution.
package scheduler

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog"

	"github.com/dlorenc/melange2/pkg/build"
	"github.com/dlorenc/melange2/pkg/service/store"
	"github.com/dlorenc/melange2/pkg/service/types"
)

// Config holds scheduler configuration.
type Config struct {
	// BuildKitAddr is the address of the BuildKit daemon.
	BuildKitAddr string
	// OutputDir is the base directory for build outputs.
	OutputDir string
	// PollInterval is how often to check for new jobs.
	PollInterval time.Duration
}

// Scheduler processes build jobs.
type Scheduler struct {
	store  store.JobStore
	config Config
}

// New creates a new scheduler.
func New(store store.JobStore, config Config) *Scheduler {
	if config.PollInterval == 0 {
		config.PollInterval = time.Second
	}
	if config.OutputDir == "" {
		config.OutputDir = "/var/lib/melange/output"
	}
	return &Scheduler{
		store:  store,
		config: config,
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
			if err := s.processNextJob(ctx); err != nil {
				log.Errorf("error processing job: %v", err)
			}
		}
	}
}

func (s *Scheduler) processNextJob(ctx context.Context) error {
	log := clog.FromContext(ctx)

	// Try to claim a pending job
	job, err := s.store.ClaimPending(ctx)
	if err != nil {
		return fmt.Errorf("claiming job: %w", err)
	}
	if job == nil {
		// No pending jobs
		return nil
	}

	log.Infof("processing job %s", job.ID)

	// Execute the build
	buildErr := s.executeJob(ctx, job)

	// Update job status
	now := time.Now()
	job.FinishedAt = &now
	if buildErr != nil {
		job.Status = types.JobStatusFailed
		job.Error = buildErr.Error()
		log.Errorf("job %s failed: %v", job.ID, buildErr)
	} else {
		job.Status = types.JobStatusSuccess
		log.Infof("job %s completed successfully", job.ID)
	}

	if err := s.store.Update(ctx, job); err != nil {
		log.Errorf("failed to update job %s: %v", job.ID, err)
	}

	return nil
}

func (s *Scheduler) executeJob(ctx context.Context, job *types.Job) error {
	log := clog.FromContext(ctx)

	// Create temp directory for the config file
	tmpDir, err := os.MkdirTemp("", "melange-job-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write the config YAML to a temp file
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(job.Spec.ConfigYAML), 0600); err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}

	// Create output directory for this job
	outputDir := filepath.Join(s.config.OutputDir, job.ID)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}
	job.OutputPath = outputDir

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
	job.LogPath = logPath

	// Capture build output
	var logBuf bytes.Buffer

	// Determine architecture
	arch := job.Spec.Arch
	if arch == "" {
		arch = runtime.GOARCH
		if arch == "arm64" {
			arch = "aarch64"
		} else if arch == "amd64" {
			arch = "x86_64"
		}
	}
	targetArch := apko_types.ParseArchitecture(arch)

	log.Infof("building for architecture: %s", targetArch)

	// Create cache directory for this build
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
		build.WithBuildKitAddr(s.config.BuildKitAddr),
		build.WithDebug(job.Spec.Debug),
		build.WithGenerateIndex(true),
		// Use Wolfi repos/keys as defaults for MVP
		build.WithExtraRepos([]string{"https://packages.wolfi.dev/os"}),
		build.WithExtraKeys([]string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"}),
		build.WithIgnoreSignatures(true), // Skip signing for MVP
		// Git provenance defaults for service
		build.WithConfigFileRepositoryURL("https://melange-service/inline"),
		build.WithConfigFileRepositoryCommit("inline-" + job.ID),
		build.WithConfigFileLicense("Apache-2.0"),
		build.WithNamespace("wolfi"),
	}

	// Create the build context
	bc, err := build.New(ctx, opts...)
	if err != nil {
		logBuf.WriteString(fmt.Sprintf("ERROR: failed to initialize build: %v\n", err))
		_, _ = logFile.Write(logBuf.Bytes())
		return fmt.Errorf("initializing build: %w", err)
	}
	defer bc.Close(ctx)

	// Execute the build
	log.Infof("starting build for job %s", job.ID)
	logBuf.WriteString(fmt.Sprintf("Starting build at %s\n", time.Now().Format(time.RFC3339)))
	logBuf.WriteString(fmt.Sprintf("Architecture: %s\n", targetArch))
	logBuf.WriteString(fmt.Sprintf("BuildKit: %s\n", s.config.BuildKitAddr))
	logBuf.WriteString("\n--- Build Output ---\n")

	if err := bc.BuildPackage(ctx); err != nil {
		logBuf.WriteString(fmt.Sprintf("\nERROR: %v\n", err))
		_, _ = logFile.Write(logBuf.Bytes())
		return fmt.Errorf("building package: %w", err)
	}

	logBuf.WriteString(fmt.Sprintf("\nBuild completed successfully at %s\n", time.Now().Format(time.RFC3339)))
	_, _ = logFile.Write(logBuf.Bytes())

	return nil
}
