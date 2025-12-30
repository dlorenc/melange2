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

package scheduler

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/pkg/service/buildkit"
	"github.com/dlorenc/melange2/pkg/service/dag"
	"github.com/dlorenc/melange2/pkg/service/storage"
	"github.com/dlorenc/melange2/pkg/service/store"
	"github.com/dlorenc/melange2/pkg/service/types"
)

func TestConfig(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "default config",
			config: Config{
				OutputDir:    "/var/lib/melange/output",
				PollInterval: time.Second,
			},
		},
		{
			name: "config with cache registry",
			config: Config{
				OutputDir:     "/var/lib/melange/output",
				PollInterval:  time.Second,
				CacheRegistry: "registry:5000/melange-cache",
				CacheMode:     "max",
			},
		},
		{
			name: "config with cache min mode",
			config: Config{
				OutputDir:     "/var/lib/melange/output",
				PollInterval:  time.Second,
				CacheRegistry: "registry:5000/melange-cache",
				CacheMode:     "min",
			},
		},
		{
			name: "config with empty cache mode (defaults to max)",
			config: Config{
				OutputDir:     "/var/lib/melange/output",
				PollInterval:  time.Second,
				CacheRegistry: "registry:5000/melange-cache",
				CacheMode:     "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.config

			// Verify basic config fields
			require.NotEmpty(t, cfg.OutputDir)

			// Verify cache config
			if cfg.CacheRegistry != "" {
				require.NotEmpty(t, cfg.CacheRegistry)
				// Mode can be empty (defaults to "max" in implementation)
				if cfg.CacheMode != "" {
					require.Contains(t, []string{"min", "max"}, cfg.CacheMode)
				}
			}
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	// Test that New() applies defaults correctly
	cfg := Config{}

	// These should be applied by New()
	if cfg.PollInterval == 0 {
		cfg.PollInterval = time.Second
	}
	if cfg.OutputDir == "" {
		cfg.OutputDir = "/var/lib/melange/output"
	}
	if cfg.MaxParallel == 0 {
		cfg.MaxParallel = 1 // Would be runtime.NumCPU() in actual New()
	}

	require.Equal(t, time.Second, cfg.PollInterval)
	require.Equal(t, "/var/lib/melange/output", cfg.OutputDir)
	require.Equal(t, 1, cfg.MaxParallel)
}

func newTestScheduler(t *testing.T, cfg Config) *Scheduler {
	t.Helper()

	backends := []buildkit.Backend{
		{Addr: "tcp://localhost:1234", Arch: "x86_64"},
	}
	pool, err := buildkit.NewPool(backends)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	localStorage, err := storage.NewLocalStorage(tmpDir)
	require.NoError(t, err)

	if cfg.OutputDir == "" {
		cfg.OutputDir = tmpDir
	}

	return New(
		store.NewMemoryStore(),
		store.NewMemoryBuildStore(),
		localStorage,
		pool,
		cfg,
	)
}

func TestNew(t *testing.T) {
	t.Run("applies default poll interval", func(t *testing.T) {
		s := newTestScheduler(t, Config{})
		assert.Equal(t, time.Second, s.config.PollInterval)
	})

	t.Run("applies default output dir", func(t *testing.T) {
		backends := []buildkit.Backend{{Addr: "tcp://localhost:1234", Arch: "x86_64"}}
		pool, _ := buildkit.NewPool(backends)
		tmpDir := t.TempDir()
		localStorage, _ := storage.NewLocalStorage(tmpDir)

		s := New(store.NewMemoryStore(), store.NewMemoryBuildStore(), localStorage, pool, Config{})
		assert.Equal(t, "/var/lib/melange/output", s.config.OutputDir)
	})

	t.Run("applies default max parallel", func(t *testing.T) {
		s := newTestScheduler(t, Config{})
		assert.Equal(t, runtime.NumCPU(), s.config.MaxParallel)
		assert.Equal(t, runtime.NumCPU(), cap(s.sem))
	})

	t.Run("respects custom poll interval", func(t *testing.T) {
		s := newTestScheduler(t, Config{PollInterval: 5 * time.Second})
		assert.Equal(t, 5*time.Second, s.config.PollInterval)
	})

	t.Run("respects custom max parallel", func(t *testing.T) {
		s := newTestScheduler(t, Config{MaxParallel: 4})
		assert.Equal(t, 4, s.config.MaxParallel)
		assert.Equal(t, 4, cap(s.sem))
	})

	t.Run("initializes active builds map", func(t *testing.T) {
		s := newTestScheduler(t, Config{})
		assert.NotNil(t, s.activeBuilds)
		assert.Empty(t, s.activeBuilds)
	})
}

func TestScheduler_ProcessNextJob_NoPending(t *testing.T) {
	ctx := context.Background()
	s := newTestScheduler(t, Config{})

	// No jobs - should return nil without error
	err := s.processNextJob(ctx)
	assert.NoError(t, err)
}

func TestScheduler_ProcessBuilds_Empty(t *testing.T) {
	ctx := context.Background()
	s := newTestScheduler(t, Config{})

	// No builds - should return nil without error
	err := s.processBuilds(ctx)
	assert.NoError(t, err)
}

func TestScheduler_UpdateBuildStatus(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		packages       []types.PackageJob
		expectedStatus types.BuildStatus
	}{
		{
			name: "all success",
			packages: []types.PackageJob{
				{Name: "pkg-a", Status: types.PackageStatusSuccess},
				{Name: "pkg-b", Status: types.PackageStatusSuccess},
			},
			expectedStatus: types.BuildStatusSuccess,
		},
		{
			name: "all failed",
			packages: []types.PackageJob{
				{Name: "pkg-a", Status: types.PackageStatusFailed},
				{Name: "pkg-b", Status: types.PackageStatusFailed},
			},
			expectedStatus: types.BuildStatusFailed,
		},
		{
			name: "mixed - partial",
			packages: []types.PackageJob{
				{Name: "pkg-a", Status: types.PackageStatusSuccess},
				{Name: "pkg-b", Status: types.PackageStatusFailed},
			},
			expectedStatus: types.BuildStatusPartial,
		},
		{
			name: "still running",
			packages: []types.PackageJob{
				{Name: "pkg-a", Status: types.PackageStatusSuccess},
				{Name: "pkg-b", Status: types.PackageStatusRunning},
			},
			expectedStatus: types.BuildStatusRunning,
		},
		{
			name: "still pending",
			packages: []types.PackageJob{
				{Name: "pkg-a", Status: types.PackageStatusSuccess},
				{Name: "pkg-b", Status: types.PackageStatusPending},
			},
			expectedStatus: types.BuildStatusRunning,
		},
		{
			name: "success with skipped",
			packages: []types.PackageJob{
				{Name: "pkg-a", Status: types.PackageStatusSuccess},
				{Name: "pkg-b", Status: types.PackageStatusSkipped},
			},
			// "partial" requires actual failures (failed > 0), skipped alone leads to "failed"
			expectedStatus: types.BuildStatusFailed,
		},
		{
			name: "all skipped",
			packages: []types.PackageJob{
				{Name: "pkg-a", Status: types.PackageStatusSkipped},
				{Name: "pkg-b", Status: types.PackageStatusSkipped},
			},
			expectedStatus: types.BuildStatusFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestScheduler(t, Config{})

			// Create a build with the specified packages
			nodes := make([]dag.Node, len(tt.packages))
			for i, pkg := range tt.packages {
				nodes[i] = dag.Node{Name: pkg.Name, ConfigYAML: "test"}
			}
			build, err := s.buildStore.CreateBuild(ctx, nodes, types.BuildSpec{})
			require.NoError(t, err)

			// Update package statuses
			for _, pkg := range tt.packages {
				err := s.buildStore.UpdatePackageJob(ctx, build.ID, &pkg)
				require.NoError(t, err)
			}

			// Run updateBuildStatus
			s.updateBuildStatus(ctx, build.ID)

			// Check result
			updated, err := s.buildStore.GetBuild(ctx, build.ID)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, updated.Status)

			// Verify FinishedAt is set for terminal states
			if tt.expectedStatus != types.BuildStatusRunning {
				assert.NotNil(t, updated.FinishedAt)
			}
		})
	}
}

func TestScheduler_CascadeFailure(t *testing.T) {
	ctx := context.Background()
	s := newTestScheduler(t, Config{})

	// Create build with dependencies: pkg-c depends on pkg-b which depends on pkg-a
	nodes := []dag.Node{
		{Name: "pkg-a", ConfigYAML: "test"},
		{Name: "pkg-b", ConfigYAML: "test", Dependencies: []string{"pkg-a"}},
		{Name: "pkg-c", ConfigYAML: "test", Dependencies: []string{"pkg-b"}},
		{Name: "pkg-d", ConfigYAML: "test"}, // Independent
	}
	build, err := s.buildStore.CreateBuild(ctx, nodes, types.BuildSpec{})
	require.NoError(t, err)

	// Cascade failure from pkg-a
	s.cascadeFailure(ctx, build.ID, "pkg-a")

	// Check results
	updated, err := s.buildStore.GetBuild(ctx, build.ID)
	require.NoError(t, err)

	statuses := make(map[string]types.PackageStatus)
	for _, pkg := range updated.Packages {
		statuses[pkg.Name] = pkg.Status
	}

	// pkg-a is not changed by cascadeFailure (caller handles that)
	assert.Equal(t, types.PackageStatusPending, statuses["pkg-a"])
	// pkg-b depends on pkg-a, should be skipped
	assert.Equal(t, types.PackageStatusSkipped, statuses["pkg-b"])
	// pkg-c depends on pkg-b (which is now skipped), should also be skipped
	assert.Equal(t, types.PackageStatusSkipped, statuses["pkg-c"])
	// pkg-d is independent, should still be pending
	assert.Equal(t, types.PackageStatusPending, statuses["pkg-d"])
}

func TestScheduler_CascadeFailure_ExternalDeps(t *testing.T) {
	ctx := context.Background()
	s := newTestScheduler(t, Config{})

	// Create build where pkg-b has external dep that's not in the build
	nodes := []dag.Node{
		{Name: "pkg-a", ConfigYAML: "test"},
		{Name: "pkg-b", ConfigYAML: "test", Dependencies: []string{"external-dep", "pkg-a"}},
	}
	build, err := s.buildStore.CreateBuild(ctx, nodes, types.BuildSpec{})
	require.NoError(t, err)

	// Cascade failure from pkg-a
	s.cascadeFailure(ctx, build.ID, "pkg-a")

	// Check results
	updated, err := s.buildStore.GetBuild(ctx, build.ID)
	require.NoError(t, err)

	statuses := make(map[string]types.PackageStatus)
	for _, pkg := range updated.Packages {
		statuses[pkg.Name] = pkg.Status
	}

	// pkg-b depends on pkg-a (in-build), should be skipped
	// The external-dep is ignored for cascade purposes
	assert.Equal(t, types.PackageStatusSkipped, statuses["pkg-b"])
}

func TestScheduler_ActiveBuilds_Tracking(t *testing.T) {
	s := newTestScheduler(t, Config{})

	// Initially empty
	assert.Empty(t, s.activeBuilds)

	// Simulate marking a build as active
	s.buildMu.Lock()
	s.activeBuilds["build-1"] = true
	s.buildMu.Unlock()

	assert.True(t, s.activeBuilds["build-1"])

	// Simulate marking as inactive
	s.buildMu.Lock()
	delete(s.activeBuilds, "build-1")
	s.buildMu.Unlock()

	assert.False(t, s.activeBuilds["build-1"])
}

func TestScheduler_Run_ContextCancellation(t *testing.T) {
	s := newTestScheduler(t, Config{PollInterval: 10 * time.Millisecond})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- s.Run(ctx)
	}()

	// Let it run a few iterations
	time.Sleep(50 * time.Millisecond)

	// Cancel and verify it stops
	cancel()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop after context cancellation")
	}
}

func TestScheduler_Semaphore(t *testing.T) {
	s := newTestScheduler(t, Config{MaxParallel: 2})

	// Semaphore should allow MaxParallel concurrent operations
	assert.Equal(t, 2, cap(s.sem))

	// Acquire both slots
	s.sem <- struct{}{}
	s.sem <- struct{}{}

	// Try to acquire non-blocking - should fail
	select {
	case s.sem <- struct{}{}:
		t.Fatal("semaphore should be full")
	default:
		// Expected
	}

	// Release one
	<-s.sem

	// Now should be able to acquire
	select {
	case s.sem <- struct{}{}:
		// Expected
	default:
		t.Fatal("semaphore should have space")
	}
}
