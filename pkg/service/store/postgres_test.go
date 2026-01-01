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

package store

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/dlorenc/melange2/pkg/service/dag"
	"github.com/dlorenc/melange2/pkg/service/types"
)

// setupTestPostgres creates a PostgreSQL container for testing.
// Returns the store and a cleanup function.
func setupTestPostgres(t *testing.T) (*PostgresBuildStore, func()) {
	t.Helper()
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "melange_test",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	host, err := container.Host(ctx)
	require.NoError(t, err)

	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)

	dsn := fmt.Sprintf("postgres://test:test@%s:%s/melange_test?sslmode=disable", host, port.Port())

	// Run migrations
	err = RunMigrations(dsn)
	require.NoError(t, err)

	store, err := NewPostgresBuildStore(ctx, dsn)
	require.NoError(t, err)

	cleanup := func() {
		store.Close()
		if err := container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %v", err)
		}
	}

	return store, cleanup
}

func TestPostgresBuildStore_CreateBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PostgreSQL test in short mode")
	}

	store, cleanup := setupTestPostgres(t)
	defer cleanup()

	ctx := context.Background()

	packages := []dag.Node{
		{Name: "pkg-a", ConfigYAML: "package:\n  name: pkg-a"},
		{Name: "pkg-b", ConfigYAML: "package:\n  name: pkg-b", Dependencies: []string{"pkg-a"}},
	}
	spec := types.BuildSpec{
		Arch:      "x86_64",
		Pipelines: map[string]string{"test.yaml": "content"},
	}

	build, err := store.CreateBuild(ctx, packages, spec)
	require.NoError(t, err)
	require.NotNil(t, build)

	assert.NotEmpty(t, build.ID)
	assert.True(t, len(build.ID) > 4 && build.ID[:4] == "bld-")
	assert.Equal(t, types.BuildStatusPending, build.Status)
	assert.Len(t, build.Packages, 2)
	assert.Equal(t, "pkg-a", build.Packages[0].Name)
	assert.Equal(t, "pkg-b", build.Packages[1].Name)
	assert.Equal(t, []string{"pkg-a"}, build.Packages[1].Dependencies)
	assert.False(t, build.CreatedAt.IsZero())
}

func TestPostgresBuildStore_GetBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PostgreSQL test in short mode")
	}

	store, cleanup := setupTestPostgres(t)
	defer cleanup()

	ctx := context.Background()

	packages := []dag.Node{{Name: "test"}}
	created, err := store.CreateBuild(ctx, packages, types.BuildSpec{})
	require.NoError(t, err)

	t.Run("existing build", func(t *testing.T) {
		build, err := store.GetBuild(ctx, created.ID)
		require.NoError(t, err)
		assert.Equal(t, created.ID, build.ID)
	})

	t.Run("non-existent build", func(t *testing.T) {
		_, err := store.GetBuild(ctx, "non-existent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "build not found")
	})
}

func TestPostgresBuildStore_UpdateBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PostgreSQL test in short mode")
	}

	store, cleanup := setupTestPostgres(t)
	defer cleanup()

	ctx := context.Background()

	packages := []dag.Node{{Name: "test"}}
	build, err := store.CreateBuild(ctx, packages, types.BuildSpec{})
	require.NoError(t, err)

	t.Run("update existing build", func(t *testing.T) {
		build.Status = types.BuildStatusRunning
		err := store.UpdateBuild(ctx, build)
		require.NoError(t, err)

		updated, _ := store.GetBuild(ctx, build.ID)
		assert.Equal(t, types.BuildStatusRunning, updated.Status)
	})

	t.Run("update non-existent build", func(t *testing.T) {
		err := store.UpdateBuild(ctx, &types.Build{
			ID:     "non-existent",
			Status: types.BuildStatusPending, // Need valid status for PostgreSQL enum
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "build not found")
	})
}

func TestPostgresBuildStore_ListBuilds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PostgreSQL test in short mode")
	}

	store, cleanup := setupTestPostgres(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("empty store", func(t *testing.T) {
		builds, err := store.ListBuilds(ctx)
		require.NoError(t, err)
		assert.Empty(t, builds)
	})

	t.Run("returns all builds sorted by creation time", func(t *testing.T) {
		store.CreateBuild(ctx, []dag.Node{{Name: "a"}}, types.BuildSpec{})
		time.Sleep(10 * time.Millisecond)
		store.CreateBuild(ctx, []dag.Node{{Name: "b"}}, types.BuildSpec{})
		time.Sleep(10 * time.Millisecond)
		store.CreateBuild(ctx, []dag.Node{{Name: "c"}}, types.BuildSpec{})

		builds, err := store.ListBuilds(ctx)
		require.NoError(t, err)
		assert.Len(t, builds, 3)

		// Should be sorted by creation time
		for i := 1; i < len(builds); i++ {
			assert.True(t, builds[i-1].CreatedAt.Before(builds[i].CreatedAt) ||
				builds[i-1].CreatedAt.Equal(builds[i].CreatedAt))
		}
	})
}

func TestPostgresBuildStore_ListActiveBuilds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PostgreSQL test in short mode")
	}

	store, cleanup := setupTestPostgres(t)
	defer cleanup()

	ctx := context.Background()

	// Create builds with different statuses
	build1, err := store.CreateBuild(ctx, []dag.Node{{Name: "active1"}}, types.BuildSpec{})
	require.NoError(t, err)
	build2, err := store.CreateBuild(ctx, []dag.Node{{Name: "active2"}}, types.BuildSpec{})
	require.NoError(t, err)
	build3, err := store.CreateBuild(ctx, []dag.Node{{Name: "completed"}}, types.BuildSpec{})
	require.NoError(t, err)

	// Complete build3
	build3.Status = types.BuildStatusSuccess
	now := time.Now()
	build3.FinishedAt = &now
	err = store.UpdateBuild(ctx, build3)
	require.NoError(t, err)

	// List active builds
	active, err := store.ListActiveBuilds(ctx)
	require.NoError(t, err)
	assert.Len(t, active, 2)

	// Should only contain build1 and build2
	ids := make(map[string]bool)
	for _, b := range active {
		ids[b.ID] = true
	}
	assert.True(t, ids[build1.ID])
	assert.True(t, ids[build2.ID])
	assert.False(t, ids[build3.ID])
}

func TestPostgresBuildStore_ClaimReadyPackage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PostgreSQL test in short mode")
	}

	store, cleanup := setupTestPostgres(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("claims package with no dependencies", func(t *testing.T) {
		packages := []dag.Node{
			{Name: "pkg-a"},
			{Name: "pkg-b", Dependencies: []string{"pkg-a"}},
		}
		build, _ := store.CreateBuild(ctx, packages, types.BuildSpec{})

		claimed, err := store.ClaimReadyPackage(ctx, build.ID)
		require.NoError(t, err)
		require.NotNil(t, claimed)
		assert.Equal(t, "pkg-a", claimed.Name)
		assert.Equal(t, types.PackageStatusRunning, claimed.Status)
		assert.NotNil(t, claimed.StartedAt)
	})

	t.Run("claims package after dependency succeeds", func(t *testing.T) {
		packages := []dag.Node{
			{Name: "pkg-a"},
			{Name: "pkg-b", Dependencies: []string{"pkg-a"}},
		}
		build, _ := store.CreateBuild(ctx, packages, types.BuildSpec{})

		// Claim and complete pkg-a
		store.ClaimReadyPackage(ctx, build.ID)
		store.UpdatePackageJob(ctx, build.ID, &types.PackageJob{
			Name:   "pkg-a",
			Status: types.PackageStatusSuccess,
		})

		// Now pkg-b should be claimable
		claimed, err := store.ClaimReadyPackage(ctx, build.ID)
		require.NoError(t, err)
		require.NotNil(t, claimed)
		assert.Equal(t, "pkg-b", claimed.Name)
	})

	t.Run("doesn't claim if dependency failed", func(t *testing.T) {
		packages := []dag.Node{
			{Name: "pkg-a"},
			{Name: "pkg-b", Dependencies: []string{"pkg-a"}},
		}
		build, _ := store.CreateBuild(ctx, packages, types.BuildSpec{})

		// Claim and fail pkg-a
		store.ClaimReadyPackage(ctx, build.ID)
		store.UpdatePackageJob(ctx, build.ID, &types.PackageJob{
			Name:   "pkg-a",
			Status: types.PackageStatusFailed,
		})

		// pkg-b shouldn't be claimable
		claimed, err := store.ClaimReadyPackage(ctx, build.ID)
		require.NoError(t, err)
		assert.Nil(t, claimed)
	})

	t.Run("ignores external dependencies", func(t *testing.T) {
		packages := []dag.Node{
			{Name: "pkg-a", Dependencies: []string{"external-dep"}},
		}
		build, _ := store.CreateBuild(ctx, packages, types.BuildSpec{})

		// pkg-a depends on external-dep which isn't in the build
		// So pkg-a should be claimable
		claimed, err := store.ClaimReadyPackage(ctx, build.ID)
		require.NoError(t, err)
		require.NotNil(t, claimed)
		assert.Equal(t, "pkg-a", claimed.Name)
	})
}

func TestPostgresBuildStore_ClaimReadyPackage_Concurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PostgreSQL test in short mode")
	}

	store, cleanup := setupTestPostgres(t)
	defer cleanup()

	ctx := context.Background()

	// Create a build with 10 packages (no dependencies)
	packages := make([]dag.Node, 10)
	for i := 0; i < 10; i++ {
		packages[i] = dag.Node{
			Name:       fmt.Sprintf("pkg-%d", i),
			ConfigYAML: fmt.Sprintf("package:\n  name: pkg-%d", i),
		}
	}
	build, err := store.CreateBuild(ctx, packages, types.BuildSpec{})
	require.NoError(t, err)

	// Concurrently claim all packages
	// With FOR UPDATE SKIP LOCKED, goroutines that find all packages locked
	// will return nil and need to retry
	var wg sync.WaitGroup
	claimed := make(chan string, 20)

	for i := 0; i < 20; i++ { // More goroutines than packages
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Keep trying until we claim a package or there are none left
			for j := 0; j < 20; j++ { // Max retries
				pkg, err := store.ClaimReadyPackage(ctx, build.ID)
				if err != nil {
					return // Real error, stop
				}
				if pkg != nil {
					claimed <- pkg.Name
					return // Successfully claimed
				}
				// pkg == nil means either all packages are locked or all are done
				// Small sleep to avoid tight loop
				time.Sleep(5 * time.Millisecond)
			}
		}()
	}

	wg.Wait()
	close(claimed)

	// Verify exactly 10 unique packages were claimed
	claimedSet := make(map[string]bool)
	for name := range claimed {
		claimedSet[name] = true
	}
	assert.Len(t, claimedSet, 10)
}

func TestPostgresBuildStore_UpdatePackageJob(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PostgreSQL test in short mode")
	}

	store, cleanup := setupTestPostgres(t)
	defer cleanup()

	ctx := context.Background()

	packages := []dag.Node{{Name: "test-pkg"}}
	build, _ := store.CreateBuild(ctx, packages, types.BuildSpec{})

	t.Run("update existing package", func(t *testing.T) {
		now := time.Now()
		err := store.UpdatePackageJob(ctx, build.ID, &types.PackageJob{
			Name:       "test-pkg",
			Status:     types.PackageStatusSuccess,
			FinishedAt: &now,
			LogPath:    "/logs/test.log",
			Metrics: &types.PackageBuildMetrics{
				TotalDurationMs:    1000,
				BuildKitDurationMs: 500,
			},
		})
		require.NoError(t, err)

		updated, _ := store.GetBuild(ctx, build.ID)
		assert.Equal(t, types.PackageStatusSuccess, updated.Packages[0].Status)
		assert.NotNil(t, updated.Packages[0].FinishedAt)
		assert.Equal(t, "/logs/test.log", updated.Packages[0].LogPath)
		require.NotNil(t, updated.Packages[0].Metrics)
		assert.Equal(t, int64(1000), updated.Packages[0].Metrics.TotalDurationMs)
	})

	t.Run("non-existent package", func(t *testing.T) {
		err := store.UpdatePackageJob(ctx, build.ID, &types.PackageJob{
			Name:   "non-existent",
			Status: types.PackageStatusFailed, // Need valid status for PostgreSQL enum
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "package not found")
	})
}

func TestPostgresBuildStore_Ping(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PostgreSQL test in short mode")
	}

	store, cleanup := setupTestPostgres(t)
	defer cleanup()

	ctx := context.Background()
	err := store.Ping(ctx)
	require.NoError(t, err)
}

func TestPostgresBuildStore_SourceFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PostgreSQL test in short mode")
	}

	store, cleanup := setupTestPostgres(t)
	defer cleanup()

	ctx := context.Background()

	packages := []dag.Node{{Name: "pkg-a", ConfigYAML: "package:\n  name: pkg-a"}}
	spec := types.BuildSpec{
		SourceFiles: map[string]map[string]string{
			"pkg-a": {
				"patches/fix.patch": "patch content",
				"config.ini":        "config content",
			},
		},
	}

	build, err := store.CreateBuild(ctx, packages, spec)
	require.NoError(t, err)

	// Verify source files are stored
	retrieved, err := store.GetBuild(ctx, build.ID)
	require.NoError(t, err)
	require.Len(t, retrieved.Packages, 1)
	assert.Equal(t, "patch content", retrieved.Packages[0].SourceFiles["patches/fix.patch"])
	assert.Equal(t, "config content", retrieved.Packages[0].SourceFiles["config.ini"])
}
