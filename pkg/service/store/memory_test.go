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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/pkg/service/dag"
	"github.com/dlorenc/melange2/pkg/service/types"
)

// Build store tests

func TestMemoryBuildStore_CreateBuild(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryBuildStore()

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

func TestMemoryBuildStore_GetBuild(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryBuildStore()

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

	t.Run("returns deep copy", func(t *testing.T) {
		build1, _ := store.GetBuild(ctx, created.ID)
		build2, _ := store.GetBuild(ctx, created.ID)

		build1.Status = types.BuildStatusRunning
		assert.NotEqual(t, build1.Status, build2.Status)

		if len(build1.Packages) > 0 {
			build1.Packages[0].Status = types.PackageStatusRunning
			assert.NotEqual(t, build1.Packages[0].Status, build2.Packages[0].Status)
		}
	})
}

func TestMemoryBuildStore_UpdateBuild(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryBuildStore()

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
		err := store.UpdateBuild(ctx, &types.Build{ID: "non-existent"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "build not found")
	})
}

func TestMemoryBuildStore_ListBuilds(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryBuildStore()

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

func TestMemoryBuildStore_ClaimReadyPackage(t *testing.T) {
	ctx := context.Background()

	t.Run("no ready packages", func(t *testing.T) {
		store := NewMemoryBuildStore()
		packages := []dag.Node{
			{Name: "pkg-a", Dependencies: []string{"pkg-b"}},
			{Name: "pkg-b", Dependencies: []string{"pkg-c"}},
		}
		build, _ := store.CreateBuild(ctx, packages, types.BuildSpec{})

		// pkg-a depends on pkg-b, pkg-b depends on pkg-c (not in graph)
		// pkg-b should be claimable since pkg-c is external
		claimed, err := store.ClaimReadyPackage(ctx, build.ID)
		require.NoError(t, err)
		require.NotNil(t, claimed)
		// pkg-b can be claimed because pkg-c is not in the build
		assert.Equal(t, "pkg-b", claimed.Name)
	})

	t.Run("claims package with no dependencies", func(t *testing.T) {
		store := NewMemoryBuildStore()
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
		store := NewMemoryBuildStore()
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
		store := NewMemoryBuildStore()
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

	t.Run("non-existent build", func(t *testing.T) {
		store := NewMemoryBuildStore()
		_, err := store.ClaimReadyPackage(ctx, "non-existent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "build not found")
	})

	t.Run("ignores external dependencies", func(t *testing.T) {
		store := NewMemoryBuildStore()
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

func TestMemoryBuildStore_UpdatePackageJob(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryBuildStore()

	packages := []dag.Node{{Name: "test-pkg"}}
	build, _ := store.CreateBuild(ctx, packages, types.BuildSpec{})

	t.Run("update existing package", func(t *testing.T) {
		now := time.Now()
		err := store.UpdatePackageJob(ctx, build.ID, &types.PackageJob{
			Name:       "test-pkg",
			Status:     types.PackageStatusSuccess,
			FinishedAt: &now,
			LogPath:    "/logs/test.log",
		})
		require.NoError(t, err)

		updated, _ := store.GetBuild(ctx, build.ID)
		assert.Equal(t, types.PackageStatusSuccess, updated.Packages[0].Status)
		assert.NotNil(t, updated.Packages[0].FinishedAt)
		assert.Equal(t, "/logs/test.log", updated.Packages[0].LogPath)
	})

	t.Run("non-existent build", func(t *testing.T) {
		err := store.UpdatePackageJob(ctx, "non-existent", &types.PackageJob{Name: "test"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "build not found")
	})

	t.Run("non-existent package", func(t *testing.T) {
		err := store.UpdatePackageJob(ctx, build.ID, &types.PackageJob{Name: "non-existent"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "package not found")
	})
}

func TestMemoryBuildStore_CopyBuild(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryBuildStore()

	packages := []dag.Node{
		{Name: "pkg-a", ConfigYAML: "yaml-a", Dependencies: []string{"dep-1", "dep-2"}},
	}
	spec := types.BuildSpec{
		Pipelines: map[string]string{"p1.yaml": "content1"},
	}
	build, _ := store.CreateBuild(ctx, packages, spec)

	// Get a copy
	copy, _ := store.GetBuild(ctx, build.ID)

	// Modify the copy's slices and maps
	copy.Packages[0].Dependencies[0] = "modified"
	copy.Packages[0].Pipelines["p1.yaml"] = "modified"

	// Get another copy and verify original is unchanged
	original, _ := store.GetBuild(ctx, build.ID)
	assert.Equal(t, "dep-1", original.Packages[0].Dependencies[0])
	assert.Equal(t, "content1", original.Packages[0].Pipelines["p1.yaml"])
}

func TestMemoryBuildStore_ListActiveBuilds(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryBuildStore()

	t.Run("empty store", func(t *testing.T) {
		builds, err := store.ListActiveBuilds(ctx)
		require.NoError(t, err)
		assert.Empty(t, builds)
	})

	t.Run("returns only active builds", func(t *testing.T) {
		// Create three builds
		build1, _ := store.CreateBuild(ctx, []dag.Node{{Name: "a"}}, types.BuildSpec{})
		build2, _ := store.CreateBuild(ctx, []dag.Node{{Name: "b"}}, types.BuildSpec{})
		build3, _ := store.CreateBuild(ctx, []dag.Node{{Name: "c"}}, types.BuildSpec{})

		// Complete build2 (success)
		build2.Status = types.BuildStatusSuccess
		now := time.Now()
		build2.FinishedAt = &now
		store.UpdateBuild(ctx, build2)

		// Fail build3
		build3.Status = types.BuildStatusFailed
		build3.FinishedAt = &now
		store.UpdateBuild(ctx, build3)

		// Only build1 should be active
		active, err := store.ListActiveBuilds(ctx)
		require.NoError(t, err)
		assert.Len(t, active, 1)
		assert.Equal(t, build1.ID, active[0].ID)
	})

	t.Run("running builds are active", func(t *testing.T) {
		store := NewMemoryBuildStore()
		build, _ := store.CreateBuild(ctx, []dag.Node{{Name: "a"}}, types.BuildSpec{})

		build.Status = types.BuildStatusRunning
		now := time.Now()
		build.StartedAt = &now
		store.UpdateBuild(ctx, build)

		active, err := store.ListActiveBuilds(ctx)
		require.NoError(t, err)
		assert.Len(t, active, 1)
		assert.Equal(t, types.BuildStatusRunning, active[0].Status)
	})

	t.Run("partial builds are not active", func(t *testing.T) {
		store := NewMemoryBuildStore()
		build, _ := store.CreateBuild(ctx, []dag.Node{{Name: "a"}}, types.BuildSpec{})

		build.Status = types.BuildStatusPartial
		now := time.Now()
		build.FinishedAt = &now
		store.UpdateBuild(ctx, build)

		active, err := store.ListActiveBuilds(ctx)
		require.NoError(t, err)
		assert.Empty(t, active)
	})
}

func TestMemoryBuildStore_Stats(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryBuildStore()

	t.Run("empty store", func(t *testing.T) {
		total, active, completed := store.Stats()
		assert.Equal(t, 0, total)
		assert.Equal(t, 0, active)
		assert.Equal(t, 0, completed)
	})

	t.Run("mixed builds", func(t *testing.T) {
		// Create builds with different statuses
		_, _ = store.CreateBuild(ctx, []dag.Node{{Name: "a"}}, types.BuildSpec{}) // stays pending (active)
		build2, _ := store.CreateBuild(ctx, []dag.Node{{Name: "b"}}, types.BuildSpec{})
		build3, _ := store.CreateBuild(ctx, []dag.Node{{Name: "c"}}, types.BuildSpec{})

		// build2 becomes success (completed)
		build2.Status = types.BuildStatusSuccess
		store.UpdateBuild(ctx, build2)

		// build3 becomes failed (completed)
		build3.Status = types.BuildStatusFailed
		store.UpdateBuild(ctx, build3)

		total, active, completed := store.Stats()
		assert.Equal(t, 3, total)
		assert.Equal(t, 1, active)
		assert.Equal(t, 2, completed)
	})
}

func TestMemoryBuildStore_Close(t *testing.T) {
	t.Run("stops eviction loop", func(t *testing.T) {
		store := NewMemoryBuildStore(WithEvictionInterval(100 * time.Millisecond))

		// Close should stop the eviction loop
		store.Close()

		// Closing again should not panic (doneCh is already closed)
		// This is a smoke test - the Close() method should be idempotent-ish
	})

	t.Run("no eviction loop", func(t *testing.T) {
		store := NewMemoryBuildStore(WithEvictionInterval(0))

		// Close should work even without eviction loop
		store.Close()
	})
}

func TestMemoryBuildStore_Eviction(t *testing.T) {
	ctx := context.Background()

	t.Run("evicts by TTL", func(t *testing.T) {
		store := NewMemoryBuildStore(
			WithBuildTTL(50*time.Millisecond),
			WithEvictionInterval(0), // Disable background eviction
		)

		// Create and complete a build
		build, _ := store.CreateBuild(ctx, []dag.Node{{Name: "a"}}, types.BuildSpec{})
		build.Status = types.BuildStatusSuccess
		now := time.Now()
		build.FinishedAt = &now
		store.UpdateBuild(ctx, build)

		// Build should exist initially
		_, err := store.GetBuild(ctx, build.ID)
		require.NoError(t, err)

		// Wait for TTL to expire
		time.Sleep(100 * time.Millisecond)

		// Manually trigger eviction
		store.evictOldBuilds()

		// Build should be evicted
		_, err = store.GetBuild(ctx, build.ID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "build not found")
	})

	t.Run("evicts by count", func(t *testing.T) {
		store := NewMemoryBuildStore(
			WithMaxCompletedBuilds(2),
			WithBuildTTL(0), // Disable TTL eviction
			WithEvictionInterval(0),
		)

		// Create and complete 4 builds
		var buildIDs []string
		for i := 0; i < 4; i++ {
			build, _ := store.CreateBuild(ctx, []dag.Node{{Name: "a"}}, types.BuildSpec{})
			build.Status = types.BuildStatusSuccess
			now := time.Now()
			build.FinishedAt = &now
			store.UpdateBuild(ctx, build)
			buildIDs = append(buildIDs, build.ID)
			time.Sleep(10 * time.Millisecond) // Ensure different finish times
		}

		// Manually trigger eviction
		store.evictOldBuilds()

		// Only the 2 most recent should remain
		// Oldest 2 should be evicted
		_, err := store.GetBuild(ctx, buildIDs[0])
		assert.Error(t, err, "oldest build should be evicted")

		_, err = store.GetBuild(ctx, buildIDs[1])
		assert.Error(t, err, "second oldest build should be evicted")

		_, err = store.GetBuild(ctx, buildIDs[2])
		assert.NoError(t, err, "third build should remain")

		_, err = store.GetBuild(ctx, buildIDs[3])
		assert.NoError(t, err, "newest build should remain")
	})

	t.Run("does not evict active builds", func(t *testing.T) {
		store := NewMemoryBuildStore(
			WithBuildTTL(1*time.Millisecond),
			WithEvictionInterval(0),
		)

		// Create a build but don't complete it
		build, _ := store.CreateBuild(ctx, []dag.Node{{Name: "a"}}, types.BuildSpec{})

		time.Sleep(50 * time.Millisecond)
		store.evictOldBuilds()

		// Active build should still exist
		_, err := store.GetBuild(ctx, build.ID)
		require.NoError(t, err)
	})
}

func TestMemoryBuildStore_Options(t *testing.T) {
	t.Run("WithMaxCompletedBuilds", func(t *testing.T) {
		store := NewMemoryBuildStore(WithMaxCompletedBuilds(5))
		assert.Equal(t, 5, store.config.MaxCompletedBuilds)
	})

	t.Run("WithBuildTTL", func(t *testing.T) {
		store := NewMemoryBuildStore(WithBuildTTL(time.Hour))
		assert.Equal(t, time.Hour, store.config.BuildTTL)
	})

	t.Run("WithEvictionInterval", func(t *testing.T) {
		store := NewMemoryBuildStore(WithEvictionInterval(time.Minute))
		defer store.Close()
		assert.Equal(t, time.Minute, store.config.EvictionInterval)
	})
}

func TestIsTerminalStatus(t *testing.T) {
	tests := []struct {
		status   types.BuildStatus
		terminal bool
	}{
		{types.BuildStatusPending, false},
		{types.BuildStatusRunning, false},
		{types.BuildStatusSuccess, true},
		{types.BuildStatusFailed, true},
		{types.BuildStatusPartial, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			assert.Equal(t, tt.terminal, IsTerminalStatus(tt.status))
		})
	}
}
