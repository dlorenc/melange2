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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/pkg/service/dag"
	"github.com/dlorenc/melange2/pkg/service/types"
)

func TestMemoryStore_Create(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	spec := types.JobSpec{
		ConfigYAML: "package:\n  name: test\n  version: 1.0.0",
		Arch:       "x86_64",
	}

	job, err := store.Create(ctx, spec)
	require.NoError(t, err)
	require.NotNil(t, job)

	assert.NotEmpty(t, job.ID)
	assert.Equal(t, types.JobStatusPending, job.Status)
	assert.Equal(t, spec.ConfigYAML, job.Spec.ConfigYAML)
	assert.Equal(t, spec.Arch, job.Spec.Arch)
	assert.False(t, job.CreatedAt.IsZero())
}

func TestMemoryStore_Get(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	spec := types.JobSpec{ConfigYAML: "test"}
	created, err := store.Create(ctx, spec)
	require.NoError(t, err)

	t.Run("existing job", func(t *testing.T) {
		job, err := store.Get(ctx, created.ID)
		require.NoError(t, err)
		assert.Equal(t, created.ID, job.ID)
		assert.Equal(t, types.JobStatusPending, job.Status)
	})

	t.Run("non-existent job", func(t *testing.T) {
		_, err := store.Get(ctx, "non-existent-id")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "job not found")
	})

	t.Run("returns copy", func(t *testing.T) {
		job1, _ := store.Get(ctx, created.ID)
		job2, _ := store.Get(ctx, created.ID)
		// Modifying one shouldn't affect the other
		job1.Status = types.JobStatusRunning
		assert.NotEqual(t, job1.Status, job2.Status)
	})
}

func TestMemoryStore_Update(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	spec := types.JobSpec{ConfigYAML: "test"}
	job, err := store.Create(ctx, spec)
	require.NoError(t, err)

	t.Run("update existing job", func(t *testing.T) {
		job.Status = types.JobStatusRunning
		now := time.Now()
		job.StartedAt = &now

		err := store.Update(ctx, job)
		require.NoError(t, err)

		updated, err := store.Get(ctx, job.ID)
		require.NoError(t, err)
		assert.Equal(t, types.JobStatusRunning, updated.Status)
		assert.NotNil(t, updated.StartedAt)
	})

	t.Run("update non-existent job", func(t *testing.T) {
		nonExistent := &types.Job{ID: "non-existent"}
		err := store.Update(ctx, nonExistent)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "job not found")
	})
}

func TestMemoryStore_ClaimPending(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	t.Run("no pending jobs", func(t *testing.T) {
		job, err := store.ClaimPending(ctx)
		require.NoError(t, err)
		assert.Nil(t, job)
	})

	t.Run("claims oldest pending job", func(t *testing.T) {
		// Create jobs with different timestamps
		job1, _ := store.Create(ctx, types.JobSpec{ConfigYAML: "job1"})
		time.Sleep(10 * time.Millisecond) // Ensure different timestamps
		job2, _ := store.Create(ctx, types.JobSpec{ConfigYAML: "job2"})

		// Should claim job1 (oldest)
		claimed, err := store.ClaimPending(ctx)
		require.NoError(t, err)
		require.NotNil(t, claimed)
		assert.Equal(t, job1.ID, claimed.ID)
		assert.Equal(t, types.JobStatusRunning, claimed.Status)
		assert.NotNil(t, claimed.StartedAt)

		// Next claim should get job2
		claimed2, err := store.ClaimPending(ctx)
		require.NoError(t, err)
		require.NotNil(t, claimed2)
		assert.Equal(t, job2.ID, claimed2.ID)

		// No more pending jobs
		claimed3, err := store.ClaimPending(ctx)
		require.NoError(t, err)
		assert.Nil(t, claimed3)
	})

	t.Run("skips non-pending jobs", func(t *testing.T) {
		store := NewMemoryStore()
		job1, _ := store.Create(ctx, types.JobSpec{ConfigYAML: "job1"})
		job2, _ := store.Create(ctx, types.JobSpec{ConfigYAML: "job2"})

		// Mark job1 as running
		job1.Status = types.JobStatusRunning
		store.Update(ctx, job1)

		// Should claim job2
		claimed, err := store.ClaimPending(ctx)
		require.NoError(t, err)
		require.NotNil(t, claimed)
		assert.Equal(t, job2.ID, claimed.ID)
	})
}

func TestMemoryStore_List(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	t.Run("empty store", func(t *testing.T) {
		jobs, err := store.List(ctx)
		require.NoError(t, err)
		assert.Empty(t, jobs)
	})

	t.Run("returns all jobs", func(t *testing.T) {
		store.Create(ctx, types.JobSpec{ConfigYAML: "job1"})
		store.Create(ctx, types.JobSpec{ConfigYAML: "job2"})
		store.Create(ctx, types.JobSpec{ConfigYAML: "job3"})

		jobs, err := store.List(ctx)
		require.NoError(t, err)
		assert.Len(t, jobs, 3)
	})

	t.Run("returns copies", func(t *testing.T) {
		jobs, _ := store.List(ctx)
		if len(jobs) > 0 {
			originalStatus := jobs[0].Status
			jobs[0].Status = types.JobStatusFailed

			jobs2, _ := store.List(ctx)
			assert.Equal(t, originalStatus, jobs2[0].Status)
		}
	})
}

func TestMemoryStore_Concurrency(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	var wg sync.WaitGroup
	numGoroutines := 10
	jobsPerGoroutine := 5

	// Concurrent creates
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < jobsPerGoroutine; j++ {
				_, err := store.Create(ctx, types.JobSpec{ConfigYAML: "test"})
				assert.NoError(t, err)
			}
		}()
	}
	wg.Wait()

	jobs, err := store.List(ctx)
	require.NoError(t, err)
	assert.Len(t, jobs, numGoroutines*jobsPerGoroutine)
}

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
