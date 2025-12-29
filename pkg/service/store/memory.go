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

// Package store provides job storage implementations.
package store

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/dlorenc/melange2/pkg/service/dag"
	"github.com/dlorenc/melange2/pkg/service/types"
	"github.com/google/uuid"
)

// JobStore defines the interface for job storage.
type JobStore interface {
	Create(ctx context.Context, spec types.JobSpec) (*types.Job, error)
	Get(ctx context.Context, id string) (*types.Job, error)
	Update(ctx context.Context, job *types.Job) error
	ClaimPending(ctx context.Context) (*types.Job, error)
	List(ctx context.Context) ([]*types.Job, error)
}

// MemoryStore is an in-memory implementation of JobStore.
type MemoryStore struct {
	mu   sync.RWMutex
	jobs map[string]*types.Job
}

// NewMemoryStore creates a new in-memory job store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		jobs: make(map[string]*types.Job),
	}
}

// Create creates a new job with the given spec.
func (s *MemoryStore) Create(ctx context.Context, spec types.JobSpec) (*types.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	job := &types.Job{
		ID:        uuid.New().String()[:8], // Short ID for readability
		Status:    types.JobStatusPending,
		Spec:      spec,
		CreatedAt: time.Now(),
	}

	s.jobs[job.ID] = job
	return job, nil
}

// Get retrieves a job by ID.
func (s *MemoryStore) Get(ctx context.Context, id string) (*types.Job, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	job, ok := s.jobs[id]
	if !ok {
		return nil, fmt.Errorf("job not found: %s", id)
	}

	// Return a copy to avoid race conditions
	copy := *job
	return &copy, nil
}

// Update updates an existing job.
func (s *MemoryStore) Update(ctx context.Context, job *types.Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.jobs[job.ID]; !ok {
		return fmt.Errorf("job not found: %s", job.ID)
	}

	// Store a copy
	copy := *job
	s.jobs[job.ID] = &copy
	return nil
}

// ClaimPending atomically claims the oldest pending job for processing.
func (s *MemoryStore) ClaimPending(ctx context.Context) (*types.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var oldest *types.Job
	for _, job := range s.jobs {
		if job.Status != types.JobStatusPending {
			continue
		}
		if oldest == nil || job.CreatedAt.Before(oldest.CreatedAt) {
			oldest = job
		}
	}

	if oldest == nil {
		return nil, nil
	}

	// Mark as running
	now := time.Now()
	oldest.Status = types.JobStatusRunning
	oldest.StartedAt = &now

	// Return a copy
	copy := *oldest
	return &copy, nil
}

// List returns all jobs.
func (s *MemoryStore) List(ctx context.Context) ([]*types.Job, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	jobs := make([]*types.Job, 0, len(s.jobs))
	for _, job := range s.jobs {
		copy := *job
		jobs = append(jobs, &copy)
	}
	return jobs, nil
}

// BuildStore defines the interface for multi-package build storage.
type BuildStore interface {
	// CreateBuild creates a new multi-package build from DAG nodes.
	CreateBuild(ctx context.Context, packages []dag.Node, spec types.BuildSpec) (*types.Build, error)

	// GetBuild retrieves a build by ID.
	GetBuild(ctx context.Context, id string) (*types.Build, error)

	// UpdateBuild updates an existing build.
	UpdateBuild(ctx context.Context, build *types.Build) error

	// ListBuilds returns all builds.
	ListBuilds(ctx context.Context) ([]*types.Build, error)

	// ClaimReadyPackage atomically claims a package that is ready to build.
	// A package is ready when all its in-graph dependencies have succeeded.
	// Returns nil if no packages are ready.
	ClaimReadyPackage(ctx context.Context, buildID string) (*types.PackageJob, error)

	// UpdatePackageJob updates a package job within a build.
	UpdatePackageJob(ctx context.Context, buildID string, pkg *types.PackageJob) error
}

// MemoryBuildStore is an in-memory implementation of BuildStore.
type MemoryBuildStore struct {
	mu     sync.RWMutex
	builds map[string]*types.Build
}

// NewMemoryBuildStore creates a new in-memory build store.
func NewMemoryBuildStore() *MemoryBuildStore {
	return &MemoryBuildStore{
		builds: make(map[string]*types.Build),
	}
}

// CreateBuild creates a new multi-package build.
func (s *MemoryBuildStore) CreateBuild(ctx context.Context, packages []dag.Node, spec types.BuildSpec) (*types.Build, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	build := &types.Build{
		ID:        "bld-" + uuid.New().String()[:8],
		Status:    types.BuildStatusPending,
		Packages:  make([]types.PackageJob, len(packages)),
		Spec:      spec,
		CreatedAt: time.Now(),
	}

	// Convert DAG nodes to PackageJobs
	for i, node := range packages {
		build.Packages[i] = types.PackageJob{
			Name:         node.Name,
			Status:       types.PackageStatusPending,
			ConfigYAML:   node.ConfigYAML,
			Dependencies: node.Dependencies,
			Pipelines:    spec.Pipelines,
		}
	}

	s.builds[build.ID] = build
	return build, nil
}

// GetBuild retrieves a build by ID.
func (s *MemoryBuildStore) GetBuild(ctx context.Context, id string) (*types.Build, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	build, ok := s.builds[id]
	if !ok {
		return nil, fmt.Errorf("build not found: %s", id)
	}

	// Return a deep copy
	return s.copyBuild(build), nil
}

// UpdateBuild updates an existing build.
func (s *MemoryBuildStore) UpdateBuild(ctx context.Context, build *types.Build) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.builds[build.ID]; !ok {
		return fmt.Errorf("build not found: %s", build.ID)
	}

	s.builds[build.ID] = s.copyBuild(build)
	return nil
}

// ListBuilds returns all builds.
func (s *MemoryBuildStore) ListBuilds(ctx context.Context) ([]*types.Build, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	builds := make([]*types.Build, 0, len(s.builds))
	for _, build := range s.builds {
		builds = append(builds, s.copyBuild(build))
	}

	// Sort by CreatedAt for deterministic ordering
	sort.Slice(builds, func(i, j int) bool {
		return builds[i].CreatedAt.Before(builds[j].CreatedAt)
	})

	return builds, nil
}

// ClaimReadyPackage atomically claims a package that is ready to build.
// A package is ready when:
// 1. Its status is Pending
// 2. All its in-graph dependencies have status Success
func (s *MemoryBuildStore) ClaimReadyPackage(ctx context.Context, buildID string) (*types.PackageJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	build, ok := s.builds[buildID]
	if !ok {
		return nil, fmt.Errorf("build not found: %s", buildID)
	}

	// Build a set of package names in this build
	inBuild := make(map[string]bool)
	for _, pkg := range build.Packages {
		inBuild[pkg.Name] = true
	}

	// Build a map of package name -> status for quick lookup
	statusMap := make(map[string]types.PackageStatus)
	for _, pkg := range build.Packages {
		statusMap[pkg.Name] = pkg.Status
	}

	// Find a ready package
	for i := range build.Packages {
		pkg := &build.Packages[i]
		if pkg.Status != types.PackageStatusPending {
			continue
		}

		// Check if all in-graph dependencies have succeeded
		ready := true
		for _, dep := range pkg.Dependencies {
			// Only check dependencies that are in this build
			if !inBuild[dep] {
				continue
			}
			if statusMap[dep] != types.PackageStatusSuccess {
				ready = false
				break
			}
		}

		if ready {
			// Claim this package
			now := time.Now()
			pkg.Status = types.PackageStatusRunning
			pkg.StartedAt = &now

			// Return a copy
			result := *pkg
			return &result, nil
		}
	}

	return nil, nil
}

// UpdatePackageJob updates a package job within a build.
func (s *MemoryBuildStore) UpdatePackageJob(ctx context.Context, buildID string, pkg *types.PackageJob) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	build, ok := s.builds[buildID]
	if !ok {
		return fmt.Errorf("build not found: %s", buildID)
	}

	// Find and update the package
	for i := range build.Packages {
		if build.Packages[i].Name == pkg.Name {
			build.Packages[i] = *pkg
			return nil
		}
	}

	return fmt.Errorf("package not found: %s", pkg.Name)
}

// copyBuild creates a deep copy of a build.
func (s *MemoryBuildStore) copyBuild(build *types.Build) *types.Build {
	copy := *build
	copy.Packages = make([]types.PackageJob, len(build.Packages))
	for i, pkg := range build.Packages {
		pkgCopy := pkg
		if pkg.Dependencies != nil {
			pkgCopy.Dependencies = make([]string, len(pkg.Dependencies))
			for j, dep := range pkg.Dependencies {
				pkgCopy.Dependencies[j] = dep
			}
		}
		if pkg.Pipelines != nil {
			pkgCopy.Pipelines = make(map[string]string)
			for k, v := range pkg.Pipelines {
				pkgCopy.Pipelines[k] = v
			}
		}
		copy.Packages[i] = pkgCopy
	}
	return &copy
}
