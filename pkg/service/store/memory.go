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

// Package store provides build storage implementations.
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

// Default eviction configuration.
const (
	// DefaultMaxCompletedBuilds is the maximum number of completed builds to retain.
	DefaultMaxCompletedBuilds = 1000
	// DefaultBuildTTL is the time after which completed builds are eligible for eviction.
	DefaultBuildTTL = 24 * time.Hour
	// DefaultEvictionInterval is how often the eviction check runs.
	DefaultEvictionInterval = 5 * time.Minute
)

// MemoryBuildStoreConfig configures the in-memory build store.
type MemoryBuildStoreConfig struct {
	// MaxCompletedBuilds is the maximum number of completed builds to retain.
	// Oldest completed builds are evicted first. 0 means no limit.
	MaxCompletedBuilds int
	// BuildTTL is the time after which completed builds are eligible for eviction.
	// 0 means no TTL-based eviction.
	BuildTTL time.Duration
	// EvictionInterval is how often the eviction check runs.
	// 0 means no background eviction (only on-demand).
	EvictionInterval time.Duration
}

// MemoryBuildStore is an in-memory implementation of BuildStore.
type MemoryBuildStore struct {
	mu     sync.RWMutex
	builds map[string]*types.Build
	config MemoryBuildStoreConfig

	// activeBuilds is an index of non-terminal builds for fast ListBuilds
	// This avoids O(n) scans when the scheduler polls every second
	activeBuilds map[string]struct{}

	// For background eviction
	stopCh chan struct{}
	doneCh chan struct{}
}

// MemoryBuildStoreOption configures a MemoryBuildStore.
type MemoryBuildStoreOption func(*MemoryBuildStore)

// WithMaxCompletedBuilds sets the maximum number of completed builds to retain.
func WithMaxCompletedBuilds(n int) MemoryBuildStoreOption {
	return func(s *MemoryBuildStore) {
		s.config.MaxCompletedBuilds = n
	}
}

// WithBuildTTL sets the TTL for completed builds.
func WithBuildTTL(ttl time.Duration) MemoryBuildStoreOption {
	return func(s *MemoryBuildStore) {
		s.config.BuildTTL = ttl
	}
}

// WithEvictionInterval sets the interval for background eviction.
func WithEvictionInterval(interval time.Duration) MemoryBuildStoreOption {
	return func(s *MemoryBuildStore) {
		s.config.EvictionInterval = interval
	}
}

// NewMemoryBuildStore creates a new in-memory build store with default settings.
func NewMemoryBuildStore(opts ...MemoryBuildStoreOption) *MemoryBuildStore {
	s := &MemoryBuildStore{
		builds:       make(map[string]*types.Build),
		activeBuilds: make(map[string]struct{}),
		config: MemoryBuildStoreConfig{
			MaxCompletedBuilds: DefaultMaxCompletedBuilds,
			BuildTTL:           DefaultBuildTTL,
			EvictionInterval:   DefaultEvictionInterval,
		},
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}

	for _, opt := range opts {
		opt(s)
	}

	// Start background eviction if interval is set
	if s.config.EvictionInterval > 0 {
		go s.evictionLoop()
	} else {
		close(s.doneCh) // No background loop
	}

	return s
}

// Close stops the background eviction loop.
func (s *MemoryBuildStore) Close() {
	close(s.stopCh)
	<-s.doneCh
}

// evictionLoop runs periodic eviction of old builds.
func (s *MemoryBuildStore) evictionLoop() {
	defer close(s.doneCh)

	ticker := time.NewTicker(s.config.EvictionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.evictOldBuilds()
		}
	}
}

// evictOldBuilds removes completed builds that exceed limits or TTL.
func (s *MemoryBuildStore) evictOldBuilds() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Collect completed builds with their completion time
	type completedBuild struct {
		id         string
		finishedAt time.Time
	}
	completed := make([]completedBuild, 0, len(s.builds))

	for id, build := range s.builds {
		if !IsTerminalStatus(build.Status) {
			continue
		}

		finishedAt := build.CreatedAt // Fallback
		if build.FinishedAt != nil {
			finishedAt = *build.FinishedAt
		}

		// Check TTL first
		if s.config.BuildTTL > 0 && now.Sub(finishedAt) > s.config.BuildTTL {
			delete(s.builds, id)
			delete(s.activeBuilds, id) // Clean index too
			continue
		}

		completed = append(completed, completedBuild{
			id:         id,
			finishedAt: finishedAt,
		})
	}

	// Check count limit
	if s.config.MaxCompletedBuilds > 0 && len(completed) > s.config.MaxCompletedBuilds {
		// Sort by finishedAt (oldest first)
		sort.Slice(completed, func(i, j int) bool {
			return completed[i].finishedAt.Before(completed[j].finishedAt)
		})

		// Evict oldest builds exceeding the limit
		toEvict := len(completed) - s.config.MaxCompletedBuilds
		for i := 0; i < toEvict; i++ {
			delete(s.builds, completed[i].id)
			delete(s.activeBuilds, completed[i].id) // Clean index too
		}
	}
}


// Stats returns current store statistics.
func (s *MemoryBuildStore) Stats() (total, active, completed int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, build := range s.builds {
		total++
		if IsTerminalStatus(build.Status) {
			completed++
		} else {
			active++
		}
	}
	return
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
	s.activeBuilds[build.ID] = struct{}{} // Track as active
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

	// Update active index based on terminal status
	if IsTerminalStatus(build.Status) {
		delete(s.activeBuilds, build.ID)
	}
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

// ListActiveBuilds returns only non-terminal builds using the active index.
// This is O(active) instead of O(total) - critical for scheduler performance at scale.
func (s *MemoryBuildStore) ListActiveBuilds(ctx context.Context) ([]*types.Build, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	builds := make([]*types.Build, 0, len(s.activeBuilds))
	for id := range s.activeBuilds {
		if build, ok := s.builds[id]; ok {
			builds = append(builds, s.copyBuild(build))
		}
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
