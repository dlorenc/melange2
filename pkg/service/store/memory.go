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
	"sync"
	"time"

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
