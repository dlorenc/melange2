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

package buildkit

import (
	"context"
	"time"
)

// StaticManager wraps the existing Pool to implement the Manager interface.
// This provides backward compatibility while enabling future implementations
// like KubernetesManager that can autoscale workers.
//
// Phase 5 of microservices architecture: See issue #178 for design details.
type StaticManager struct {
	pool *Pool
}

// NewStaticManager creates a new StaticManager wrapping the given pool.
func NewStaticManager(pool *Pool) *StaticManager {
	return &StaticManager{pool: pool}
}

// NewStaticManagerFromBackends creates a StaticManager from a list of backends.
func NewStaticManagerFromBackends(backends []Backend) (*StaticManager, error) {
	pool, err := NewPool(backends)
	if err != nil {
		return nil, err
	}
	return NewStaticManager(pool), nil
}

// NewStaticManagerFromConfig creates a StaticManager from a pool configuration.
func NewStaticManagerFromConfig(config PoolConfig) (*StaticManager, error) {
	pool, err := NewPoolWithConfig(config)
	if err != nil {
		return nil, err
	}
	return NewStaticManager(pool), nil
}

// NewStaticManagerFromConfigFile creates a StaticManager from a YAML config file.
func NewStaticManagerFromConfigFile(configPath string) (*StaticManager, error) {
	pool, err := NewPoolFromConfig(configPath)
	if err != nil {
		return nil, err
	}
	return NewStaticManager(pool), nil
}

// NewStaticManagerFromSingleAddr creates a StaticManager with a single backend.
func NewStaticManagerFromSingleAddr(addr, arch string) (*StaticManager, error) {
	pool, err := NewPoolFromSingleAddr(addr, arch)
	if err != nil {
		return nil, err
	}
	return NewStaticManager(pool), nil
}

// Request acquires a worker from the pool matching the requirements.
func (m *StaticManager) Request(ctx context.Context, req WorkerRequest) (*Worker, error) {
	// Use the atomic select-and-acquire to avoid race conditions
	backend, err := m.pool.SelectAndAcquireWithContext(ctx, req.Arch, req.Selector)
	if err != nil {
		return nil, err
	}

	return &Worker{
		ID:         backend.Addr, // Use addr as ID for static pool
		Addr:       backend.Addr,
		Arch:       backend.Arch,
		Labels:     backend.Labels,
		AcquiredAt: time.Now(),
	}, nil
}

// Release returns a worker to the pool and records the build result.
func (m *StaticManager) Release(worker *Worker, result BuildResult) {
	m.pool.Release(worker.Addr, result.Success)
}

// Status returns the current state of all workers.
func (m *StaticManager) Status() ManagerStatus {
	backendStatuses := m.pool.Status()

	workers := make([]WorkerStatus, 0, len(backendStatuses))
	totalWorkers := 0
	availableWorkers := 0
	activeJobs := 0

	for _, bs := range backendStatuses {
		maxJobs := bs.MaxJobs
		if maxJobs == 0 {
			maxJobs = m.pool.defaultMaxJobs
		}

		workers = append(workers, WorkerStatus{
			ID:          bs.Addr,
			Addr:        bs.Addr,
			Arch:        bs.Arch,
			Labels:      bs.Labels,
			ActiveJobs:  bs.ActiveJobs,
			MaxJobs:     maxJobs,
			CircuitOpen: bs.CircuitOpen,
			Failures:    bs.Failures,
			LastFailure: bs.LastFailure,
		})

		totalWorkers++
		activeJobs += bs.ActiveJobs
		if !bs.CircuitOpen && bs.ActiveJobs < maxJobs {
			availableWorkers++
		}
	}

	return ManagerStatus{
		Type:             "static",
		TotalWorkers:     totalWorkers,
		AvailableWorkers: availableWorkers,
		ActiveJobs:       activeJobs,
		Workers:          workers,
	}
}

// TotalCapacity returns the total job capacity across all backends.
func (m *StaticManager) TotalCapacity() int {
	return m.pool.TotalCapacity()
}

// Architectures returns a list of supported architectures.
func (m *StaticManager) Architectures() []string {
	return m.pool.Architectures()
}

// Close shuts down the manager. For StaticManager, this is a no-op.
func (m *StaticManager) Close() error {
	return nil
}

// Pool returns the underlying pool for backward compatibility.
// This should only be used during the migration period.
func (m *StaticManager) Pool() *Pool {
	return m.pool
}

// Add adds a new backend to the pool.
func (m *StaticManager) Add(backend Backend) error {
	return m.pool.Add(backend)
}

// Remove removes a backend from the pool.
func (m *StaticManager) Remove(addr string) error {
	return m.pool.Remove(addr)
}

// List returns all backends in the pool.
func (m *StaticManager) List() []Backend {
	return m.pool.List()
}

// Verify StaticManager implements Manager interface.
var _ Manager = (*StaticManager)(nil)
