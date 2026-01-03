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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStaticManager_Request(t *testing.T) {
	backends := []Backend{
		{Addr: "tcp://backend1:1234", Arch: "x86_64", Labels: map[string]string{"tier": "standard"}},
		{Addr: "tcp://backend2:1234", Arch: "x86_64", Labels: map[string]string{"tier": "high-memory"}},
		{Addr: "tcp://backend3:1234", Arch: "aarch64", Labels: map[string]string{}},
	}

	manager, err := NewStaticManagerFromBackends(backends)
	require.NoError(t, err)

	ctx := context.Background()

	// Test basic request
	worker, err := manager.Request(ctx, WorkerRequest{
		Arch:  "x86_64",
		JobID: "test-job-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "x86_64", worker.Arch)
	assert.NotEmpty(t, worker.Addr)
	assert.NotZero(t, worker.AcquiredAt)

	// Release the worker
	manager.Release(worker, BuildResult{Success: true, Duration: time.Second})

	// Test request with selector
	worker, err = manager.Request(ctx, WorkerRequest{
		Arch:     "x86_64",
		JobID:    "test-job-2",
		Selector: map[string]string{"tier": "high-memory"},
	})
	require.NoError(t, err)
	assert.Equal(t, "tcp://backend2:1234", worker.Addr)
	manager.Release(worker, BuildResult{Success: true})

	// Test request for different architecture
	worker, err = manager.Request(ctx, WorkerRequest{
		Arch:  "aarch64",
		JobID: "test-job-3",
	})
	require.NoError(t, err)
	assert.Equal(t, "tcp://backend3:1234", worker.Addr)
	assert.Equal(t, "aarch64", worker.Arch)
	manager.Release(worker, BuildResult{Success: true})

	// Test request with no matching backend
	_, err = manager.Request(ctx, WorkerRequest{
		Arch:  "riscv64",
		JobID: "test-job-4",
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNoAvailableBackend)
}

func TestStaticManager_Status(t *testing.T) {
	backends := []Backend{
		{Addr: "tcp://backend1:1234", Arch: "x86_64", MaxJobs: 2},
		{Addr: "tcp://backend2:1234", Arch: "aarch64", MaxJobs: 1},
	}

	manager, err := NewStaticManagerFromBackends(backends)
	require.NoError(t, err)

	// Initial status
	status := manager.Status()
	assert.Equal(t, "static", status.Type)
	assert.Equal(t, 2, status.TotalWorkers)
	assert.Equal(t, 2, status.AvailableWorkers)
	assert.Equal(t, 0, status.ActiveJobs)
	assert.Len(t, status.Workers, 2)

	// Acquire a worker
	ctx := context.Background()
	worker, err := manager.Request(ctx, WorkerRequest{
		Arch:  "x86_64",
		JobID: "test-job",
	})
	require.NoError(t, err)

	// Check status after acquiring
	status = manager.Status()
	assert.Equal(t, 1, status.ActiveJobs)
	assert.Equal(t, 2, status.AvailableWorkers) // Still available as it has capacity

	// Release the worker
	manager.Release(worker, BuildResult{Success: true})

	// Check status after release
	status = manager.Status()
	assert.Equal(t, 0, status.ActiveJobs)
}

func TestStaticManager_TotalCapacity(t *testing.T) {
	backends := []Backend{
		{Addr: "tcp://backend1:1234", Arch: "x86_64", MaxJobs: 4},
		{Addr: "tcp://backend2:1234", Arch: "x86_64", MaxJobs: 2},
		{Addr: "tcp://backend3:1234", Arch: "aarch64"}, // Uses default
	}

	config := PoolConfig{
		Backends:       backends,
		DefaultMaxJobs: 3,
	}

	manager, err := NewStaticManagerFromConfig(config)
	require.NoError(t, err)

	// 4 + 2 + 3 (default) = 9
	assert.Equal(t, 9, manager.TotalCapacity())
}

func TestStaticManager_Architectures(t *testing.T) {
	backends := []Backend{
		{Addr: "tcp://backend1:1234", Arch: "x86_64"},
		{Addr: "tcp://backend2:1234", Arch: "x86_64"},
		{Addr: "tcp://backend3:1234", Arch: "aarch64"},
	}

	manager, err := NewStaticManagerFromBackends(backends)
	require.NoError(t, err)

	archs := manager.Architectures()
	assert.Contains(t, archs, "x86_64")
	assert.Contains(t, archs, "aarch64")
}

func TestStaticManager_AddRemove(t *testing.T) {
	backends := []Backend{
		{Addr: "tcp://backend1:1234", Arch: "x86_64"},
		{Addr: "tcp://backend2:1234", Arch: "aarch64"},
	}

	manager, err := NewStaticManagerFromBackends(backends)
	require.NoError(t, err)

	// Add a new backend
	err = manager.Add(Backend{
		Addr:   "tcp://backend3:1234",
		Arch:   "x86_64",
		Labels: map[string]string{"tier": "premium"},
	})
	require.NoError(t, err)

	// Verify it was added
	assert.Len(t, manager.List(), 3)

	// Try to add duplicate
	err = manager.Add(Backend{
		Addr: "tcp://backend3:1234",
		Arch: "x86_64",
	})
	assert.Error(t, err)

	// Remove a backend
	err = manager.Remove("tcp://backend2:1234")
	require.NoError(t, err)
	assert.Len(t, manager.List(), 2)

	// Try to remove non-existent
	err = manager.Remove("tcp://nonexistent:1234")
	assert.Error(t, err)
}

func TestStaticManager_FailureTracking(t *testing.T) {
	backends := []Backend{
		{Addr: "tcp://backend1:1234", Arch: "x86_64", MaxJobs: 2},
	}

	config := PoolConfig{
		Backends:         backends,
		FailureThreshold: 2,
		RecoveryTimeout:  100 * time.Millisecond,
	}

	manager, err := NewStaticManagerFromConfig(config)
	require.NoError(t, err)

	ctx := context.Background()

	// First failure
	worker1, err := manager.Request(ctx, WorkerRequest{Arch: "x86_64", JobID: "job1"})
	require.NoError(t, err)
	manager.Release(worker1, BuildResult{Success: false, Error: "test failure"})

	// Check status shows failure
	status := manager.Status()
	assert.Equal(t, 1, status.Workers[0].Failures)
	assert.False(t, status.Workers[0].CircuitOpen)

	// Second failure should open circuit
	worker2, err := manager.Request(ctx, WorkerRequest{Arch: "x86_64", JobID: "job2"})
	require.NoError(t, err)
	manager.Release(worker2, BuildResult{Success: false, Error: "test failure"})

	status = manager.Status()
	assert.Equal(t, 2, status.Workers[0].Failures)
	assert.True(t, status.Workers[0].CircuitOpen)

	// Should not be able to get a worker now
	_, err = manager.Request(ctx, WorkerRequest{Arch: "x86_64", JobID: "job3"})
	assert.Error(t, err)

	// Wait for recovery timeout
	time.Sleep(150 * time.Millisecond)

	// Should be able to get a worker again (half-open state)
	worker3, err := manager.Request(ctx, WorkerRequest{Arch: "x86_64", JobID: "job4"})
	require.NoError(t, err)

	// Success should reset failures and close circuit
	manager.Release(worker3, BuildResult{Success: true})

	status = manager.Status()
	assert.Equal(t, 0, status.Workers[0].Failures)
	assert.False(t, status.Workers[0].CircuitOpen)
}

func TestStaticManager_Close(t *testing.T) {
	backends := []Backend{
		{Addr: "tcp://backend1:1234", Arch: "x86_64"},
	}

	manager, err := NewStaticManagerFromBackends(backends)
	require.NoError(t, err)

	// Close should be a no-op for static manager
	err = manager.Close()
	assert.NoError(t, err)
}

func TestStaticManager_VerifyInterface(t *testing.T) {
	// Verify StaticManager implements Manager interface
	var _ Manager = (*StaticManager)(nil)
}
