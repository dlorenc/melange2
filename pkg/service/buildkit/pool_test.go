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
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewPool(t *testing.T) {
	tests := []struct {
		name     string
		backends []Backend
		wantErr  bool
	}{
		{
			name:     "empty backends",
			backends: []Backend{},
			wantErr:  true,
		},
		{
			name: "missing addr",
			backends: []Backend{
				{Arch: "x86_64"},
			},
			wantErr: true,
		},
		{
			name: "missing arch",
			backends: []Backend{
				{Addr: "tcp://localhost:1234"},
			},
			wantErr: true,
		},
		{
			name: "valid single backend",
			backends: []Backend{
				{Addr: "tcp://localhost:1234", Arch: "x86_64"},
			},
			wantErr: false,
		},
		{
			name: "valid multiple backends",
			backends: []Backend{
				{Addr: "tcp://amd64-1:1234", Arch: "x86_64", Labels: map[string]string{"tier": "standard"}},
				{Addr: "tcp://amd64-2:1234", Arch: "x86_64", Labels: map[string]string{"tier": "high-memory"}},
				{Addr: "tcp://arm64-1:1234", Arch: "aarch64", Labels: map[string]string{"tier": "standard"}},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool, err := NewPool(tt.backends)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, pool)
		})
	}
}

func TestPoolSelect(t *testing.T) {
	backends := []Backend{
		{Addr: "tcp://amd64-std:1234", Arch: "x86_64", Labels: map[string]string{"tier": "standard"}},
		{Addr: "tcp://amd64-high:1234", Arch: "x86_64", Labels: map[string]string{"tier": "high-memory"}},
		{Addr: "tcp://arm64-std:1234", Arch: "aarch64", Labels: map[string]string{"tier": "standard"}},
	}
	pool, err := NewPool(backends)
	require.NoError(t, err)

	tests := []struct {
		name     string
		arch     string
		selector map[string]string
		wantAddr string
		wantErr  bool
	}{
		{
			name:     "select by arch only",
			arch:     "aarch64",
			selector: nil,
			wantAddr: "tcp://arm64-std:1234",
			wantErr:  false,
		},
		{
			name:     "select by arch and tier",
			arch:     "x86_64",
			selector: map[string]string{"tier": "high-memory"},
			wantAddr: "tcp://amd64-high:1234",
			wantErr:  false,
		},
		{
			name:     "no matching arch",
			arch:     "riscv64",
			selector: nil,
			wantErr:  true,
		},
		{
			name:     "no matching selector",
			arch:     "x86_64",
			selector: map[string]string{"tier": "nonexistent"},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, err := pool.Select(tt.arch, tt.selector)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantAddr, backend.Addr)
		})
	}
}

func TestPoolSelectLoadAware(t *testing.T) {
	backends := []Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64", Labels: map[string]string{}},
		{Addr: "tcp://amd64-2:1234", Arch: "x86_64", Labels: map[string]string{}},
		{Addr: "tcp://amd64-3:1234", Arch: "x86_64", Labels: map[string]string{}},
	}
	pool, err := NewPool(backends)
	require.NoError(t, err)

	// With no load, SelectAndAcquire should pick any backend (all have 0 load)
	backend1, err := pool.SelectAndAcquire("x86_64", nil)
	require.NoError(t, err)
	require.NotNil(t, backend1)

	// Next SelectAndAcquire should pick a less-loaded backend (not the first one)
	backend2, err := pool.SelectAndAcquire("x86_64", nil)
	require.NoError(t, err)
	require.NotEqual(t, backend1.Addr, backend2.Addr)

	// Release all slots
	pool.Release(backend1.Addr, true)
	pool.Release(backend2.Addr, true)
}

func TestPoolFromConfig(t *testing.T) {
	configContent := `
backends:
  - addr: tcp://amd64-1:1234
    arch: x86_64
    labels:
      tier: standard
  - addr: tcp://arm64-1:1234
    arch: aarch64
    labels:
      tier: standard
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "backends.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	pool, err := NewPoolFromConfig(configPath)
	require.NoError(t, err)
	require.Len(t, pool.List(), 2)

	archs := pool.Architectures()
	require.Len(t, archs, 2)
}

func TestPoolFromSingleAddr(t *testing.T) {
	pool, err := NewPoolFromSingleAddr("tcp://localhost:1234", "")
	require.NoError(t, err)

	backends := pool.List()
	require.Len(t, backends, 1)
	require.Equal(t, "tcp://localhost:1234", backends[0].Addr)
	require.Equal(t, "x86_64", backends[0].Arch) // default arch
}

func TestPoolListByArch(t *testing.T) {
	backends := []Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
		{Addr: "tcp://amd64-2:1234", Arch: "x86_64"},
		{Addr: "tcp://arm64-1:1234", Arch: "aarch64"},
	}
	pool, err := NewPool(backends)
	require.NoError(t, err)

	amd64 := pool.ListByArch("x86_64")
	require.Len(t, amd64, 2)

	arm64 := pool.ListByArch("aarch64")
	require.Len(t, arm64, 1)

	riscv := pool.ListByArch("riscv64")
	require.Len(t, riscv, 0)
}

func TestPoolAdd(t *testing.T) {
	pool, err := NewPool([]Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	})
	require.NoError(t, err)
	require.Len(t, pool.List(), 1)

	// Add a new backend
	err = pool.Add(Backend{
		Addr:   "tcp://arm64-1:1234",
		Arch:   "aarch64",
		Labels: map[string]string{"tier": "standard"},
	})
	require.NoError(t, err)
	require.Len(t, pool.List(), 2)

	// Verify new architecture is available
	archs := pool.Architectures()
	require.Len(t, archs, 2)

	// Should be able to select the new backend
	backend, err := pool.Select("aarch64", nil)
	require.NoError(t, err)
	require.Equal(t, "tcp://arm64-1:1234", backend.Addr)
}

func TestPoolAddValidation(t *testing.T) {
	pool, err := NewPool([]Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	})
	require.NoError(t, err)

	// Missing addr
	err = pool.Add(Backend{Arch: "x86_64"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "addr is required")

	// Missing arch
	err = pool.Add(Backend{Addr: "tcp://new:1234"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "arch is required")

	// Duplicate addr
	err = pool.Add(Backend{Addr: "tcp://amd64-1:1234", Arch: "x86_64"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}

func TestPoolRemove(t *testing.T) {
	pool, err := NewPool([]Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
		{Addr: "tcp://amd64-2:1234", Arch: "x86_64"},
		{Addr: "tcp://arm64-1:1234", Arch: "aarch64"},
	})
	require.NoError(t, err)
	require.Len(t, pool.List(), 3)

	// Remove a backend
	err = pool.Remove("tcp://amd64-2:1234")
	require.NoError(t, err)
	require.Len(t, pool.List(), 2)

	// Verify it's gone
	for _, b := range pool.List() {
		require.NotEqual(t, "tcp://amd64-2:1234", b.Addr)
	}
}

func TestPoolRemoveValidation(t *testing.T) {
	pool, err := NewPool([]Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	})
	require.NoError(t, err)

	// Cannot remove last backend
	err = pool.Remove("tcp://amd64-1:1234")
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot remove the last backend")

	// Add another backend first
	err = pool.Add(Backend{Addr: "tcp://amd64-2:1234", Arch: "x86_64"})
	require.NoError(t, err)

	// Non-existent backend (need 2+ backends to test this)
	err = pool.Remove("tcp://nonexistent:1234")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")

	// Now can remove one of the backends
	err = pool.Remove("tcp://amd64-1:1234")
	require.NoError(t, err)
}

func TestPoolAcquireRelease(t *testing.T) {
	pool, err := NewPool([]Backend{
		{Addr: "tcp://backend:1234", Arch: "x86_64", MaxJobs: 2},
	})
	require.NoError(t, err)

	// Should be able to acquire up to MaxJobs
	backend1, err := pool.SelectAndAcquire("x86_64", nil)
	require.NoError(t, err)
	require.NotNil(t, backend1)

	backend2, err := pool.SelectAndAcquire("x86_64", nil)
	require.NoError(t, err)
	require.NotNil(t, backend2)

	// Third acquire should fail (at capacity)
	_, err = pool.SelectAndAcquire("x86_64", nil)
	require.Error(t, err)
	require.Equal(t, ErrNoAvailableBackend, err)

	// Release one slot
	pool.Release(backend1.Addr, true)

	// Now can acquire again
	backend3, err := pool.SelectAndAcquire("x86_64", nil)
	require.NoError(t, err)
	require.NotNil(t, backend3)

	// Release all
	pool.Release(backend2.Addr, true)
	pool.Release(backend3.Addr, true)
}

func TestPoolCapacityLimit(t *testing.T) {
	pool, err := NewPool([]Backend{
		{Addr: "tcp://backend:1234", Arch: "x86_64", MaxJobs: 1},
	})
	require.NoError(t, err)

	// Acquire the only slot
	backend, err := pool.SelectAndAcquire("x86_64", nil)
	require.NoError(t, err)
	require.NotNil(t, backend)

	// SelectAndAcquire should fail because backend is at capacity
	_, err = pool.SelectAndAcquire("x86_64", nil)
	require.Error(t, err)
	require.Equal(t, ErrNoAvailableBackend, err)

	// Release and SelectAndAcquire should succeed
	pool.Release(backend.Addr, true)

	backend2, err := pool.SelectAndAcquire("x86_64", nil)
	require.NoError(t, err)
	require.Equal(t, "tcp://backend:1234", backend2.Addr)

	pool.Release(backend2.Addr, true)
}

func TestPoolCircuitBreaker(t *testing.T) {
	pool, err := NewPoolWithConfig(PoolConfig{
		Backends: []Backend{
			{Addr: "tcp://backend:1234", Arch: "x86_64"},
		},
		FailureThreshold: 2,
		RecoveryTimeout:  100 * time.Millisecond,
	})
	require.NoError(t, err)

	// First failure
	backend, err := pool.SelectAndAcquire("x86_64", nil)
	require.NoError(t, err)
	pool.Release(backend.Addr, false)

	// Still available (threshold not reached)
	backend, err = pool.SelectAndAcquire("x86_64", nil)
	require.NoError(t, err)
	require.NotNil(t, backend)

	// Second failure (reaches threshold)
	pool.Release(backend.Addr, false)

	// Circuit should be open, select should fail
	_, err = pool.SelectAndAcquire("x86_64", nil)
	require.Error(t, err)
	require.Equal(t, ErrNoAvailableBackend, err)

	// Wait for recovery timeout
	time.Sleep(150 * time.Millisecond)

	// Should be available again (half-open state)
	backend, err = pool.SelectAndAcquire("x86_64", nil)
	require.NoError(t, err)
	require.NotNil(t, backend)

	// Success should reset the circuit
	pool.Release(backend.Addr, true)

	// Should remain available
	backend, err = pool.SelectAndAcquire("x86_64", nil)
	require.NoError(t, err)
	require.NotNil(t, backend)
	pool.Release(backend.Addr, true)
}

func TestPoolStatus(t *testing.T) {
	pool, err := NewPool([]Backend{
		{Addr: "tcp://backend-1:1234", Arch: "x86_64", MaxJobs: 4},
		{Addr: "tcp://backend-2:1234", Arch: "x86_64", MaxJobs: 2},
	})
	require.NoError(t, err)

	// Initial status
	status := pool.Status()
	require.Len(t, status, 2)
	require.Equal(t, 0, status[0].ActiveJobs)
	require.Equal(t, 0, status[1].ActiveJobs)
	require.False(t, status[0].CircuitOpen)

	// Acquire some slots using SelectAndAcquire
	acquired := make([]*Backend, 0, 3)
	for i := 0; i < 3; i++ {
		backend, err := pool.SelectAndAcquire("x86_64", nil)
		require.NoError(t, err)
		acquired = append(acquired, backend)
	}

	// Check status reflects active jobs (total should be 3)
	status = pool.Status()
	totalActive := 0
	for _, s := range status {
		totalActive += s.ActiveJobs
	}
	require.Equal(t, 3, totalActive)

	// Release all
	for _, backend := range acquired {
		pool.Release(backend.Addr, true)
	}
}

func TestPoolDefaultMaxJobs(t *testing.T) {
	// Backend without MaxJobs should use pool default
	pool, err := NewPoolWithConfig(PoolConfig{
		Backends: []Backend{
			{Addr: "tcp://backend:1234", Arch: "x86_64"}, // No MaxJobs
		},
		DefaultMaxJobs: 2,
	})
	require.NoError(t, err)

	// Should be able to acquire default (2) jobs
	backend1, err := pool.SelectAndAcquire("x86_64", nil)
	require.NoError(t, err)
	backend2, err := pool.SelectAndAcquire("x86_64", nil)
	require.NoError(t, err)

	// Third should fail
	_, err = pool.SelectAndAcquire("x86_64", nil)
	require.Error(t, err)
	require.Equal(t, ErrNoAvailableBackend, err)

	pool.Release(backend1.Addr, true)
	pool.Release(backend2.Addr, true)
}

func TestPoolWithConfigFullOptions(t *testing.T) {
	configContent := `
backends:
  - addr: tcp://backend-1:1234
    arch: x86_64
    maxJobs: 8
    labels:
      tier: high
  - addr: tcp://backend-2:1234
    arch: x86_64
    maxJobs: 2
    labels:
      tier: standard
defaultMaxJobs: 4
failureThreshold: 5
recoveryTimeout: 60s
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "backends.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	pool, err := NewPoolFromConfig(configPath)
	require.NoError(t, err)

	backends := pool.List()
	require.Len(t, backends, 2)

	// Verify MaxJobs was parsed
	for _, b := range backends {
		if b.Addr == "tcp://backend-1:1234" {
			require.Equal(t, 8, b.MaxJobs)
		} else if b.Addr == "tcp://backend-2:1234" {
			require.Equal(t, 2, b.MaxJobs)
		}
	}
}

func TestPoolSelectAndAcquire(t *testing.T) {
	pool, err := NewPool([]Backend{
		{Addr: "tcp://backend-1:1234", Arch: "x86_64", MaxJobs: 2},
		{Addr: "tcp://backend-2:1234", Arch: "x86_64", MaxJobs: 2},
	})
	require.NoError(t, err)

	// Acquire should return backend
	backend, err := pool.SelectAndAcquire("x86_64", nil)
	require.NoError(t, err)
	require.NotNil(t, backend)

	// Status should show 1 active job
	status := pool.Status()
	totalActive := 0
	for _, s := range status {
		totalActive += s.ActiveJobs
	}
	require.Equal(t, 1, totalActive)

	// Acquire 3 more slots (total capacity is 4)
	for i := 0; i < 3; i++ {
		_, err := pool.SelectAndAcquire("x86_64", nil)
		require.NoError(t, err)
	}

	// Pool should now be at capacity
	_, err = pool.SelectAndAcquire("x86_64", nil)
	require.Error(t, err)
	require.Equal(t, ErrNoAvailableBackend, err)

	// Release one slot and try again
	pool.Release("tcp://backend-1:1234", true)

	backend, err = pool.SelectAndAcquire("x86_64", nil)
	require.NoError(t, err)
	require.NotNil(t, backend)
}

func TestPoolConcurrentSelectAndAcquire(t *testing.T) {
	// Create a pool with 8 total slots across 2 backends
	pool, err := NewPoolWithConfig(PoolConfig{
		Backends: []Backend{
			{Addr: "tcp://backend-1:1234", Arch: "x86_64", MaxJobs: 4},
			{Addr: "tcp://backend-2:1234", Arch: "x86_64", MaxJobs: 4},
		},
	})
	require.NoError(t, err)

	const totalAttempts = 100

	var wg sync.WaitGroup
	var acquired atomic.Int32
	var released atomic.Int32
	var failed atomic.Int32

	// Try to acquire 100 times concurrently
	// With only 8 slots and 100 goroutines, this tests the atomic behavior
	// of SelectAndAcquire - no goroutine should get a "half-acquired" slot
	for i := 0; i < totalAttempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			backend, err := pool.SelectAndAcquire("x86_64", nil)
			if err != nil {
				// Expected when pool is at capacity
				failed.Add(1)
				return
			}

			acquired.Add(1)
			// Brief hold to simulate work
			time.Sleep(time.Millisecond)
			pool.Release(backend.Addr, true)
			released.Add(1)
		}()
	}

	wg.Wait()

	// All acquired slots should be released
	require.Equal(t, acquired.Load(), released.Load(), "all acquired slots should be released")

	// Verify pool is back to zero active jobs
	status := pool.Status()
	totalActive := 0
	for _, s := range status {
		totalActive += s.ActiveJobs
	}
	require.Equal(t, 0, totalActive, "pool should have no active jobs after test")

	// Total should equal attempts
	require.Equal(t, int32(totalAttempts), acquired.Load()+failed.Load(),
		"acquired + failed should equal total attempts")

	// At least some should have succeeded (at minimum, initial 8 slots)
	require.GreaterOrEqual(t, acquired.Load(), int32(8),
		"should have acquired at least the slot count")

	t.Logf("acquired: %d, failed: %d, released: %d", acquired.Load(), failed.Load(), released.Load())
}

func TestPoolConcurrentSelectAndAcquireWithRetry(t *testing.T) {
	// This test ensures that concurrent access with retries eventually succeeds
	// for all goroutines, proving no spurious failures from the race condition
	pool, err := NewPoolWithConfig(PoolConfig{
		Backends: []Backend{
			{Addr: "tcp://backend-1:1234", Arch: "x86_64", MaxJobs: 4},
			{Addr: "tcp://backend-2:1234", Arch: "x86_64", MaxJobs: 4},
		},
	})
	require.NoError(t, err)

	const totalJobs = 50
	const holdTime = 5 * time.Millisecond
	const maxRetries = 100

	var wg sync.WaitGroup
	var completed atomic.Int32
	var totalRetries atomic.Int32

	// All 50 jobs should eventually complete with retries
	for i := 0; i < totalJobs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			var backend *Backend
			var err error
			retries := 0

			// Retry until we get a slot
			for retries < maxRetries {
				backend, err = pool.SelectAndAcquire("x86_64", nil)
				if err == nil {
					break
				}
				retries++
				totalRetries.Add(1)
				time.Sleep(time.Millisecond) // Brief backoff
			}

			require.NoError(t, err, "should eventually acquire a slot")
			require.NotNil(t, backend)

			// Simulate work
			time.Sleep(holdTime)
			pool.Release(backend.Addr, true)
			completed.Add(1)
		}()
	}

	wg.Wait()

	// All jobs should complete
	require.Equal(t, int32(totalJobs), completed.Load(), "all jobs should complete")

	// Verify pool is clean
	status := pool.Status()
	for _, s := range status {
		require.Equal(t, 0, s.ActiveJobs, "backend %s should have no active jobs", s.Addr)
	}

	t.Logf("completed: %d, total retries: %d", completed.Load(), totalRetries.Load())
}

func TestPoolTotalCapacity(t *testing.T) {
	pool, err := NewPoolWithConfig(PoolConfig{
		Backends: []Backend{
			{Addr: "tcp://backend-1:1234", Arch: "x86_64", MaxJobs: 8},
			{Addr: "tcp://backend-2:1234", Arch: "x86_64", MaxJobs: 4},
			{Addr: "tcp://backend-3:1234", Arch: "aarch64", MaxJobs: 0}, // Uses default
		},
		DefaultMaxJobs: 2,
	})
	require.NoError(t, err)

	// Total should be 8 + 4 + 2 (default) = 14
	require.Equal(t, 14, pool.TotalCapacity())
}
