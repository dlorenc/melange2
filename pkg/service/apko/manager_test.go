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

package apko

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStaticManager_Request(t *testing.T) {
	manager, err := NewStaticManager(StaticManagerConfig{
		Instances: []InstanceConfig{
			{ID: "apko1", Addr: "apko-server-1:9090", MaxConcurrent: 4},
			{ID: "apko2", Addr: "apko-server-2:9090", MaxConcurrent: 2},
		},
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Test basic request
	instance, err := manager.Request(ctx, InstanceRequest{
		JobID: "test-job-1",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, instance.ID)
	assert.NotEmpty(t, instance.Addr)
	assert.NotZero(t, instance.AcquiredAt)

	// Release the instance
	manager.Release(instance, BuildResult{Success: true, Duration: time.Second})
}

func TestStaticManager_LoadBalancing(t *testing.T) {
	manager, err := NewStaticManager(StaticManagerConfig{
		Instances: []InstanceConfig{
			{ID: "apko1", Addr: "apko-server-1:9090", MaxConcurrent: 2},
			{ID: "apko2", Addr: "apko-server-2:9090", MaxConcurrent: 2},
		},
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Acquire first instance
	inst1, err := manager.Request(ctx, InstanceRequest{JobID: "job1"})
	require.NoError(t, err)

	// Acquire second instance - should go to the other (less loaded) instance
	inst2, err := manager.Request(ctx, InstanceRequest{JobID: "job2"})
	require.NoError(t, err)
	assert.NotEqual(t, inst1.ID, inst2.ID, "should balance load across instances")

	// Release both
	manager.Release(inst1, BuildResult{Success: true})
	manager.Release(inst2, BuildResult{Success: true})
}

func TestStaticManager_Capacity(t *testing.T) {
	manager, err := NewStaticManager(StaticManagerConfig{
		Instances: []InstanceConfig{
			{ID: "apko1", Addr: "apko-server-1:9090", MaxConcurrent: 2},
			{ID: "apko2", Addr: "apko-server-2:9090", MaxConcurrent: 3},
		},
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Total capacity should be 2 + 3 = 5
	assert.Equal(t, 5, manager.TotalCapacity())
	assert.Equal(t, 5, manager.AvailableCapacity())

	// Acquire some instances
	inst1, _ := manager.Request(ctx, InstanceRequest{JobID: "job1"})
	inst2, _ := manager.Request(ctx, InstanceRequest{JobID: "job2"})

	// Available should be reduced
	assert.Equal(t, 5, manager.TotalCapacity())
	assert.Equal(t, 3, manager.AvailableCapacity())

	// Release
	manager.Release(inst1, BuildResult{Success: true})
	manager.Release(inst2, BuildResult{Success: true})

	assert.Equal(t, 5, manager.AvailableCapacity())
}

func TestStaticManager_FullCapacity(t *testing.T) {
	manager, err := NewStaticManager(StaticManagerConfig{
		Instances: []InstanceConfig{
			{ID: "apko1", Addr: "apko-server-1:9090", MaxConcurrent: 1},
		},
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Acquire the only slot
	inst, err := manager.Request(ctx, InstanceRequest{JobID: "job1"})
	require.NoError(t, err)

	// Should fail to acquire more
	_, err = manager.Request(ctx, InstanceRequest{JobID: "job2"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no apko instances available")

	// Release and try again
	manager.Release(inst, BuildResult{Success: true})

	inst, err = manager.Request(ctx, InstanceRequest{JobID: "job3"})
	require.NoError(t, err)
	manager.Release(inst, BuildResult{Success: true})
}

func TestStaticManager_Status(t *testing.T) {
	manager, err := NewStaticManager(StaticManagerConfig{
		Instances: []InstanceConfig{
			{ID: "apko1", Addr: "apko-server-1:9090", MaxConcurrent: 4},
			{ID: "apko2", Addr: "apko-server-2:9090", MaxConcurrent: 2},
		},
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Initial status
	status := manager.Status()
	assert.Equal(t, "static", status.Type)
	assert.Equal(t, 2, status.TotalInstances)
	assert.Equal(t, 6, status.TotalCapacity)
	assert.Equal(t, 0, status.ActiveBuilds)
	assert.Len(t, status.Instances, 2)

	// Acquire an instance
	inst, err := manager.Request(ctx, InstanceRequest{JobID: "test-job"})
	require.NoError(t, err)

	// Check status after acquiring
	status = manager.Status()
	assert.Equal(t, 1, status.ActiveBuilds)

	// Release with cache hit
	manager.Release(inst, BuildResult{Success: true, CacheHit: true})

	// Check cache stats
	status = manager.Status()
	assert.Equal(t, 0, status.ActiveBuilds)
	assert.Equal(t, int64(1), status.CacheHits)
	assert.Equal(t, int64(0), status.CacheMisses)
}

func TestStaticManager_CircuitBreaker(t *testing.T) {
	manager, err := NewStaticManager(StaticManagerConfig{
		Instances: []InstanceConfig{
			{ID: "apko1", Addr: "apko-server-1:9090", MaxConcurrent: 2},
		},
		CircuitBreakerThreshold: 2,
		CircuitBreakerRecovery:  100 * time.Millisecond,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// First failure
	inst1, err := manager.Request(ctx, InstanceRequest{JobID: "job1"})
	require.NoError(t, err)
	manager.Release(inst1, BuildResult{Success: false, Error: "test failure"})

	// Check status shows failure
	status := manager.Status()
	assert.Equal(t, 1, status.Instances[0].Failures)
	assert.False(t, status.Instances[0].CircuitOpen)

	// Second failure should open circuit
	inst2, err := manager.Request(ctx, InstanceRequest{JobID: "job2"})
	require.NoError(t, err)
	manager.Release(inst2, BuildResult{Success: false, Error: "test failure"})

	status = manager.Status()
	assert.Equal(t, 2, status.Instances[0].Failures)
	assert.True(t, status.Instances[0].CircuitOpen)

	// Should not be able to get an instance now
	_, err = manager.Request(ctx, InstanceRequest{JobID: "job3"})
	assert.Error(t, err)

	// Wait for recovery timeout
	time.Sleep(150 * time.Millisecond)

	// Should be able to get an instance again (half-open state)
	inst3, err := manager.Request(ctx, InstanceRequest{JobID: "job4"})
	require.NoError(t, err)

	// Success should reset failures and close circuit
	manager.Release(inst3, BuildResult{Success: true})

	status = manager.Status()
	assert.Equal(t, 0, status.Instances[0].Failures)
	assert.False(t, status.Instances[0].CircuitOpen)
}

func TestStaticManager_AddRemove(t *testing.T) {
	manager, err := NewStaticManager(StaticManagerConfig{
		Instances: []InstanceConfig{
			{ID: "apko1", Addr: "apko-server-1:9090", MaxConcurrent: 4},
		},
	})
	require.NoError(t, err)

	// Add a new instance
	err = manager.Add(InstanceConfig{
		ID:            "apko2",
		Addr:          "apko-server-2:9090",
		MaxConcurrent: 2,
	})
	require.NoError(t, err)

	// Verify it was added
	assert.Len(t, manager.List(), 2)

	// Try to add duplicate by ID
	err = manager.Add(InstanceConfig{
		ID:   "apko2",
		Addr: "apko-server-3:9090",
	})
	assert.Error(t, err)

	// Try to add duplicate by addr
	err = manager.Add(InstanceConfig{
		ID:   "apko3",
		Addr: "apko-server-2:9090",
	})
	assert.Error(t, err)

	// Remove an instance
	err = manager.Remove("apko1")
	require.NoError(t, err)
	assert.Len(t, manager.List(), 1)

	// Try to remove non-existent
	err = manager.Remove("nonexistent")
	assert.Error(t, err)
}

func TestStaticManager_SingleAddr(t *testing.T) {
	manager, err := NewStaticManagerFromSingleAddr("apko-server:9090", 8)
	require.NoError(t, err)

	assert.Equal(t, 8, manager.TotalCapacity())
	assert.Len(t, manager.List(), 1)
	assert.Equal(t, "apko-server:9090", manager.List()[0].Addr)
}

func TestStaticManager_DefaultMaxConcurrent(t *testing.T) {
	manager, err := NewStaticManager(StaticManagerConfig{
		Instances: []InstanceConfig{
			{Addr: "apko-server:9090"}, // No MaxConcurrent specified
		},
	})
	require.NoError(t, err)

	// Should use default of 16
	assert.Equal(t, 16, manager.TotalCapacity())
}

func TestStaticManager_CacheStats(t *testing.T) {
	manager, err := NewStaticManager(StaticManagerConfig{
		Instances: []InstanceConfig{
			{ID: "apko1", Addr: "apko-server:9090", MaxConcurrent: 4},
		},
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Build with cache hit
	inst1, _ := manager.Request(ctx, InstanceRequest{JobID: "job1"})
	manager.Release(inst1, BuildResult{Success: true, CacheHit: true})

	// Build with cache miss
	inst2, _ := manager.Request(ctx, InstanceRequest{JobID: "job2"})
	manager.Release(inst2, BuildResult{Success: true, CacheHit: false})

	// Another cache hit
	inst3, _ := manager.Request(ctx, InstanceRequest{JobID: "job3"})
	manager.Release(inst3, BuildResult{Success: true, CacheHit: true})

	status := manager.Status()
	assert.Equal(t, int64(2), status.CacheHits)
	assert.Equal(t, int64(1), status.CacheMisses)
}

func TestStaticManager_Close(t *testing.T) {
	manager, err := NewStaticManager(StaticManagerConfig{
		Instances: []InstanceConfig{
			{Addr: "apko-server:9090"},
		},
	})
	require.NoError(t, err)

	// Close should be a no-op for static manager
	err = manager.Close()
	assert.NoError(t, err)
}

func TestStaticManager_EmptyInstances(t *testing.T) {
	_, err := NewStaticManager(StaticManagerConfig{
		Instances: []InstanceConfig{},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one apko instance is required")
}

func TestStaticManager_EmptyAddr(t *testing.T) {
	_, err := NewStaticManager(StaticManagerConfig{
		Instances: []InstanceConfig{
			{ID: "apko1"}, // No Addr
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "instance addr is required")
}

func TestStaticManager_VerifyInterface(t *testing.T) {
	// Verify StaticManager implements Manager interface
	var _ Manager = (*StaticManager)(nil)
}
