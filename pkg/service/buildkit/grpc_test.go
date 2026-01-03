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
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// mockManager implements Manager for testing the gRPC server.
type mockManager struct {
	workers         []Backend
	requestedWorker *Worker
	requestErr      error
	released        bool
	releaseResult   BuildResult
}

func (m *mockManager) Request(ctx context.Context, req WorkerRequest) (*Worker, error) {
	if m.requestErr != nil {
		return nil, m.requestErr
	}
	if m.requestedWorker != nil {
		return m.requestedWorker, nil
	}
	// Default: return first matching worker
	for _, b := range m.workers {
		if b.Arch == req.Arch {
			return &Worker{
				ID:         b.Addr,
				Addr:       b.Addr,
				Arch:       b.Arch,
				Labels:     b.Labels,
				AcquiredAt: time.Now(),
			}, nil
		}
	}
	return nil, context.DeadlineExceeded
}

func (m *mockManager) Release(worker *Worker, result BuildResult) {
	m.released = true
	m.releaseResult = result
}

func (m *mockManager) Status() ManagerStatus {
	workers := make([]WorkerStatus, len(m.workers))
	for i, b := range m.workers {
		workers[i] = WorkerStatus{
			ID:         b.Addr,
			Addr:       b.Addr,
			Arch:       b.Arch,
			Labels:     b.Labels,
			MaxJobs:    b.MaxJobs,
			ActiveJobs: 0,
		}
	}
	return ManagerStatus{
		Type:             "mock",
		TotalWorkers:     len(m.workers),
		AvailableWorkers: len(m.workers),
		ActiveJobs:       0,
		Workers:          workers,
	}
}

func (m *mockManager) TotalCapacity() int {
	total := 0
	for _, b := range m.workers {
		if b.MaxJobs > 0 {
			total += b.MaxJobs
		} else {
			total += 4 // default
		}
	}
	return total
}

func (m *mockManager) Architectures() []string {
	archs := make(map[string]struct{})
	for _, b := range m.workers {
		archs[b.Arch] = struct{}{}
	}
	result := make([]string, 0, len(archs))
	for a := range archs {
		result = append(result, a)
	}
	return result
}

func (m *mockManager) Close() error {
	return nil
}

// startTestServer starts a gRPC server with the given manager for testing.
func startTestServer(t *testing.T, manager Manager) (string, func()) {
	t.Helper()

	server := NewGRPCServer(GRPCServerConfig{Manager: manager})
	grpcServer := grpc.NewServer()
	RegisterBuildKitManagerServiceServer(grpcServer, server)

	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			t.Logf("gRPC server error: %v", err)
		}
	}()

	cleanup := func() {
		grpcServer.GracefulStop()
	}

	return listener.Addr().String(), cleanup
}

func TestGRPCServer_RequestWorker(t *testing.T) {
	mock := &mockManager{
		workers: []Backend{
			{Addr: "tcp://buildkit-1:1234", Arch: "x86_64", MaxJobs: 4},
			{Addr: "tcp://buildkit-2:1234", Arch: "aarch64", MaxJobs: 4},
		},
	}

	addr, cleanup := startTestServer(t, mock)
	defer cleanup()

	// Create client
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := NewBuildKitManagerServiceClient(conn)

	// Test requesting a worker
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.RequestWorker(ctx, &RequestWorkerRequest{
		Arch:  "x86_64",
		JobId: "test-job-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "tcp://buildkit-1:1234", resp.Worker.Addr)
	assert.Equal(t, "x86_64", resp.Worker.Arch)
	assert.NotEmpty(t, resp.Worker.Id)
}

func TestGRPCServer_ReleaseWorker(t *testing.T) {
	mock := &mockManager{
		workers: []Backend{
			{Addr: "tcp://buildkit-1:1234", Arch: "x86_64", MaxJobs: 4},
		},
	}

	addr, cleanup := startTestServer(t, mock)
	defer cleanup()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := NewBuildKitManagerServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// First request a worker
	reqResp, err := client.RequestWorker(ctx, &RequestWorkerRequest{
		Arch:  "x86_64",
		JobId: "test-job-2",
	})
	require.NoError(t, err)

	// Then release it
	releaseResp, err := client.ReleaseWorker(ctx, &ReleaseWorkerRequest{
		WorkerId: reqResp.Worker.Id,
		Result: &BuildResultInfo{
			Success:    true,
			DurationMs: 1000,
		},
	})
	require.NoError(t, err)
	assert.True(t, releaseResp.Released)
	assert.True(t, mock.released)
	assert.True(t, mock.releaseResult.Success)
}

func TestGRPCServer_GetStatus(t *testing.T) {
	mock := &mockManager{
		workers: []Backend{
			{Addr: "tcp://buildkit-1:1234", Arch: "x86_64", MaxJobs: 8},
			{Addr: "tcp://buildkit-2:1234", Arch: "x86_64", MaxJobs: 8},
		},
	}

	addr, cleanup := startTestServer(t, mock)
	defer cleanup()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := NewBuildKitManagerServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetStatus(ctx, &GetStatusRequest{})
	require.NoError(t, err)
	assert.Equal(t, "mock", resp.Status.Type)
	assert.Equal(t, int32(2), resp.Status.TotalWorkers)
	assert.Equal(t, int32(2), resp.Status.AvailableWorkers)
	assert.Len(t, resp.Status.Workers, 2)
}

func TestGRPCServer_GetCapacity(t *testing.T) {
	mock := &mockManager{
		workers: []Backend{
			{Addr: "tcp://buildkit-1:1234", Arch: "x86_64", MaxJobs: 8},
			{Addr: "tcp://buildkit-2:1234", Arch: "x86_64", MaxJobs: 16},
		},
	}

	addr, cleanup := startTestServer(t, mock)
	defer cleanup()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := NewBuildKitManagerServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetCapacity(ctx, &GetCapacityRequest{})
	require.NoError(t, err)
	assert.Equal(t, int32(24), resp.TotalCapacity) // 8 + 16
}

func TestGRPCServer_GetArchitectures(t *testing.T) {
	mock := &mockManager{
		workers: []Backend{
			{Addr: "tcp://buildkit-1:1234", Arch: "x86_64", MaxJobs: 4},
			{Addr: "tcp://buildkit-2:1234", Arch: "aarch64", MaxJobs: 4},
		},
	}

	addr, cleanup := startTestServer(t, mock)
	defer cleanup()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := NewBuildKitManagerServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetArchitectures(ctx, &GetArchitecturesRequest{})
	require.NoError(t, err)
	assert.Len(t, resp.Architectures, 2)
	assert.Contains(t, resp.Architectures, "x86_64")
	assert.Contains(t, resp.Architectures, "aarch64")
}

func TestGRPCServer_Health(t *testing.T) {
	mock := &mockManager{
		workers: []Backend{
			{Addr: "tcp://buildkit-1:1234", Arch: "x86_64", MaxJobs: 4},
		},
	}

	addr, cleanup := startTestServer(t, mock)
	defer cleanup()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := NewBuildKitManagerServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.Health(ctx, &HealthRequest{})
	require.NoError(t, err)
	assert.Equal(t, HealthResponse_SERVING, resp.Status)
	assert.Equal(t, "mock", resp.ManagerType)
	assert.Equal(t, int32(1), resp.TotalWorkers)
}

func TestGRPCClient_ImplementsManager(t *testing.T) {
	// Test that GRPCClient implements Manager interface
	mock := &mockManager{
		workers: []Backend{
			{Addr: "tcp://buildkit-1:1234", Arch: "x86_64", MaxJobs: 4},
		},
	}

	addr, cleanup := startTestServer(t, mock)
	defer cleanup()

	ctx := context.Background()
	client, err := NewGRPCClient(ctx, DefaultGRPCClientConfig(addr))
	require.NoError(t, err)
	defer client.Close()

	// Verify it implements Manager
	var _ Manager = client

	// Test basic operations
	worker, err := client.Request(ctx, WorkerRequest{
		Arch:  "x86_64",
		JobID: "test-job-3",
	})
	require.NoError(t, err)
	assert.Equal(t, "x86_64", worker.Arch)

	// Release (doesn't return error)
	client.Release(worker, BuildResult{Success: true})

	// Status
	status := client.Status()
	assert.Equal(t, "mock", status.Type)
	assert.Equal(t, 1, status.TotalWorkers)

	// Capacity
	assert.Equal(t, 4, client.TotalCapacity())

	// Architectures
	archs := client.Architectures()
	assert.Contains(t, archs, "x86_64")
}

func TestGRPCServer_RequestWorkerValidation(t *testing.T) {
	mock := &mockManager{
		workers: []Backend{
			{Addr: "tcp://buildkit-1:1234", Arch: "x86_64", MaxJobs: 4},
		},
	}

	addr, cleanup := startTestServer(t, mock)
	defer cleanup()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := NewBuildKitManagerServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test missing arch
	_, err = client.RequestWorker(ctx, &RequestWorkerRequest{
		JobId: "test-job",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "arch is required")
}

func TestGRPCServer_ReleaseUnknownWorker(t *testing.T) {
	mock := &mockManager{
		workers: []Backend{
			{Addr: "tcp://buildkit-1:1234", Arch: "x86_64", MaxJobs: 4},
		},
	}

	addr, cleanup := startTestServer(t, mock)
	defer cleanup()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := NewBuildKitManagerServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try to release a worker that was never acquired
	resp, err := client.ReleaseWorker(ctx, &ReleaseWorkerRequest{
		WorkerId: "unknown-worker-id",
		Result: &BuildResultInfo{
			Success: true,
		},
	})
	require.NoError(t, err)
	// Should return false but not error (idempotent)
	assert.False(t, resp.Released)
}

func TestGRPCClient_CircuitBreaker(t *testing.T) {
	// Create a client with a very short recovery time
	cfg := DefaultGRPCClientConfig("localhost:0") // invalid address
	cfg.CircuitBreakerThreshold = 2
	cfg.CircuitBreakerRecovery = 100 * time.Millisecond

	ctx := context.Background()
	client, err := NewGRPCClient(ctx, cfg)
	require.NoError(t, err)
	defer client.Close()

	// Circuit should be closed initially
	state := client.GetCircuitState()
	assert.False(t, state.Open)

	// Simulate failures
	client.recordFailure()
	client.recordFailure()

	// Circuit should now be open
	state = client.GetCircuitState()
	assert.True(t, state.Open)
	assert.Equal(t, 2, state.Failures)

	// Wait for recovery
	time.Sleep(150 * time.Millisecond)

	// Circuit should be closed (recovery period passed)
	state = client.GetCircuitState()
	assert.False(t, state.Open)

	// Reset and verify
	client.ResetCircuit()
	state = client.GetCircuitState()
	assert.False(t, state.Open)
	assert.Equal(t, 0, state.Failures)
}
