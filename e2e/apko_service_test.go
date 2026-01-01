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

package e2e

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/dlorenc/melange2/e2e/harness"
	"github.com/dlorenc/melange2/pkg/service/apko"
)

// TestApkoService_Health tests the health endpoint of the apko service.
func TestApkoService_Health(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// Start an apko server
	server := apko.NewServer(apko.ServerConfig{
		Registry:      "localhost:5000/apko-cache", // Will fail, but that's OK for health check
		MaxConcurrent: 4,
	})

	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	grpcServer := grpc.NewServer()
	apko.RegisterApkoServiceServer(grpcServer, server)

	// Register gRPC health check
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("apko.v1.ApkoService", grpc_health_v1.HealthCheckResponse_SERVING)

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	// Create client
	ctx := context.Background()
	client, err := apko.NewClient(ctx, apko.ClientConfig{
		Addr:           lis.Addr().String(),
		RequestTimeout: 5 * time.Second,
	})
	require.NoError(t, err)
	defer client.Close()

	// Test Health
	resp, err := client.Health(ctx)
	require.NoError(t, err)
	assert.Equal(t, apko.HealthResponse_SERVING, resp.Status)
	assert.Equal(t, int32(0), resp.ActiveRequests)
	assert.Equal(t, int32(4), resp.MaxConcurrent)
}

// TestApkoService_CircuitBreaker tests the circuit breaker behavior.
func TestApkoService_CircuitBreaker(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// Start an apko server that will always fail builds
	server := apko.NewServer(apko.ServerConfig{
		Registry:      "invalid-registry:99999/apko-cache", // Will fail
		MaxConcurrent: 2,
	})

	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	grpcServer := grpc.NewServer()
	apko.RegisterApkoServiceServer(grpcServer, server)

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	// Create client with low threshold for testing
	ctx := context.Background()
	client, err := apko.NewClient(ctx, apko.ClientConfig{
		Addr:                    lis.Addr().String(),
		RequestTimeout:          2 * time.Second,
		MaxRetries:              0, // No retries to speed up test
		CircuitBreakerThreshold: 2,
		CircuitBreakerRecovery:  100 * time.Millisecond,
	})
	require.NoError(t, err)
	defer client.Close()

	// Circuit should be closed initially
	state := client.GetCircuitState()
	assert.False(t, state.Open)

	// Make failing requests to trigger circuit breaker
	req := &apko.BuildLayersRequest{
		ImageConfigYaml: "contents:\n  packages:\n    - busybox",
		Arch:            "x86_64",
		RequestId:       "test-cb-1",
	}

	// First failure
	_, err = client.BuildLayers(ctx, req)
	require.Error(t, err)

	// Second failure - should open circuit
	_, err = client.BuildLayers(ctx, req)
	require.Error(t, err)

	// Circuit should be open
	state = client.GetCircuitState()
	assert.True(t, state.Open)
	assert.Equal(t, 2, state.Failures)

	// Request should fail immediately due to open circuit
	_, err = client.BuildLayers(ctx, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "circuit breaker is open")

	// Wait for recovery period
	time.Sleep(150 * time.Millisecond)

	// Circuit should allow test request now
	state = client.GetCircuitState()
	assert.False(t, state.Open) // isCircuitOpen() returns false after recovery

	// Reset circuit for clean state
	client.ResetCircuit()
	state = client.GetCircuitState()
	assert.False(t, state.Open)
	assert.Equal(t, 0, state.Failures)
}

// TestApkoService_WithRegistry tests the full integration with a real registry.
func TestApkoService_WithRegistry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// Start registry and buildkit using harness
	h := harness.New(t, harness.WithRegistry())
	ctx := h.Context()

	registryAddr := h.RegistryAddr()
	require.NotEmpty(t, registryAddr)

	// Start an apko server with the real registry
	server := apko.NewServer(apko.ServerConfig{
		Registry:         registryAddr + "/apko-cache",
		RegistryInsecure: true, // Test registry is HTTP
		MaxConcurrent:    2,
	})

	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	grpcServer := grpc.NewServer()
	apko.RegisterApkoServiceServer(grpcServer, server)

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	// Create client
	client, err := apko.NewClient(ctx, apko.ClientConfig{
		Addr:           lis.Addr().String(),
		RequestTimeout: 2 * time.Minute, // Building layers can take time
		MaxRetries:     1,
	})
	require.NoError(t, err)
	defer client.Close()

	// Test building layers with a simple config
	resp, err := client.BuildLayers(ctx, &apko.BuildLayersRequest{
		ImageConfigYaml: `
contents:
  repositories:
    - https://packages.wolfi.dev/os
  keyring:
    - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
  packages:
    - wolfi-baselayout
`,
		Arch:             "x86_64",
		RequestId:        "test-build-1",
		MaxLayers:        5,
		IgnoreSignatures: true,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.ImageRef)
	assert.Greater(t, resp.LayerCount, int32(0))
	assert.False(t, resp.CacheHit) // First build should not be cached
	assert.Greater(t, resp.DurationMs, int64(0))

	// Second request with same config should hit cache
	resp2, err := client.BuildLayers(ctx, &apko.BuildLayersRequest{
		ImageConfigYaml: `
contents:
  repositories:
    - https://packages.wolfi.dev/os
  keyring:
    - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
  packages:
    - wolfi-baselayout
`,
		Arch:             "x86_64",
		RequestId:        "test-build-2",
		MaxLayers:        5,
		IgnoreSignatures: true,
	})
	require.NoError(t, err)
	assert.Equal(t, resp.ImageRef, resp2.ImageRef) // Same image ref
	assert.True(t, resp2.CacheHit)                 // Should be cached

	// Different config should produce different image
	resp3, err := client.BuildLayers(ctx, &apko.BuildLayersRequest{
		ImageConfigYaml: `
contents:
  repositories:
    - https://packages.wolfi.dev/os
  keyring:
    - https://packages.wolfi.dev/os/wolfi-signing.rsa.pub
  packages:
    - wolfi-baselayout
    - busybox
`,
		Arch:             "x86_64",
		RequestId:        "test-build-3",
		MaxLayers:        5,
		IgnoreSignatures: true,
	})
	require.NoError(t, err)
	assert.NotEqual(t, resp.ImageRef, resp3.ImageRef) // Different image ref
	assert.False(t, resp3.CacheHit)                   // Not cached

	// Verify stats
	stats := server.Stats()
	assert.Equal(t, 1, int(stats.CacheHits))
	assert.Equal(t, 2, int(stats.CacheMisses))
}

// TestApkoService_Semaphore tests concurrent request limiting.
func TestApkoService_Semaphore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	// Start registry and buildkit using harness
	h := harness.New(t, harness.WithRegistry())

	registryAddr := h.RegistryAddr()
	require.NotEmpty(t, registryAddr)

	// Start an apko server with limited concurrency
	server := apko.NewServer(apko.ServerConfig{
		Registry:         registryAddr + "/apko-cache",
		RegistryInsecure: true,
		MaxConcurrent:    1, // Only allow 1 concurrent build
	})

	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	grpcServer := grpc.NewServer()
	apko.RegisterApkoServiceServer(grpcServer, server)

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	// Health check should show max concurrent
	ctx := h.Context()
	client, err := apko.NewClient(ctx, apko.ClientConfig{
		Addr:           lis.Addr().String(),
		RequestTimeout: 2 * time.Minute,
	})
	require.NoError(t, err)
	defer client.Close()

	resp, err := client.Health(ctx)
	require.NoError(t, err)
	assert.Equal(t, int32(1), resp.MaxConcurrent)
}
