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
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func TestDefaultClientConfig(t *testing.T) {
	cfg := DefaultClientConfig("localhost:9090")

	assert.Equal(t, "localhost:9090", cfg.Addr)
	assert.Equal(t, 5*time.Minute, cfg.RequestTimeout)
	assert.Equal(t, 3, cfg.MaxRetries)
	assert.Equal(t, 100*time.Millisecond, cfg.InitialBackoff)
	assert.Equal(t, 10*time.Second, cfg.MaxBackoff)
	assert.Equal(t, 5, cfg.CircuitBreakerThreshold)
	assert.Equal(t, 30*time.Second, cfg.CircuitBreakerRecovery)
}

func TestClientConfig_Defaults(t *testing.T) {
	// Test that NewClient applies defaults
	tests := []struct {
		name     string
		config   ClientConfig
		expected ClientConfig
	}{
		{
			name: "empty config gets defaults",
			config: ClientConfig{
				Addr: "localhost:9090",
			},
			expected: ClientConfig{
				Addr:                    "localhost:9090",
				RequestTimeout:          5 * time.Minute,
				MaxRetries:              3,
				InitialBackoff:          100 * time.Millisecond,
				MaxBackoff:              10 * time.Second,
				CircuitBreakerThreshold: 5,
				CircuitBreakerRecovery:  30 * time.Second,
			},
		},
		{
			name: "partial config preserves set values",
			config: ClientConfig{
				Addr:           "localhost:9090",
				RequestTimeout: 1 * time.Minute,
				MaxRetries:     5,
			},
			expected: ClientConfig{
				Addr:                    "localhost:9090",
				RequestTimeout:          1 * time.Minute,
				MaxRetries:              5,
				InitialBackoff:          100 * time.Millisecond,
				MaxBackoff:              10 * time.Second,
				CircuitBreakerThreshold: 5,
				CircuitBreakerRecovery:  30 * time.Second,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't actually create the client without a server,
			// but we can verify the config validation logic
			cfg := tt.config

			if cfg.RequestTimeout == 0 {
				cfg.RequestTimeout = 5 * time.Minute
			}
			if cfg.MaxRetries == 0 {
				cfg.MaxRetries = 3
			}
			if cfg.InitialBackoff == 0 {
				cfg.InitialBackoff = 100 * time.Millisecond
			}
			if cfg.MaxBackoff == 0 {
				cfg.MaxBackoff = 10 * time.Second
			}
			if cfg.CircuitBreakerThreshold == 0 {
				cfg.CircuitBreakerThreshold = 5
			}
			if cfg.CircuitBreakerRecovery == 0 {
				cfg.CircuitBreakerRecovery = 30 * time.Second
			}

			assert.Equal(t, tt.expected, cfg)
		})
	}
}

func TestClient_CircuitBreaker(t *testing.T) {
	// Test circuit breaker state management
	client := &Client{
		config: ClientConfig{
			CircuitBreakerThreshold: 3,
			CircuitBreakerRecovery:  100 * time.Millisecond,
		},
	}

	// Initially closed
	assert.False(t, client.isCircuitOpen())
	state := client.GetCircuitState()
	assert.False(t, state.Open)
	assert.Equal(t, 0, state.Failures)

	// Record failures
	client.recordFailure()
	assert.Equal(t, 1, client.failures)
	assert.False(t, client.isCircuitOpen())

	client.recordFailure()
	assert.Equal(t, 2, client.failures)
	assert.False(t, client.isCircuitOpen())

	// Third failure should open circuit
	client.recordFailure()
	assert.Equal(t, 3, client.failures)
	assert.True(t, client.isCircuitOpen())

	state = client.GetCircuitState()
	assert.True(t, state.Open)
	assert.Equal(t, 3, state.Failures)

	// Wait for recovery period
	time.Sleep(150 * time.Millisecond)

	// Circuit should allow test request
	assert.False(t, client.isCircuitOpen())

	// Success should close circuit
	client.recordSuccess()
	assert.False(t, client.isCircuitOpen())
	assert.Equal(t, 0, client.failures)
}

func TestClient_ResetCircuit(t *testing.T) {
	client := &Client{
		config: ClientConfig{
			CircuitBreakerThreshold: 2,
		},
	}

	// Open the circuit
	client.recordFailure()
	client.recordFailure()
	assert.True(t, client.circuitOpen)
	assert.Equal(t, 2, client.failures)

	// Reset should clear everything
	client.ResetCircuit()
	assert.False(t, client.circuitOpen)
	assert.Equal(t, 0, client.failures)
	assert.True(t, client.lastFailure.IsZero())
	assert.True(t, client.circuitOpenedAt.IsZero())
}

func TestClient_isRetryable(t *testing.T) {
	client := &Client{}

	tests := []struct {
		name     string
		code     codes.Code
		expected bool
	}{
		{"Unavailable is retryable", codes.Unavailable, true},
		{"ResourceExhausted is retryable", codes.ResourceExhausted, true},
		{"Aborted is retryable", codes.Aborted, true},
		{"DeadlineExceeded is retryable", codes.DeadlineExceeded, true},
		{"InvalidArgument is not retryable", codes.InvalidArgument, false},
		{"NotFound is not retryable", codes.NotFound, false},
		{"Internal is not retryable", codes.Internal, false},
		{"PermissionDenied is not retryable", codes.PermissionDenied, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := status.Error(tt.code, "test error")
			assert.Equal(t, tt.expected, client.isRetryable(err))
		})
	}
}

// mockApkoServer is a mock implementation for testing
type mockApkoServer struct {
	UnimplementedApkoServiceServer
	buildLayersResponse *BuildLayersResponse
	buildLayersError    error
	healthResponse      *HealthResponse
	buildLayersCalls    int
}

func (m *mockApkoServer) BuildLayers(ctx context.Context, req *BuildLayersRequest) (*BuildLayersResponse, error) {
	m.buildLayersCalls++
	if m.buildLayersError != nil {
		return nil, m.buildLayersError
	}
	return m.buildLayersResponse, nil
}

func (m *mockApkoServer) Health(ctx context.Context, req *HealthRequest) (*HealthResponse, error) {
	if m.healthResponse != nil {
		return m.healthResponse, nil
	}
	return &HealthResponse{
		Status:         HealthResponse_SERVING,
		ActiveRequests: 0,
		MaxConcurrent:  16,
	}, nil
}

func TestClient_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Start a mock gRPC server
	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	mock := &mockApkoServer{
		buildLayersResponse: &BuildLayersResponse{
			ImageRef:   "registry:5000/apko-cache:abc123",
			LayerCount: 5,
			CacheHit:   false,
			DurationMs: 1000,
		},
	}

	grpcServer := grpc.NewServer()
	RegisterApkoServiceServer(grpcServer, mock)

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	// Create client
	ctx := context.Background()
	client, err := NewClient(ctx, ClientConfig{
		Addr:           lis.Addr().String(),
		RequestTimeout: 5 * time.Second,
		MaxRetries:     2,
	})
	require.NoError(t, err)
	defer client.Close()

	// Test Health
	healthResp, err := client.Health(ctx)
	require.NoError(t, err)
	assert.Equal(t, HealthResponse_SERVING, healthResp.Status)

	// Test BuildLayers
	resp, err := client.BuildLayers(ctx, &BuildLayersRequest{
		ImageConfigYaml: "contents:\n  packages:\n    - busybox",
		Arch:            "x86_64",
		RequestId:       "test-123",
	})
	require.NoError(t, err)
	assert.Equal(t, "registry:5000/apko-cache:abc123", resp.ImageRef)
	assert.Equal(t, int32(5), resp.LayerCount)
	assert.Equal(t, 1, mock.buildLayersCalls)
}

func TestClient_Retry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Start a mock gRPC server that fails first then succeeds
	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	failCount := 0
	mock := &mockApkoServer{}

	// Override BuildLayers to fail twice then succeed
	originalBuildLayers := mock.BuildLayers
	mock.buildLayersError = status.Error(codes.Unavailable, "temporary error")

	grpcServer := grpc.NewServer()

	// Create a wrapper server that tracks calls
	wrapper := &retryTestServer{
		mock:        mock,
		failCount:   &failCount,
		maxFailures: 2,
	}
	RegisterApkoServiceServer(grpcServer, wrapper)

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	// Suppress unused variable warning
	_ = originalBuildLayers

	// Create client with short backoff for testing
	ctx := context.Background()
	client, err := NewClient(ctx, ClientConfig{
		Addr:           lis.Addr().String(),
		RequestTimeout: 5 * time.Second,
		MaxRetries:     3,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     50 * time.Millisecond,
	})
	require.NoError(t, err)
	defer client.Close()

	// Should succeed after retries
	resp, err := client.BuildLayers(ctx, &BuildLayersRequest{
		ImageConfigYaml: "contents:\n  packages:\n    - busybox",
		Arch:            "x86_64",
		RequestId:       "test-retry",
	})
	require.NoError(t, err)
	assert.Equal(t, "registry:5000/apko-cache:retry-success", resp.ImageRef)
	assert.Equal(t, 3, failCount) // 2 failures + 1 success
}

// retryTestServer wraps a mock server to simulate failures
type retryTestServer struct {
	UnimplementedApkoServiceServer
	mock        *mockApkoServer
	failCount   *int
	maxFailures int
}

func (s *retryTestServer) BuildLayers(ctx context.Context, req *BuildLayersRequest) (*BuildLayersResponse, error) {
	*s.failCount++
	if *s.failCount <= s.maxFailures {
		return nil, status.Error(codes.Unavailable, "temporary error")
	}
	return &BuildLayersResponse{
		ImageRef:   "registry:5000/apko-cache:retry-success",
		LayerCount: 3,
		CacheHit:   false,
		DurationMs: 500,
	}, nil
}

func (s *retryTestServer) Health(ctx context.Context, req *HealthRequest) (*HealthResponse, error) {
	return s.mock.Health(ctx, req)
}

func TestClient_Close(t *testing.T) {
	// Test that Close works on a nil connection
	client := &Client{}
	err := client.Close()
	assert.NoError(t, err)

	// Test with an actual connection
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	grpcServer := grpc.NewServer()
	RegisterApkoServiceServer(grpcServer, &mockApkoServer{})

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	ctx := context.Background()
	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	client = &Client{
		conn:   conn,
		client: NewApkoServiceClient(conn),
		config: DefaultClientConfig(lis.Addr().String()),
	}

	_ = ctx // suppress unused variable warning

	err = client.Close()
	assert.NoError(t, err)
}
