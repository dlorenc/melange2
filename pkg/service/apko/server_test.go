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

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewServer(t *testing.T) {
	tests := []struct {
		name           string
		config         ServerConfig
		expectedMax    int
	}{
		{
			name:        "default config",
			config:      ServerConfig{},
			expectedMax: 16, // default
		},
		{
			name: "custom max concurrent",
			config: ServerConfig{
				MaxConcurrent: 8,
			},
			expectedMax: 8,
		},
		{
			name: "full config",
			config: ServerConfig{
				Registry:         "registry:5000/apko-cache",
				RegistryInsecure: true,
				ApkCacheDir:      "/tmp/apk-cache",
				MaxConcurrent:    32,
			},
			expectedMax: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewServer(tt.config)
			require.NotNil(t, server)
			assert.Equal(t, tt.expectedMax, server.MaxConcurrent)
			assert.Equal(t, tt.config.Registry, server.Registry)
			assert.Equal(t, tt.config.RegistryInsecure, server.RegistryInsecure)
		})
	}
}

func TestServer_Health(t *testing.T) {
	server := NewServer(ServerConfig{
		MaxConcurrent: 4,
	})

	ctx := context.Background()
	resp, err := server.Health(ctx, &HealthRequest{})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, HealthResponse_SERVING, resp.Status)
	assert.Equal(t, int32(0), resp.ActiveRequests)
	assert.Equal(t, int32(4), resp.MaxConcurrent)
}

func TestServer_Stats(t *testing.T) {
	server := NewServer(ServerConfig{
		MaxConcurrent: 8,
	})

	stats := server.Stats()
	assert.Equal(t, 0, stats.ActiveRequests)
	assert.Equal(t, 8, stats.MaxConcurrent)
	assert.Equal(t, int64(0), stats.CacheHits)
	assert.Equal(t, int64(0), stats.CacheMisses)
}

func TestServer_BuildLayers_InvalidArguments(t *testing.T) {
	server := NewServer(ServerConfig{
		Registry:      "registry:5000/apko-cache",
		MaxConcurrent: 4,
	})

	ctx := context.Background()

	tests := []struct {
		name        string
		req         *BuildLayersRequest
		expectedErr codes.Code
	}{
		{
			name:        "missing image config",
			req:         &BuildLayersRequest{Arch: "x86_64"},
			expectedErr: codes.InvalidArgument,
		},
		{
			name:        "missing arch",
			req:         &BuildLayersRequest{ImageConfigYaml: "test: value"},
			expectedErr: codes.InvalidArgument,
		},
		{
			name: "invalid yaml",
			req: &BuildLayersRequest{
				ImageConfigYaml: "invalid: yaml: [",
				Arch:            "x86_64",
			},
			expectedErr: codes.InvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := server.BuildLayers(ctx, tt.req)
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, tt.expectedErr, st.Code())
		})
	}
}

func TestServer_hashConfig(t *testing.T) {
	server := NewServer(ServerConfig{})

	// Same config should produce same hash
	cfg1 := apko_types.ImageConfiguration{
		Contents: apko_types.ImageContents{
			Packages: []string{"busybox", "glibc"},
		},
		Archs: []apko_types.Architecture{apko_types.ParseArchitecture("x86_64")},
	}

	cfg2 := apko_types.ImageConfiguration{
		Contents: apko_types.ImageContents{
			Packages: []string{"busybox", "glibc"},
		},
		Archs: []apko_types.Architecture{apko_types.ParseArchitecture("x86_64")},
	}

	hash1 := server.hashConfig(cfg1)
	hash2 := server.hashConfig(cfg2)

	assert.Equal(t, hash1, hash2)
	assert.Len(t, hash1, 16) // First 16 chars of hex

	// Different config should produce different hash
	cfg3 := apko_types.ImageConfiguration{
		Contents: apko_types.ImageContents{
			Packages: []string{"busybox", "glibc", "curl"},
		},
		Archs: []apko_types.Architecture{apko_types.ParseArchitecture("x86_64")},
	}

	hash3 := server.hashConfig(cfg3)
	assert.NotEqual(t, hash1, hash3)

	// Different arch should produce different hash
	cfg4 := apko_types.ImageConfiguration{
		Contents: apko_types.ImageContents{
			Packages: []string{"busybox", "glibc"},
		},
		Archs: []apko_types.Architecture{apko_types.ParseArchitecture("aarch64")},
	}

	hash4 := server.hashConfig(cfg4)
	assert.NotEqual(t, hash1, hash4)
}

func TestServer_Semaphore(t *testing.T) {
	server := NewServer(ServerConfig{
		MaxConcurrent: 2,
	})

	// Semaphore should have capacity of MaxConcurrent
	assert.Equal(t, 2, cap(server.sem))

	// Acquire both slots
	server.sem <- struct{}{}
	server.sem <- struct{}{}

	// Try to acquire non-blocking - should fail
	select {
	case server.sem <- struct{}{}:
		t.Fatal("semaphore should be full")
	default:
		// Expected
	}

	// Release one
	<-server.sem

	// Now should be able to acquire
	select {
	case server.sem <- struct{}{}:
		// Expected
	default:
		t.Fatal("semaphore should have space")
	}
}

func TestServer_ActiveRequests(t *testing.T) {
	server := NewServer(ServerConfig{
		MaxConcurrent: 4,
	})

	// Initially 0
	assert.Equal(t, int32(0), server.activeRequests.Load())

	// Increment
	server.activeRequests.Add(1)
	assert.Equal(t, int32(1), server.activeRequests.Load())

	server.activeRequests.Add(1)
	assert.Equal(t, int32(2), server.activeRequests.Load())

	// Decrement
	server.activeRequests.Add(-1)
	assert.Equal(t, int32(1), server.activeRequests.Load())
}

func TestServer_CacheMetrics(t *testing.T) {
	server := NewServer(ServerConfig{
		MaxConcurrent: 4,
	})

	// Initially 0
	assert.Equal(t, int64(0), server.cacheHits.Load())
	assert.Equal(t, int64(0), server.cacheMisses.Load())

	// Record some hits/misses
	server.cacheHits.Add(1)
	server.cacheMisses.Add(2)

	assert.Equal(t, int64(1), server.cacheHits.Load())
	assert.Equal(t, int64(2), server.cacheMisses.Load())

	// Verify stats reflect metrics
	stats := server.Stats()
	assert.Equal(t, int64(1), stats.CacheHits)
	assert.Equal(t, int64(2), stats.CacheMisses)
}
