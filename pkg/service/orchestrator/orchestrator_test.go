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

package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/pkg/service/buildkit"
	"github.com/dlorenc/melange2/pkg/service/client"
	"github.com/dlorenc/melange2/pkg/service/types"
)

// mockServer creates a test HTTP server that simulates the melange API.
type mockServer struct {
	t              *testing.T
	mu             sync.Mutex
	builds         map[string]*types.Build
	claimedPackage *types.PackageJob
	claimCount     int
}

func newMockServer(t *testing.T) *mockServer {
	return &mockServer{
		t:      t,
		builds: make(map[string]*types.Build),
	}
}

func (m *mockServer) addBuild(build *types.Build) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.builds[build.ID] = build
}

func (m *mockServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Route requests
	switch {
	case r.URL.Path == "/healthz":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

	case r.URL.Path == "/api/v1/builds/active" && r.Method == http.MethodGet:
		// List active builds
		var activeBuilds []*types.Build
		for _, b := range m.builds {
			if b.Status == types.BuildStatusPending || b.Status == types.BuildStatusRunning {
				activeBuilds = append(activeBuilds, b)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(activeBuilds)

	case r.URL.Path == "/api/v1/builds/test-build" && r.Method == http.MethodGet:
		// Get specific build
		if build, ok := m.builds["test-build"]; ok {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(build)
		} else {
			http.Error(w, "build not found", http.StatusNotFound)
		}

	case r.URL.Path == "/api/v1/builds/test-build" && r.Method == http.MethodPut:
		// Update build status
		var req struct {
			Status types.BuildStatus `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if build, ok := m.builds["test-build"]; ok {
			build.Status = req.Status
			if req.Status == types.BuildStatusRunning && build.StartedAt == nil {
				now := time.Now()
				build.StartedAt = &now
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(build)
		} else {
			http.Error(w, "build not found", http.StatusNotFound)
		}

	case r.URL.Path == "/api/v1/builds/test-build/packages/claim" && r.Method == http.MethodPost:
		// Claim any ready package
		m.claimCount++
		if m.claimCount == 1 && m.claimedPackage != nil {
			m.claimedPackage.Status = types.PackageStatusRunning
			now := time.Now()
			m.claimedPackage.StartedAt = &now
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(m.claimedPackage)
		} else {
			// No more packages to claim
			w.WriteHeader(http.StatusNoContent)
		}

	case r.URL.Path == "/api/v1/builds/test-build/packages/test-pkg" && r.Method == http.MethodPut:
		// Update package status
		var req client.UpdatePackageRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Update the package in the build
		if build, ok := m.builds["test-build"]; ok {
			for i := range build.Packages {
				if build.Packages[i].Name == "test-pkg" {
					build.Packages[i].Status = req.Status
					build.Packages[i].Error = req.Error
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(&build.Packages[i])
					return
				}
			}
		}
		http.Error(w, "package not found", http.StatusNotFound)

	default:
		http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
	}
}

func TestNew(t *testing.T) {
	// Create a mock pool
	pool, err := buildkit.NewPoolFromSingleAddr("tcp://localhost:1234", "x86_64")
	require.NoError(t, err)

	// Create a mock client
	apiClient := client.New("http://localhost:8080")

	// Create orchestrator with various configs
	orch := New(apiClient, nil, pool, Config{
		PollInterval: 2 * time.Second,
		MaxParallel:  4,
	})

	assert.NotNil(t, orch)
	assert.NotNil(t, orch.client)
	assert.Equal(t, 2*time.Second, orch.config.PollInterval)
	assert.Equal(t, 4, orch.config.MaxParallel)
}

func TestOrchestratorDefaults(t *testing.T) {
	pool, err := buildkit.NewPoolFromSingleAddr("tcp://localhost:1234", "x86_64")
	require.NoError(t, err)

	apiClient := client.New("http://localhost:8080")

	orch := New(apiClient, nil, pool, Config{})

	assert.Equal(t, time.Second, orch.config.PollInterval)
	assert.Equal(t, "/var/lib/melange/output", orch.config.OutputDir)
}

func TestProcessBuildsListsActiveBuilds(t *testing.T) {
	// Create mock server that tracks requests
	listCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/builds/active" && r.Method == http.MethodGet {
			listCalled = true
			// Return empty list - just testing the API call is made
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]*types.Build{})
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	})

	testServer := httptest.NewServer(handler)
	defer testServer.Close()

	// Create orchestrator
	pool, err := buildkit.NewPoolFromSingleAddr("tcp://localhost:1234", "x86_64")
	require.NoError(t, err)

	apiClient := client.New(testServer.URL)

	orch := New(apiClient, nil, pool, Config{
		PollInterval: 100 * time.Millisecond,
		MaxParallel:  1,
	})

	ctx := context.Background()

	// Run processBuilds - should call ListActiveBuilds via HTTP
	err = orch.processBuilds(ctx)
	assert.NoError(t, err)
	assert.True(t, listCalled, "ListActiveBuilds should have been called via HTTP")
}

func TestUpdateBuildStatus(t *testing.T) {
	// Create mock server
	mock := newMockServer(t)
	testServer := httptest.NewServer(mock)
	defer testServer.Close()

	// Add a test build with all packages completed
	build := &types.Build{
		ID:     "test-build",
		Status: types.BuildStatusRunning,
		Packages: []types.PackageJob{
			{
				Name:   "test-pkg",
				Status: types.PackageStatusSuccess,
			},
		},
		Spec: types.BuildSpec{},
	}
	mock.addBuild(build)

	// Create orchestrator
	pool, err := buildkit.NewPoolFromSingleAddr("tcp://localhost:1234", "x86_64")
	require.NoError(t, err)

	apiClient := client.New(testServer.URL)

	orch := New(apiClient, nil, pool, Config{})

	ctx := context.Background()

	// Update build status
	orch.updateBuildStatus(ctx, "test-build")

	// Verify the build status was updated
	mock.mu.Lock()
	assert.Equal(t, types.BuildStatusSuccess, mock.builds["test-build"].Status)
	mock.mu.Unlock()
}

func TestCascadeFailure(t *testing.T) {
	// Create mock server
	mock := newMockServer(t)

	// Track update requests
	var updateRequests []struct {
		packageName string
		status      types.PackageStatus
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mock.mu.Lock()
		defer mock.mu.Unlock()

		switch {
		case r.URL.Path == "/api/v1/builds/test-build" && r.Method == http.MethodGet:
			// Return build with dependencies
			build := &types.Build{
				ID:     "test-build",
				Status: types.BuildStatusRunning,
				Packages: []types.PackageJob{
					{
						Name:         "pkg-a",
						Status:       types.PackageStatusFailed,
						Dependencies: nil,
					},
					{
						Name:         "pkg-b",
						Status:       types.PackageStatusPending,
						Dependencies: []string{"pkg-a"},
					},
					{
						Name:         "pkg-c",
						Status:       types.PackageStatusPending,
						Dependencies: []string{"pkg-b"},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(build)

		case r.Method == http.MethodPut && len(r.URL.Path) > len("/api/v1/builds/test-build/packages/"):
			// Extract package name and update
			var req client.UpdatePackageRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// Record the update
			pkgName := r.URL.Path[len("/api/v1/builds/test-build/packages/"):]
			updateRequests = append(updateRequests, struct {
				packageName string
				status      types.PackageStatus
			}{pkgName, req.Status})

			pkg := &types.PackageJob{
				Name:   pkgName,
				Status: req.Status,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(pkg)

		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	})

	testServer := httptest.NewServer(handler)
	defer testServer.Close()

	// Create orchestrator
	pool, err := buildkit.NewPoolFromSingleAddr("tcp://localhost:1234", "x86_64")
	require.NoError(t, err)

	apiClient := client.New(testServer.URL)

	orch := New(apiClient, nil, pool, Config{})

	ctx := context.Background()

	// Cascade failure from pkg-a
	orch.cascadeFailure(ctx, "test-build", "pkg-a")

	// Verify pkg-b was marked as skipped
	assert.NotEmpty(t, updateRequests)
	assert.Equal(t, "pkg-b", updateRequests[0].packageName)
	assert.Equal(t, types.PackageStatusSkipped, updateRequests[0].status)
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{0, "0 B"},
		{100, "100 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1048576, "1.0 MiB"},
		{1073741824, "1.0 GiB"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatBytes(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
