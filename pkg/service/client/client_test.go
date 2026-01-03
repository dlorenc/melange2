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

package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/pkg/service/buildkit"
	svcerrors "github.com/dlorenc/melange2/pkg/service/errors"
	"github.com/dlorenc/melange2/pkg/service/types"
)

func TestNew(t *testing.T) {
	c := New("http://localhost:8080")
	require.NotNil(t, c)
	assert.Equal(t, "http://localhost:8080", c.baseURL)
	assert.NotNil(t, c.httpClient)
	assert.Equal(t, 30*time.Second, c.httpClient.Timeout)
}

func TestHealth(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{
			name:       "healthy server",
			statusCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "unhealthy server",
			statusCode: http.StatusServiceUnavailable,
			wantErr:    true,
		},
		{
			name:       "internal error",
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/healthz", r.URL.Path)
				assert.Equal(t, http.MethodGet, r.Method)
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			c := New(server.URL)
			err := c.Health(context.Background())

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestListBackends(t *testing.T) {
	expectedBackends := []buildkit.Backend{
		{Addr: "tcp://localhost:1234", Arch: "x86_64"},
		{Addr: "tcp://localhost:5678", Arch: "aarch64"},
	}

	t.Run("list all backends", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/v1/backends", r.URL.Path)
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Empty(t, r.URL.Query().Get("arch"))

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(BackendsResponse{
				Backends:      expectedBackends,
				Architectures: []string{"x86_64", "aarch64"},
			})
		}))
		defer server.Close()

		c := New(server.URL)
		resp, err := c.ListBackends(context.Background(), "")

		require.NoError(t, err)
		assert.Len(t, resp.Backends, 2)
		assert.Contains(t, resp.Architectures, "x86_64")
		assert.Contains(t, resp.Architectures, "aarch64")
	})

	t.Run("filter by architecture", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/v1/backends", r.URL.Path)
			assert.Equal(t, "x86_64", r.URL.Query().Get("arch"))

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(BackendsResponse{
				Backends:      []buildkit.Backend{{Addr: "tcp://localhost:1234", Arch: "x86_64"}},
				Architectures: []string{"x86_64"},
			})
		}))
		defer server.Close()

		c := New(server.URL)
		resp, err := c.ListBackends(context.Background(), "x86_64")

		require.NoError(t, err)
		assert.Len(t, resp.Backends, 1)
		assert.Equal(t, "x86_64", resp.Backends[0].Arch)
	})

	t.Run("server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("internal error"))
		}))
		defer server.Close()

		c := New(server.URL)
		_, err := c.ListBackends(context.Background(), "")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "500")
	})
}

func TestAddBackend(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		backend := buildkit.Backend{
			Addr:   "tcp://localhost:9999",
			Arch:   "aarch64",
			Labels: map[string]string{"tier": "high"},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/v1/backends", r.URL.Path)
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			var reqBackend buildkit.Backend
			err := json.NewDecoder(r.Body).Decode(&reqBackend)
			require.NoError(t, err)
			assert.Equal(t, backend.Addr, reqBackend.Addr)
			assert.Equal(t, backend.Arch, reqBackend.Arch)

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(backend)
		}))
		defer server.Close()

		c := New(server.URL)
		result, err := c.AddBackend(context.Background(), backend)

		require.NoError(t, err)
		assert.Equal(t, backend.Addr, result.Addr)
		assert.Equal(t, backend.Arch, result.Arch)
	})

	t.Run("error response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid backend"))
		}))
		defer server.Close()

		c := New(server.URL)
		_, err := c.AddBackend(context.Background(), buildkit.Backend{})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "400")
	})
}

func TestRemoveBackend(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/v1/backends", r.URL.Path)
			assert.Equal(t, http.MethodDelete, r.Method)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			var req map[string]string
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "tcp://localhost:1234", req["addr"])

			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		c := New(server.URL)
		err := c.RemoveBackend(context.Background(), "tcp://localhost:1234")

		assert.NoError(t, err)
	})

	t.Run("not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("backend not found"))
		}))
		defer server.Close()

		c := New(server.URL)
		err := c.RemoveBackend(context.Background(), "tcp://nonexistent:1234")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "404")
	})
}

func TestSubmitBuild(t *testing.T) {
	t.Run("single config", func(t *testing.T) {
		expectedResp := types.CreateBuildResponse{
			ID:       "bld-12345",
			Packages: []string{"test-pkg"},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/v1/builds", r.URL.Path)
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			var req types.CreateBuildRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.NotEmpty(t, req.ConfigYAML)
			assert.Equal(t, "x86_64", req.Arch)

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(expectedResp)
		}))
		defer server.Close()

		c := New(server.URL)
		resp, err := c.SubmitBuild(context.Background(), types.CreateBuildRequest{
			ConfigYAML: "package:\n  name: test-pkg\n  version: 1.0.0",
			Arch:       "x86_64",
		})

		require.NoError(t, err)
		assert.Equal(t, expectedResp.ID, resp.ID)
		assert.Equal(t, expectedResp.Packages, resp.Packages)
	})

	t.Run("multiple configs", func(t *testing.T) {
		expectedResp := types.CreateBuildResponse{
			ID:       "bld-67890",
			Packages: []string{"pkg-a", "pkg-b"},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req types.CreateBuildRequest
			json.NewDecoder(r.Body).Decode(&req)
			assert.Len(t, req.Configs, 2)

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(expectedResp)
		}))
		defer server.Close()

		c := New(server.URL)
		resp, err := c.SubmitBuild(context.Background(), types.CreateBuildRequest{
			Configs: []string{"config1", "config2"},
			Arch:    "x86_64",
		})

		require.NoError(t, err)
		assert.Equal(t, []string{"pkg-a", "pkg-b"}, resp.Packages)
	})

	t.Run("error response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid config"))
		}))
		defer server.Close()

		c := New(server.URL)
		_, err := c.SubmitBuild(context.Background(), types.CreateBuildRequest{})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "400")
	})
}

func TestGetBuild(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		now := time.Now()
		expectedBuild := types.Build{
			ID:        "bld-12345",
			Status:    types.BuildStatusSuccess,
			CreatedAt: now,
			Packages: []types.PackageJob{
				{Name: "test-pkg", Status: types.PackageStatusSuccess},
			},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/v1/builds/bld-12345", r.URL.Path)
			assert.Equal(t, http.MethodGet, r.Method)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(expectedBuild)
		}))
		defer server.Close()

		c := New(server.URL)
		build, err := c.GetBuild(context.Background(), "bld-12345")

		require.NoError(t, err)
		assert.Equal(t, expectedBuild.ID, build.ID)
		assert.Equal(t, expectedBuild.Status, build.Status)
	})

	t.Run("not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("build not found"))
		}))
		defer server.Close()

		c := New(server.URL)
		_, err := c.GetBuild(context.Background(), "nonexistent")

		assert.Error(t, err)
		assert.ErrorIs(t, err, svcerrors.ErrBuildNotFound)
	})
}

func TestListBuilds(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		expectedBuilds := []types.Build{
			{ID: "bld-1", Status: types.BuildStatusSuccess},
			{ID: "bld-2", Status: types.BuildStatusRunning},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/v1/builds", r.URL.Path)
			assert.Equal(t, http.MethodGet, r.Method)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(expectedBuilds)
		}))
		defer server.Close()

		c := New(server.URL)
		builds, err := c.ListBuilds(context.Background())

		require.NoError(t, err)
		assert.Len(t, builds, 2)
		assert.Equal(t, "bld-1", builds[0].ID)
		assert.Equal(t, "bld-2", builds[1].ID)
	})

	t.Run("empty list", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]types.Build{})
		}))
		defer server.Close()

		c := New(server.URL)
		builds, err := c.ListBuilds(context.Background())

		require.NoError(t, err)
		assert.Empty(t, builds)
	})
}

func TestWaitForBuild(t *testing.T) {
	t.Run("immediate success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(types.Build{
				ID:     "bld-1",
				Status: types.BuildStatusSuccess,
			})
		}))
		defer server.Close()

		c := New(server.URL)
		build, err := c.WaitForBuild(context.Background(), "bld-1", 10*time.Millisecond)

		require.NoError(t, err)
		assert.Equal(t, types.BuildStatusSuccess, build.Status)
	})

	t.Run("wait for completion", func(t *testing.T) {
		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			status := types.BuildStatusRunning
			if callCount >= 3 {
				status = types.BuildStatusSuccess
			}
			json.NewEncoder(w).Encode(types.Build{
				ID:     "bld-1",
				Status: status,
			})
		}))
		defer server.Close()

		c := New(server.URL)
		build, err := c.WaitForBuild(context.Background(), "bld-1", 10*time.Millisecond)

		require.NoError(t, err)
		assert.Equal(t, types.BuildStatusSuccess, build.Status)
		assert.GreaterOrEqual(t, callCount, 3)
	})

	t.Run("returns on failure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(types.Build{
				ID:     "bld-1",
				Status: types.BuildStatusFailed,
			})
		}))
		defer server.Close()

		c := New(server.URL)
		build, err := c.WaitForBuild(context.Background(), "bld-1", 10*time.Millisecond)

		require.NoError(t, err)
		assert.Equal(t, types.BuildStatusFailed, build.Status)
	})

	t.Run("returns on partial", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(types.Build{
				ID:     "bld-1",
				Status: types.BuildStatusPartial,
			})
		}))
		defer server.Close()

		c := New(server.URL)
		build, err := c.WaitForBuild(context.Background(), "bld-1", 10*time.Millisecond)

		require.NoError(t, err)
		assert.Equal(t, types.BuildStatusPartial, build.Status)
	})

	t.Run("context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(types.Build{
				ID:     "bld-1",
				Status: types.BuildStatusRunning,
			})
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		c := New(server.URL)
		_, err := c.WaitForBuild(ctx, "bld-1", 10*time.Millisecond)

		assert.Error(t, err)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	})
}

func TestListActiveBuilds(t *testing.T) {
	t.Run("returns active builds only", func(t *testing.T) {
		expectedBuilds := []*types.Build{
			{ID: "bld-1", Status: types.BuildStatusPending},
			{ID: "bld-2", Status: types.BuildStatusRunning},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/v1/builds/active", r.URL.Path)
			assert.Equal(t, http.MethodGet, r.Method)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(expectedBuilds)
		}))
		defer server.Close()

		c := New(server.URL)
		builds, err := c.ListActiveBuilds(context.Background())

		require.NoError(t, err)
		require.Len(t, builds, 2)
		assert.Equal(t, "bld-1", builds[0].ID)
		assert.Equal(t, types.BuildStatusPending, builds[0].Status)
		assert.Equal(t, "bld-2", builds[1].ID)
		assert.Equal(t, types.BuildStatusRunning, builds[1].Status)
	})

	t.Run("empty list", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]*types.Build{})
		}))
		defer server.Close()

		c := New(server.URL)
		builds, err := c.ListActiveBuilds(context.Background())

		require.NoError(t, err)
		assert.Empty(t, builds)
	})
}

func TestClaimPackage(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		expectedPkg := types.PackageJob{
			Name:   "test-pkg",
			Status: types.PackageStatusRunning,
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/v1/builds/bld-123/packages/test-pkg/claim", r.URL.Path)
			assert.Equal(t, http.MethodPost, r.Method)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(expectedPkg)
		}))
		defer server.Close()

		c := New(server.URL)
		pkg, err := c.ClaimPackage(context.Background(), "bld-123", "test-pkg")

		require.NoError(t, err)
		assert.Equal(t, "test-pkg", pkg.Name)
		assert.Equal(t, types.PackageStatusRunning, pkg.Status)
	})

	t.Run("build not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("build not found"))
		}))
		defer server.Close()

		c := New(server.URL)
		_, err := c.ClaimPackage(context.Background(), "nonexistent", "test-pkg")

		require.Error(t, err)
		assert.ErrorIs(t, err, svcerrors.ErrBuildNotFound)
	})

	t.Run("package not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("package not found"))
		}))
		defer server.Close()

		c := New(server.URL)
		_, err := c.ClaimPackage(context.Background(), "bld-123", "nonexistent")

		require.Error(t, err)
		assert.ErrorIs(t, err, svcerrors.ErrPackageNotFound)
	})

	t.Run("package not ready", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte("package not ready: dependencies not satisfied"))
		}))
		defer server.Close()

		c := New(server.URL)
		_, err := c.ClaimPackage(context.Background(), "bld-123", "test-pkg")

		require.Error(t, err)
		assert.ErrorIs(t, err, svcerrors.ErrPackageNotReady)
	})

	t.Run("package already claimed", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte("package already claimed or completed"))
		}))
		defer server.Close()

		c := New(server.URL)
		_, err := c.ClaimPackage(context.Background(), "bld-123", "test-pkg")

		require.Error(t, err)
		assert.ErrorIs(t, err, svcerrors.ErrPackageAlreadyClaimed)
	})

	t.Run("empty build ID", func(t *testing.T) {
		c := New("http://localhost:8080")
		_, err := c.ClaimPackage(context.Background(), "", "test-pkg")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "build ID is required")
	})

	t.Run("empty package name", func(t *testing.T) {
		c := New("http://localhost:8080")
		_, err := c.ClaimPackage(context.Background(), "bld-123", "")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "package name is required")
	})

	t.Run("url encodes special characters", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check that the path is properly encoded
			assert.Equal(t, "/api/v1/builds/bld%2F123/packages/pkg%2Fwith%2Fslash/claim", r.URL.RawPath)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(types.PackageJob{Name: "pkg/with/slash"})
		}))
		defer server.Close()

		c := New(server.URL)
		pkg, err := c.ClaimPackage(context.Background(), "bld/123", "pkg/with/slash")

		require.NoError(t, err)
		assert.Equal(t, "pkg/with/slash", pkg.Name)
	})
}

func TestUpdatePackage(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/v1/builds/bld-123/packages/test-pkg", r.URL.Path)
			assert.Equal(t, http.MethodPut, r.Method)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			var req UpdatePackageRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, types.PackageStatusSuccess, req.Status)
			assert.Equal(t, "/logs/test.log", req.LogPath)
			assert.Equal(t, "/output/test.apk", req.OutputPath)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(types.PackageJob{
				Name:       "test-pkg",
				Status:     req.Status,
				LogPath:    req.LogPath,
				OutputPath: req.OutputPath,
			})
		}))
		defer server.Close()

		c := New(server.URL)
		pkg, err := c.UpdatePackage(context.Background(), "bld-123", "test-pkg", &UpdatePackageRequest{
			Status:     types.PackageStatusSuccess,
			LogPath:    "/logs/test.log",
			OutputPath: "/output/test.apk",
		})

		require.NoError(t, err)
		assert.Equal(t, types.PackageStatusSuccess, pkg.Status)
		assert.Equal(t, "/logs/test.log", pkg.LogPath)
	})

	t.Run("with error message", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req UpdatePackageRequest
			json.NewDecoder(r.Body).Decode(&req)
			assert.Equal(t, types.PackageStatusFailed, req.Status)
			assert.Equal(t, "compilation failed", req.Error)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(types.PackageJob{
				Name:   "test-pkg",
				Status: req.Status,
				Error:  req.Error,
			})
		}))
		defer server.Close()

		c := New(server.URL)
		pkg, err := c.UpdatePackage(context.Background(), "bld-123", "test-pkg", &UpdatePackageRequest{
			Status: types.PackageStatusFailed,
			Error:  "compilation failed",
		})

		require.NoError(t, err)
		assert.Equal(t, types.PackageStatusFailed, pkg.Status)
		assert.Equal(t, "compilation failed", pkg.Error)
	})

	t.Run("build not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("build not found"))
		}))
		defer server.Close()

		c := New(server.URL)
		_, err := c.UpdatePackage(context.Background(), "nonexistent", "test-pkg", &UpdatePackageRequest{
			Status: types.PackageStatusSuccess,
		})

		require.Error(t, err)
		assert.ErrorIs(t, err, svcerrors.ErrBuildNotFound)
	})

	t.Run("empty build ID", func(t *testing.T) {
		c := New("http://localhost:8080")
		_, err := c.UpdatePackage(context.Background(), "", "test-pkg", &UpdatePackageRequest{})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "build ID is required")
	})
}

func TestGetPackage(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		expectedPkg := types.PackageJob{
			Name:       "test-pkg",
			Status:     types.PackageStatusSuccess,
			ConfigYAML: "package:\n  name: test-pkg",
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/v1/builds/bld-123/packages/test-pkg", r.URL.Path)
			assert.Equal(t, http.MethodGet, r.Method)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(expectedPkg)
		}))
		defer server.Close()

		c := New(server.URL)
		pkg, err := c.GetPackage(context.Background(), "bld-123", "test-pkg")

		require.NoError(t, err)
		assert.Equal(t, "test-pkg", pkg.Name)
		assert.Equal(t, types.PackageStatusSuccess, pkg.Status)
	})

	t.Run("package not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("package not found"))
		}))
		defer server.Close()

		c := New(server.URL)
		_, err := c.GetPackage(context.Background(), "bld-123", "nonexistent")

		require.Error(t, err)
		assert.ErrorIs(t, err, svcerrors.ErrPackageNotFound)
	})
}

func TestRetryLogic(t *testing.T) {
	t.Run("retries on server error", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			if attempts < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte("service unavailable"))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(types.Build{ID: "bld-1", Status: types.BuildStatusPending})
		}))
		defer server.Close()

		c := New(server.URL, WithRetryOptions(RetryOptions{
			MaxRetries:        3,
			InitialBackoff:    1 * time.Millisecond,
			MaxBackoff:        10 * time.Millisecond,
			BackoffMultiplier: 2.0,
		}))

		build, err := c.GetBuild(context.Background(), "bld-1")

		require.NoError(t, err)
		assert.Equal(t, "bld-1", build.ID)
		assert.Equal(t, 3, attempts)
	})

	t.Run("does not retry on 400 error", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("bad request"))
		}))
		defer server.Close()

		c := New(server.URL, WithRetryOptions(RetryOptions{
			MaxRetries:        3,
			InitialBackoff:    1 * time.Millisecond,
			MaxBackoff:        10 * time.Millisecond,
			BackoffMultiplier: 2.0,
		}))

		_, err := c.GetBuild(context.Background(), "bld-1")

		require.Error(t, err)
		assert.Equal(t, 1, attempts) // Should not retry
	})

	t.Run("does not retry on 404 error", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("build not found"))
		}))
		defer server.Close()

		c := New(server.URL, WithRetryOptions(RetryOptions{
			MaxRetries:        3,
			InitialBackoff:    1 * time.Millisecond,
			MaxBackoff:        10 * time.Millisecond,
			BackoffMultiplier: 2.0,
		}))

		_, err := c.GetBuild(context.Background(), "bld-1")

		require.Error(t, err)
		assert.Equal(t, 1, attempts) // Should not retry
	})

	t.Run("respects max retries", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("server error"))
		}))
		defer server.Close()

		c := New(server.URL, WithRetryOptions(RetryOptions{
			MaxRetries:        2,
			InitialBackoff:    1 * time.Millisecond,
			MaxBackoff:        10 * time.Millisecond,
			BackoffMultiplier: 2.0,
		}))

		_, err := c.GetBuild(context.Background(), "bld-1")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "max retries exceeded")
		assert.Equal(t, 3, attempts) // Initial + 2 retries
	})

	t.Run("context cancellation stops retries", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("server error"))
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()

		c := New(server.URL, WithRetryOptions(RetryOptions{
			MaxRetries:        10,
			InitialBackoff:    50 * time.Millisecond, // Long enough to trigger timeout
			MaxBackoff:        100 * time.Millisecond,
			BackoffMultiplier: 2.0,
		}))

		_, err := c.GetBuild(ctx, "bld-1")

		require.Error(t, err)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		// Should have attempted at least once but not all retries
		assert.GreaterOrEqual(t, attempts, 1)
		assert.Less(t, attempts, 10)
	})
}

func TestClientOptions(t *testing.T) {
	t.Run("WithTimeout", func(t *testing.T) {
		c := New("http://localhost:8080", WithTimeout(5*time.Second))
		assert.Equal(t, 5*time.Second, c.httpClient.Timeout)
	})

	t.Run("WithRetryOptions", func(t *testing.T) {
		opts := RetryOptions{
			MaxRetries:        5,
			InitialBackoff:    200 * time.Millisecond,
			MaxBackoff:        10 * time.Second,
			BackoffMultiplier: 3.0,
		}
		c := New("http://localhost:8080", WithRetryOptions(opts))
		assert.Equal(t, opts, c.retryOpts)
	})

	t.Run("WithHTTPClient", func(t *testing.T) {
		customClient := &http.Client{Timeout: 60 * time.Second}
		c := New("http://localhost:8080", WithHTTPClient(customClient))
		assert.Equal(t, customClient, c.httpClient)
	})

	t.Run("normalizes base URL", func(t *testing.T) {
		c := New("http://localhost:8080/")
		assert.Equal(t, "http://localhost:8080", c.baseURL)
	})

	t.Run("DefaultRetryOptions", func(t *testing.T) {
		opts := DefaultRetryOptions()
		assert.Equal(t, 3, opts.MaxRetries)
		assert.Equal(t, 100*time.Millisecond, opts.InitialBackoff)
		assert.Equal(t, 5*time.Second, opts.MaxBackoff)
		assert.Equal(t, 2.0, opts.BackoffMultiplier)
	})
}

func TestErrorTypes(t *testing.T) {
	t.Run("NetworkError", func(t *testing.T) {
		inner := context.DeadlineExceeded
		err := &NetworkError{Err: inner}
		assert.Contains(t, err.Error(), "network error")
		assert.ErrorIs(t, err, inner)
	})

	t.Run("HTTPError", func(t *testing.T) {
		err := &HTTPError{StatusCode: 400, Message: "bad request"}
		assert.Equal(t, "HTTP 400: bad request", err.Error())
	})

	t.Run("ServerError", func(t *testing.T) {
		err := &ServerError{StatusCode: 503, Message: "service unavailable"}
		assert.Equal(t, "server error (HTTP 503): service unavailable", err.Error())
	})
}

func TestCreateBuild(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		expectedResp := types.CreateBuildResponse{
			ID:       "bld-12345",
			Packages: []string{"test-pkg"},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/v1/builds", r.URL.Path)
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			var req types.CreateBuildRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "x86_64", req.Arch)

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(expectedResp)
		}))
		defer server.Close()

		c := New(server.URL)
		resp, err := c.CreateBuild(context.Background(), &types.CreateBuildRequest{
			ConfigYAML: "package:\n  name: test-pkg\n  version: 1.0.0",
			Arch:       "x86_64",
		})

		require.NoError(t, err)
		assert.Equal(t, expectedResp.ID, resp.ID)
		assert.Equal(t, expectedResp.Packages, resp.Packages)
	})
}
