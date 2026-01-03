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

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/pkg/service/buildkit"
	"github.com/dlorenc/melange2/pkg/service/store"
)

func newTestServer(t *testing.T, backends []buildkit.Backend) *Server {
	t.Helper()
	pool, err := buildkit.NewPool(backends)
	require.NoError(t, err)
	return NewServer(store.NewMemoryBuildStore(), pool)
}

func TestListBackends(t *testing.T) {
	backends := []buildkit.Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64", Labels: map[string]string{"tier": "standard"}},
		{Addr: "tcp://arm64-1:1234", Arch: "aarch64", Labels: map[string]string{"tier": "standard"}},
	}
	server := newTestServer(t, backends)

	t.Run("list all backends", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var resp struct {
			Backends      []buildkit.Backend `json:"backends"`
			Architectures []string           `json:"architectures"`
		}
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		require.Len(t, resp.Backends, 2)
		require.Len(t, resp.Architectures, 2)
	})

	t.Run("filter by architecture", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends?arch=aarch64", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var resp struct {
			Backends      []buildkit.Backend `json:"backends"`
			Architectures []string           `json:"architectures"`
		}
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		require.Len(t, resp.Backends, 1)
		require.Equal(t, "aarch64", resp.Backends[0].Arch)
	})

	t.Run("filter by non-existent architecture", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends?arch=riscv64", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var resp struct {
			Backends      []buildkit.Backend `json:"backends"`
			Architectures []string           `json:"architectures"`
		}
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		require.Len(t, resp.Backends, 0)
	})
}

func TestAddBackend(t *testing.T) {
	backends := []buildkit.Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	}
	server := newTestServer(t, backends)

	t.Run("add valid backend", func(t *testing.T) {
		body := `{"addr": "tcp://arm64-1:1234", "arch": "aarch64", "labels": {"tier": "high-memory"}}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/backends", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusCreated, w.Code)

		var backend buildkit.Backend
		err := json.NewDecoder(w.Body).Decode(&backend)
		require.NoError(t, err)
		require.Equal(t, "tcp://arm64-1:1234", backend.Addr)
		require.Equal(t, "aarch64", backend.Arch)
		require.Equal(t, "high-memory", backend.Labels["tier"])

		// Verify it was added by listing
		listReq := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
		listW := httptest.NewRecorder()
		server.ServeHTTP(listW, listReq)

		var resp struct {
			Backends []buildkit.Backend `json:"backends"`
		}
		err = json.NewDecoder(listW.Body).Decode(&resp)
		require.NoError(t, err)
		require.Len(t, resp.Backends, 2)
	})

	t.Run("add duplicate backend", func(t *testing.T) {
		body := `{"addr": "tcp://amd64-1:1234", "arch": "x86_64"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/backends", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusConflict, w.Code)
		require.Contains(t, w.Body.String(), "already exists")
	})

	t.Run("add backend missing addr", func(t *testing.T) {
		body := `{"arch": "x86_64"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/backends", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "addr is required")
	})

	t.Run("add backend missing arch", func(t *testing.T) {
		body := `{"addr": "tcp://new:1234"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/backends", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "arch is required")
	})

	t.Run("add backend invalid json", func(t *testing.T) {
		body := `{invalid json}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/backends", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "invalid request body")
	})
}

func TestRemoveBackend(t *testing.T) {
	t.Run("remove valid backend", func(t *testing.T) {
		server := newTestServer(t, []buildkit.Backend{
			{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
			{Addr: "tcp://amd64-2:1234", Arch: "x86_64"},
		})

		body := `{"addr": "tcp://amd64-2:1234"}`
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/backends", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusNoContent, w.Code)

		// Verify it was removed by listing
		listReq := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
		listW := httptest.NewRecorder()
		server.ServeHTTP(listW, listReq)

		var resp struct {
			Backends []buildkit.Backend `json:"backends"`
		}
		err := json.NewDecoder(listW.Body).Decode(&resp)
		require.NoError(t, err)
		require.Len(t, resp.Backends, 1)
		require.Equal(t, "tcp://amd64-1:1234", resp.Backends[0].Addr)
	})

	t.Run("remove non-existent backend", func(t *testing.T) {
		server := newTestServer(t, []buildkit.Backend{
			{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
			{Addr: "tcp://amd64-2:1234", Arch: "x86_64"},
		})

		body := `{"addr": "tcp://nonexistent:1234"}`
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/backends", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusNotFound, w.Code)
		require.Contains(t, w.Body.String(), "not found")
	})

	t.Run("remove last backend", func(t *testing.T) {
		server := newTestServer(t, []buildkit.Backend{
			{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
		})

		body := `{"addr": "tcp://amd64-1:1234"}`
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/backends", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "cannot remove the last backend")
	})

	t.Run("remove backend missing addr", func(t *testing.T) {
		server := newTestServer(t, []buildkit.Backend{
			{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
		})

		body := `{}`
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/backends", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "addr is required")
	})

	t.Run("remove backend invalid json", func(t *testing.T) {
		server := newTestServer(t, []buildkit.Backend{
			{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
		})

		body := `{invalid}`
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/backends", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "invalid request body")
	})
}

func TestBackendsMethodNotAllowed(t *testing.T) {
	backends := []buildkit.Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	}
	server := newTestServer(t, backends)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/backends", nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHealthEndpoint(t *testing.T) {
	backends := []buildkit.Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	}
	server := newTestServer(t, backends)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	require.Equal(t, "ok", resp["status"])
}

// Build API tests

func TestCreateBuild(t *testing.T) {
	backends := []buildkit.Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	}
	server := newTestServer(t, backends)

	t.Run("create build with multiple configs", func(t *testing.T) {
		body := `{
			"configs": [
				"package:\n  name: pkg-a\n  version: 1.0.0\n",
				"package:\n  name: pkg-b\n  version: 1.0.0\nenvironment:\n  contents:\n    packages:\n      - pkg-a\n"
			],
			"arch": "x86_64"
		}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/builds", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusCreated, w.Code)

		var resp map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		require.NotEmpty(t, resp["id"])
		require.Contains(t, resp["id"], "bld-")

		packages := resp["packages"].([]interface{})
		require.Len(t, packages, 2)
		// pkg-a should come before pkg-b due to dependency ordering
		require.Equal(t, "pkg-a", packages[0])
		require.Equal(t, "pkg-b", packages[1])
	})

	t.Run("create build with single config_yaml", func(t *testing.T) {
		body := `{
			"config_yaml": "package:\n  name: single-pkg\n  version: 1.0.0\n"
		}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/builds", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusCreated, w.Code)

		var resp map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		require.Contains(t, resp["id"], "bld-")
		packages := resp["packages"].([]interface{})
		require.Len(t, packages, 1)
		require.Equal(t, "single-pkg", packages[0])
	})

	t.Run("create build missing config", func(t *testing.T) {
		body := `{"arch": "x86_64"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/builds", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "config_yaml, configs, or git_source is required")
	})

	t.Run("create build empty configs", func(t *testing.T) {
		body := `{"configs": []}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/builds", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		// Empty configs array is treated as missing config
		require.Contains(t, w.Body.String(), "config_yaml, configs, or git_source is required")
	})

	t.Run("create build invalid config yaml", func(t *testing.T) {
		body := `{"configs": ["invalid: yaml: content:"]}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/builds", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "failed to parse configs")
	})

	t.Run("create build config missing package name", func(t *testing.T) {
		body := `{"configs": ["version: 1.0.0\n"]}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/builds", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "config missing package name")
	})

	t.Run("create build invalid json", func(t *testing.T) {
		body := `{invalid}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/builds", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "invalid request body")
	})

	t.Run("create build with cyclic dependency in dag mode", func(t *testing.T) {
		// Cyclic dependencies are only rejected in DAG mode (flat mode ignores dependencies)
		body := `{
			"mode": "dag",
			"configs": [
				"package:\n  name: pkg-a\n  version: 1.0.0\nenvironment:\n  contents:\n    packages:\n      - pkg-b\n",
				"package:\n  name: pkg-b\n  version: 1.0.0\nenvironment:\n  contents:\n    packages:\n      - pkg-a\n"
			]
		}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/builds", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "dependency error")
	})

	t.Run("create build with cyclic dependency in flat mode succeeds", func(t *testing.T) {
		// Flat mode ignores dependencies, so cyclic deps are allowed
		body := `{
			"mode": "flat",
			"configs": [
				"package:\n  name: pkg-c\n  version: 1.0.0\nenvironment:\n  contents:\n    packages:\n      - pkg-d\n",
				"package:\n  name: pkg-d\n  version: 1.0.0\nenvironment:\n  contents:\n    packages:\n      - pkg-c\n"
			]
		}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/builds", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusCreated, w.Code)
	})
}

func TestListBuilds(t *testing.T) {
	backends := []buildkit.Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	}
	server := newTestServer(t, backends)

	t.Run("empty list", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/builds", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var builds []interface{}
		err := json.NewDecoder(w.Body).Decode(&builds)
		require.NoError(t, err)
		require.Empty(t, builds)
	})

	t.Run("list with builds", func(t *testing.T) {
		// Create some builds first
		for i := 0; i < 2; i++ {
			body := `{"configs": ["package:\n  name: test\n  version: 1.0.0\n"]}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/builds", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			server.ServeHTTP(w, req)
			require.Equal(t, http.StatusCreated, w.Code)
		}

		// List builds
		req := httptest.NewRequest(http.MethodGet, "/api/v1/builds", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var builds []interface{}
		err := json.NewDecoder(w.Body).Decode(&builds)
		require.NoError(t, err)
		require.Len(t, builds, 2)
	})
}

func TestGetBuild(t *testing.T) {
	backends := []buildkit.Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	}
	server := newTestServer(t, backends)

	// Create a build first
	body := `{"configs": ["package:\n  name: test-pkg\n  version: 1.0.0\n"]}`
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/builds", bytes.NewBufferString(body))
	createReq.Header.Set("Content-Type", "application/json")
	createW := httptest.NewRecorder()
	server.ServeHTTP(createW, createReq)
	require.Equal(t, http.StatusCreated, createW.Code)

	var createResp map[string]interface{}
	json.NewDecoder(createW.Body).Decode(&createResp)
	buildID := createResp["id"].(string)

	t.Run("get existing build", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/builds/"+buildID, nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var build map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&build)
		require.NoError(t, err)
		require.Equal(t, buildID, build["id"])
		require.Equal(t, "pending", build["status"])
		require.NotNil(t, build["packages"])
	})

	t.Run("get non-existent build", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/builds/non-existent", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("get build with empty id", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/builds/", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "build ID required")
	})

	t.Run("method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/builds/"+buildID, nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestBuildsMethodNotAllowed(t *testing.T) {
	backends := []buildkit.Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	}
	server := newTestServer(t, backends)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/builds", nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// Helper function tests

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		ms       int64
		expected string
	}{
		{
			name:     "zero returns empty",
			ms:       0,
			expected: "",
		},
		{
			name:     "one second",
			ms:       1000,
			expected: "1s",
		},
		{
			name:     "one minute",
			ms:       60000,
			expected: "1m0s",
		},
		{
			name:     "one hour",
			ms:       3600000,
			expected: "1h0m0s",
		},
		{
			name:     "mixed duration",
			ms:       3661000,
			expected: "1h1m1s",
		},
		{
			name:     "milliseconds only",
			ms:       500,
			expected: "500ms",
		},
		{
			name:     "negative value",
			ms:       -1000,
			expected: "-1s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatDuration(tt.ms)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestAverage(t *testing.T) {
	tests := []struct {
		name     string
		values   []int64
		expected int64
	}{
		{
			name:     "empty slice",
			values:   []int64{},
			expected: 0,
		},
		{
			name:     "nil slice",
			values:   nil,
			expected: 0,
		},
		{
			name:     "single value",
			values:   []int64{100},
			expected: 100,
		},
		{
			name:     "multiple values",
			values:   []int64{10, 20, 30},
			expected: 20,
		},
		{
			name:     "integer division",
			values:   []int64{10, 20, 25},
			expected: 18, // (10+20+25)/3 = 55/3 = 18 (integer division)
		},
		{
			name:     "large values",
			values:   []int64{1000000, 2000000, 3000000},
			expected: 2000000,
		},
		{
			name:     "values with zero",
			values:   []int64{0, 100, 200},
			expected: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := average(tt.values)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestPercentile(t *testing.T) {
	tests := []struct {
		name     string
		values   []int64
		p        int
		expected int64
	}{
		{
			name:     "empty slice",
			values:   []int64{},
			p:        50,
			expected: 0,
		},
		{
			name:     "nil slice",
			values:   nil,
			p:        50,
			expected: 0,
		},
		{
			name:     "single value",
			values:   []int64{100},
			p:        50,
			expected: 100,
		},
		{
			name:     "50th percentile (median) odd",
			values:   []int64{10, 20, 30, 40, 50},
			p:        50,
			expected: 30, // index = (50*5)/100 = 2
		},
		{
			name:     "50th percentile (median) even",
			values:   []int64{10, 20, 30, 40},
			p:        50,
			expected: 30, // index = (50*4)/100 = 2
		},
		{
			name:     "90th percentile",
			values:   []int64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
			p:        90,
			expected: 100, // index = (90*10)/100 = 9
		},
		{
			name:     "95th percentile",
			values:   []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
			p:        95,
			expected: 20, // index = (95*20)/100 = 19
		},
		{
			name:     "0th percentile",
			values:   []int64{10, 20, 30},
			p:        0,
			expected: 10, // index = 0
		},
		{
			name:     "100th percentile",
			values:   []int64{10, 20, 30},
			p:        100,
			expected: 30, // index = min(3, 2) = 2
		},
		{
			name:     "unsorted input",
			values:   []int64{50, 10, 40, 20, 30},
			p:        50,
			expected: 30, // should sort first
		},
		{
			name:     "duplicate values",
			values:   []int64{10, 10, 10, 10, 10},
			p:        90,
			expected: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy to ensure original isn't modified (only for non-nil slices)
			var valuesCopy []int64
			if tt.values != nil {
				valuesCopy = make([]int64, len(tt.values))
				copy(valuesCopy, tt.values)
			}

			result := percentile(tt.values, tt.p)
			require.Equal(t, tt.expected, result)

			// Verify original slice wasn't modified
			if tt.values != nil {
				require.Equal(t, valuesCopy, tt.values)
			}
		})
	}
}

// Phase 1 API tests for microservices architecture

func TestListActiveBuilds(t *testing.T) {
	backends := []buildkit.Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	}
	server := newTestServer(t, backends)

	t.Run("empty when no builds", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/builds/active", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var builds []interface{}
		err := json.NewDecoder(w.Body).Decode(&builds)
		require.NoError(t, err)
		require.Empty(t, builds)
	})

	t.Run("returns active builds", func(t *testing.T) {
		// Create a build
		body := `{"configs": ["package:\n  name: active-pkg\n  version: 1.0.0\n"]}`
		createReq := httptest.NewRequest(http.MethodPost, "/api/v1/builds", bytes.NewBufferString(body))
		createReq.Header.Set("Content-Type", "application/json")
		createW := httptest.NewRecorder()
		server.ServeHTTP(createW, createReq)
		require.Equal(t, http.StatusCreated, createW.Code)

		// List active builds
		req := httptest.NewRequest(http.MethodGet, "/api/v1/builds/active", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var builds []map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&builds)
		require.NoError(t, err)
		require.Len(t, builds, 1)
		require.Equal(t, "pending", builds[0]["status"])
	})

	t.Run("method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/builds/active", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestClaimPackage(t *testing.T) {
	backends := []buildkit.Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	}
	server := newTestServer(t, backends)

	// Create a build with two packages
	body := `{
		"configs": [
			"package:\n  name: pkg-a\n  version: 1.0.0\n",
			"package:\n  name: pkg-b\n  version: 1.0.0\nenvironment:\n  contents:\n    packages:\n      - pkg-a\n"
		],
		"mode": "dag"
	}`
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/builds", bytes.NewBufferString(body))
	createReq.Header.Set("Content-Type", "application/json")
	createW := httptest.NewRecorder()
	server.ServeHTTP(createW, createReq)
	require.Equal(t, http.StatusCreated, createW.Code)

	var createResp map[string]interface{}
	json.NewDecoder(createW.Body).Decode(&createResp)
	buildID := createResp["id"].(string)

	t.Run("claim ready package", func(t *testing.T) {
		// pkg-a should be claimable since it has no dependencies
		req := httptest.NewRequest(http.MethodPost, "/api/v1/builds/"+buildID+"/packages/pkg-a/claim", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var pkg map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&pkg)
		require.NoError(t, err)
		require.Equal(t, "pkg-a", pkg["name"])
		require.Equal(t, "running", pkg["status"])
		require.NotNil(t, pkg["started_at"])
	})

	t.Run("claim package with unsatisfied dependencies", func(t *testing.T) {
		// pkg-b depends on pkg-a which is still running (not success)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/builds/"+buildID+"/packages/pkg-b/claim", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusConflict, w.Code)
		require.Contains(t, w.Body.String(), "not ready")
	})

	t.Run("claim already claimed package", func(t *testing.T) {
		// pkg-a was already claimed
		req := httptest.NewRequest(http.MethodPost, "/api/v1/builds/"+buildID+"/packages/pkg-a/claim", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusConflict, w.Code)
		require.Contains(t, w.Body.String(), "already claimed")
	})

	t.Run("claim non-existent package", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/builds/"+buildID+"/packages/non-existent/claim", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusNotFound, w.Code)
		require.Contains(t, w.Body.String(), "package not found")
	})

	t.Run("claim from non-existent build", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/builds/non-existent/packages/pkg-a/claim", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusNotFound, w.Code)
		require.Contains(t, w.Body.String(), "build not found")
	})

	t.Run("method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/builds/"+buildID+"/packages/pkg-a/claim", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestUpdatePackage(t *testing.T) {
	backends := []buildkit.Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	}
	server := newTestServer(t, backends)

	// Create a build and claim a package
	body := `{"configs": ["package:\n  name: test-pkg\n  version: 1.0.0\n"]}`
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/builds", bytes.NewBufferString(body))
	createReq.Header.Set("Content-Type", "application/json")
	createW := httptest.NewRecorder()
	server.ServeHTTP(createW, createReq)
	require.Equal(t, http.StatusCreated, createW.Code)

	var createResp map[string]interface{}
	json.NewDecoder(createW.Body).Decode(&createResp)
	buildID := createResp["id"].(string)

	// Claim the package
	claimReq := httptest.NewRequest(http.MethodPost, "/api/v1/builds/"+buildID+"/packages/test-pkg/claim", nil)
	claimW := httptest.NewRecorder()
	server.ServeHTTP(claimW, claimReq)
	require.Equal(t, http.StatusOK, claimW.Code)

	t.Run("update package to success", func(t *testing.T) {
		updateBody := `{"status": "success", "output_path": "/output/test-pkg"}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/builds/"+buildID+"/packages/test-pkg", bytes.NewBufferString(updateBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var pkg map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&pkg)
		require.NoError(t, err)
		require.Equal(t, "test-pkg", pkg["name"])
		require.Equal(t, "success", pkg["status"])
		require.Equal(t, "/output/test-pkg", pkg["output_path"])
		require.NotNil(t, pkg["finished_at"])
	})

	t.Run("update non-existent package", func(t *testing.T) {
		updateBody := `{"status": "success"}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/builds/"+buildID+"/packages/non-existent", bytes.NewBufferString(updateBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("update with invalid json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/builds/"+buildID+"/packages/test-pkg", bytes.NewBufferString("{invalid}"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "invalid request body")
	})
}

func TestGetPackage(t *testing.T) {
	backends := []buildkit.Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	}
	server := newTestServer(t, backends)

	// Create a build
	body := `{"configs": ["package:\n  name: test-pkg\n  version: 1.0.0\n"]}`
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/builds", bytes.NewBufferString(body))
	createReq.Header.Set("Content-Type", "application/json")
	createW := httptest.NewRecorder()
	server.ServeHTTP(createW, createReq)
	require.Equal(t, http.StatusCreated, createW.Code)

	var createResp map[string]interface{}
	json.NewDecoder(createW.Body).Decode(&createResp)
	buildID := createResp["id"].(string)

	t.Run("get existing package", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/builds/"+buildID+"/packages/test-pkg", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var pkg map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&pkg)
		require.NoError(t, err)
		require.Equal(t, "test-pkg", pkg["name"])
		require.Equal(t, "pending", pkg["status"])
	})

	t.Run("get non-existent package", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/builds/"+buildID+"/packages/non-existent", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusNotFound, w.Code)
		require.Contains(t, w.Body.String(), "package not found")
	})

	t.Run("get package from non-existent build", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/builds/non-existent/packages/test-pkg", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestPackageClaimWithDependencies(t *testing.T) {
	backends := []buildkit.Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	}
	server := newTestServer(t, backends)

	// Create a build with dependencies: pkg-a -> pkg-b -> pkg-c
	body := `{
		"configs": [
			"package:\n  name: pkg-a\n  version: 1.0.0\n",
			"package:\n  name: pkg-b\n  version: 1.0.0\nenvironment:\n  contents:\n    packages:\n      - pkg-a\n",
			"package:\n  name: pkg-c\n  version: 1.0.0\nenvironment:\n  contents:\n    packages:\n      - pkg-b\n"
		],
		"mode": "dag"
	}`
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/builds", bytes.NewBufferString(body))
	createReq.Header.Set("Content-Type", "application/json")
	createW := httptest.NewRecorder()
	server.ServeHTTP(createW, createReq)
	require.Equal(t, http.StatusCreated, createW.Code)

	var createResp map[string]interface{}
	json.NewDecoder(createW.Body).Decode(&createResp)
	buildID := createResp["id"].(string)

	// 1. Claim pkg-a (no dependencies)
	claimA := httptest.NewRequest(http.MethodPost, "/api/v1/builds/"+buildID+"/packages/pkg-a/claim", nil)
	claimAW := httptest.NewRecorder()
	server.ServeHTTP(claimAW, claimA)
	require.Equal(t, http.StatusOK, claimAW.Code)

	// 2. Try to claim pkg-b (should fail - pkg-a still running)
	claimB := httptest.NewRequest(http.MethodPost, "/api/v1/builds/"+buildID+"/packages/pkg-b/claim", nil)
	claimBW := httptest.NewRecorder()
	server.ServeHTTP(claimBW, claimB)
	require.Equal(t, http.StatusConflict, claimBW.Code)

	// 3. Mark pkg-a as success
	updateA := httptest.NewRequest(http.MethodPut, "/api/v1/builds/"+buildID+"/packages/pkg-a",
		bytes.NewBufferString(`{"status": "success"}`))
	updateAW := httptest.NewRecorder()
	server.ServeHTTP(updateAW, updateA)
	require.Equal(t, http.StatusOK, updateAW.Code)

	// 4. Now pkg-b should be claimable
	claimB2 := httptest.NewRequest(http.MethodPost, "/api/v1/builds/"+buildID+"/packages/pkg-b/claim", nil)
	claimB2W := httptest.NewRecorder()
	server.ServeHTTP(claimB2W, claimB2)
	require.Equal(t, http.StatusOK, claimB2W.Code)

	// 5. pkg-c still shouldn't be claimable (pkg-b running)
	claimC := httptest.NewRequest(http.MethodPost, "/api/v1/builds/"+buildID+"/packages/pkg-c/claim", nil)
	claimCW := httptest.NewRecorder()
	server.ServeHTTP(claimCW, claimC)
	require.Equal(t, http.StatusConflict, claimCW.Code)

	// 6. Mark pkg-b as success
	updateB := httptest.NewRequest(http.MethodPut, "/api/v1/builds/"+buildID+"/packages/pkg-b",
		bytes.NewBufferString(`{"status": "success"}`))
	updateBW := httptest.NewRecorder()
	server.ServeHTTP(updateBW, updateB)
	require.Equal(t, http.StatusOK, updateBW.Code)

	// 7. Now pkg-c should be claimable
	claimC2 := httptest.NewRequest(http.MethodPost, "/api/v1/builds/"+buildID+"/packages/pkg-c/claim", nil)
	claimC2W := httptest.NewRecorder()
	server.ServeHTTP(claimC2W, claimC2)
	require.Equal(t, http.StatusOK, claimC2W.Code)
}
