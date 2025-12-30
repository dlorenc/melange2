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
	return NewServer(store.NewMemoryStore(), store.NewMemoryBuildStore(), pool)
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

// Job API tests

func TestCreateJob(t *testing.T) {
	backends := []buildkit.Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	}
	server := newTestServer(t, backends)

	t.Run("create valid job", func(t *testing.T) {
		body := `{
			"config_yaml": "package:\n  name: test-pkg\n  version: 1.0.0\n",
			"arch": "x86_64",
			"with_test": true
		}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusCreated, w.Code)

		var resp map[string]string
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		require.NotEmpty(t, resp["id"])
	})

	t.Run("create job with pipelines", func(t *testing.T) {
		body := `{
			"config_yaml": "package:\n  name: test-pkg\n  version: 1.0.0\n",
			"pipelines": {
				"autoconf/configure.yaml": "name: Configure\npipeline:\n  - runs: ./configure"
			}
		}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("create job missing config", func(t *testing.T) {
		body := `{"arch": "x86_64"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "config_yaml is required")
	})

	t.Run("create job invalid json", func(t *testing.T) {
		body := `{invalid}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "invalid request body")
	})
}

func TestListJobs(t *testing.T) {
	backends := []buildkit.Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	}
	server := newTestServer(t, backends)

	t.Run("empty list", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var jobs []interface{}
		err := json.NewDecoder(w.Body).Decode(&jobs)
		require.NoError(t, err)
		require.Empty(t, jobs)
	})

	t.Run("list with jobs", func(t *testing.T) {
		// Create some jobs first
		for i := 0; i < 3; i++ {
			body := `{"config_yaml": "package:\n  name: test\n  version: 1.0.0\n"}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			server.ServeHTTP(w, req)
			require.Equal(t, http.StatusCreated, w.Code)
		}

		// List jobs
		req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var jobs []interface{}
		err := json.NewDecoder(w.Body).Decode(&jobs)
		require.NoError(t, err)
		require.Len(t, jobs, 3)
	})
}

func TestGetJob(t *testing.T) {
	backends := []buildkit.Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	}
	server := newTestServer(t, backends)

	// Create a job first
	body := `{"config_yaml": "package:\n  name: test-pkg\n  version: 1.0.0\n"}`
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewBufferString(body))
	createReq.Header.Set("Content-Type", "application/json")
	createW := httptest.NewRecorder()
	server.ServeHTTP(createW, createReq)
	require.Equal(t, http.StatusCreated, createW.Code)

	var createResp map[string]string
	json.NewDecoder(createW.Body).Decode(&createResp)
	jobID := createResp["id"]

	t.Run("get existing job", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+jobID, nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var job map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&job)
		require.NoError(t, err)
		require.Equal(t, jobID, job["id"])
		require.Equal(t, "pending", job["status"])
	})

	t.Run("get non-existent job", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/non-existent", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("get job with empty id", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/", nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "job ID required")
	})

	t.Run("method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+jobID, nil)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestJobsMethodNotAllowed(t *testing.T) {
	backends := []buildkit.Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	}
	server := newTestServer(t, backends)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/jobs", nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
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

	t.Run("create build via jobs endpoint with configs", func(t *testing.T) {
		body := `{
			"configs": [
				"package:\n  name: lib-a\n  version: 1.0.0\n"
			]
		}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusCreated, w.Code)

		var resp map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		require.Contains(t, resp["id"], "bld-")
	})

	t.Run("create build missing configs", func(t *testing.T) {
		body := `{"arch": "x86_64"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/builds", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "either configs or git_source is required")
	})

	t.Run("create build empty configs", func(t *testing.T) {
		body := `{"configs": []}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/builds", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code)
		// Empty configs array is treated as missing configs
		require.Contains(t, w.Body.String(), "either configs or git_source is required")
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

	t.Run("create build with cyclic dependency", func(t *testing.T) {
		body := `{
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
