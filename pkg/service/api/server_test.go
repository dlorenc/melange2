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
	return NewServer(store.NewMemoryStore(), pool)
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
