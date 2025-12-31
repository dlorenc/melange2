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

package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

func TestNewClient(t *testing.T) {
	t.Run("creates client with rate limiter", func(t *testing.T) {
		rl := rate.NewLimiter(rate.Limit(10), 1)
		client := NewClient(rl)

		require.NotNil(t, client)
		assert.NotNil(t, client.Client)
		assert.Equal(t, rl, client.Ratelimiter)
	})

	t.Run("creates client with nil rate limiter", func(t *testing.T) {
		client := NewClient(nil)

		require.NotNil(t, client)
		assert.NotNil(t, client.Client)
		assert.Nil(t, client.Ratelimiter)
	})
}

func TestRLHTTPClient_Do(t *testing.T) {
	t.Run("successful request without rate limiter", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		}))
		defer server.Close()

		client := NewClient(nil)
		req, err := http.NewRequest(http.MethodGet, server.URL, nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("successful request with rate limiter", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		// High limit so it doesn't block
		rl := rate.NewLimiter(rate.Limit(100), 10)
		client := NewClient(rl)

		req, err := http.NewRequest(http.MethodGet, server.URL, nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("rate limiter context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		// Very low limit
		rl := rate.NewLimiter(rate.Limit(0.001), 1)
		// Consume the burst
		rl.Allow()

		client := NewClient(rl)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		assert.Error(t, err)
	})

	t.Run("network error", func(t *testing.T) {
		client := NewClient(nil)

		req, err := http.NewRequest(http.MethodGet, "http://localhost:99999", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		assert.Error(t, err)
	})
}

func TestRLHTTPClient_GetArtifactSHA256(t *testing.T) {
	t.Run("successful hash", func(t *testing.T) {
		// SHA256 of "test content"
		expectedHash := "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("test content"))
		}))
		defer server.Close()

		client := NewClient(nil)
		hash, err := client.GetArtifactSHA256(context.Background(), server.URL)

		require.NoError(t, err)
		assert.Equal(t, expectedHash, hash)
	})

	t.Run("empty content", func(t *testing.T) {
		// SHA256 of empty string
		expectedHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := NewClient(nil)
		hash, err := client.GetArtifactSHA256(context.Background(), server.URL)

		require.NoError(t, err)
		assert.Equal(t, expectedHash, hash)
	})

	t.Run("404 error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		client := NewClient(nil)
		_, err := client.GetArtifactSHA256(context.Background(), server.URL)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "404")
	})

	t.Run("500 error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := NewClient(nil)
		_, err := client.GetArtifactSHA256(context.Background(), server.URL)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "500")
	})

	t.Run("invalid URL", func(t *testing.T) {
		client := NewClient(nil)
		_, err := client.GetArtifactSHA256(context.Background(), "://invalid-url")

		assert.Error(t, err)
	})

	t.Run("connection refused", func(t *testing.T) {
		client := NewClient(nil)
		_, err := client.GetArtifactSHA256(context.Background(), "http://localhost:99999/artifact")

		assert.Error(t, err)
	})
}
