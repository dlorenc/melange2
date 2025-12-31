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

// Package harness provides test infrastructure for e2e tests.
package harness

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/dlorenc/melange2/pkg/service/api"
	"github.com/dlorenc/melange2/pkg/service/buildkit"
	"github.com/dlorenc/melange2/pkg/service/client"
	"github.com/dlorenc/melange2/pkg/service/scheduler"
	"github.com/dlorenc/melange2/pkg/service/storage"
	"github.com/dlorenc/melange2/pkg/service/store"
)

// TestBaseImage is the base image used for e2e tests.
const TestBaseImage = "cgr.dev/chainguard/wolfi-base"

// Harness provides shared test infrastructure for e2e tests.
type Harness struct {
	t            *testing.T
	ctx          context.Context
	cancel       context.CancelFunc
	buildKit     *BuildKitContainer
	registry     *RegistryContainer
	server       *api.Server
	httpServer   *httptest.Server
	scheduler    *scheduler.Scheduler
	buildStore   *store.MemoryBuildStore
	pool         *buildkit.Pool
	tempDir      string
	schedulerWg  sync.WaitGroup
	schedulerCtx context.Context
	schedulerCancel context.CancelFunc
}

// Options configure the test harness.
type Options struct {
	// WithServer enables the remote build server.
	WithServer bool
	// WithRegistry enables the in-cluster registry for cache.
	WithRegistry bool
	// ServerConfig overrides scheduler configuration.
	ServerConfig *scheduler.Config
}

// Option is a functional option for configuring the harness.
type Option func(*Options)

// WithServer enables the remote build server.
func WithServer() Option {
	return func(o *Options) {
		o.WithServer = true
	}
}

// WithRegistry enables the in-cluster registry.
func WithRegistry() Option {
	return func(o *Options) {
		o.WithRegistry = true
	}
}

// WithServerConfig sets custom scheduler configuration.
func WithServerConfig(cfg *scheduler.Config) Option {
	return func(o *Options) {
		o.ServerConfig = cfg
	}
}

// New creates a new test harness.
// Call Close() when done to clean up resources.
func New(t *testing.T, opts ...Option) *Harness {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	options := &Options{}
	for _, opt := range opts {
		opt(options)
	}

	ctx, cancel := context.WithCancel(context.Background())

	h := &Harness{
		t:      t,
		ctx:    ctx,
		cancel: cancel,
	}

	// Create temp directory for test artifacts
	tempDir, err := os.MkdirTemp("", "melange-e2e-*")
	if err != nil {
		cancel()
		t.Fatalf("failed to create temp dir: %v", err)
	}
	h.tempDir = tempDir

	// Start BuildKit container
	h.buildKit = StartBuildKit(t, ctx)

	// Optionally start registry
	if options.WithRegistry {
		h.registry = StartRegistry(t, ctx)
	}

	// Optionally start server
	if options.WithServer {
		h.startServer(options.ServerConfig)
	}

	t.Cleanup(func() {
		h.Close()
	})

	return h
}

// startServer starts the in-process server and scheduler.
func (h *Harness) startServer(cfg *scheduler.Config) {
	// Create build store with no eviction for tests
	h.buildStore = store.NewMemoryBuildStore(
		store.WithEvictionInterval(0), // Disable background eviction
	)

	// Create BuildKit pool
	var err error
	h.pool, err = buildkit.NewPoolFromSingleAddr(h.buildKit.Addr, "x86_64")
	if err != nil {
		h.t.Fatalf("failed to create pool: %v", err)
	}

	// Create local storage
	outputDir := h.tempDir + "/output"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		h.t.Fatalf("failed to create output dir: %v", err)
	}
	localStorage, err := storage.NewLocalStorage(outputDir)
	if err != nil {
		h.t.Fatalf("failed to create local storage: %v", err)
	}

	// Create scheduler config
	schedulerCfg := scheduler.Config{
		OutputDir:    outputDir,
		PollInterval: 100 * time.Millisecond, // Fast polling for tests
		MaxParallel:  2,
	}
	if cfg != nil {
		schedulerCfg = *cfg
		if schedulerCfg.OutputDir == "" {
			schedulerCfg.OutputDir = outputDir
		}
	}

	// Add cache registry if available
	if h.registry != nil {
		schedulerCfg.CacheRegistry = h.registry.Addr + "/melange-cache"
		schedulerCfg.CacheMode = "max"
	}

	// Create scheduler
	h.scheduler = scheduler.New(h.buildStore, localStorage, h.pool, schedulerCfg)

	// Create API server
	h.server = api.NewServer(h.buildStore, h.pool)

	// Start HTTP server
	h.httpServer = httptest.NewServer(h.server)

	// Start scheduler in background
	h.schedulerCtx, h.schedulerCancel = context.WithCancel(h.ctx)
	h.schedulerWg.Add(1)
	go func() {
		defer h.schedulerWg.Done()
		_ = h.scheduler.Run(h.schedulerCtx)
	}()
}

// BuildKitAddr returns the BuildKit address.
func (h *Harness) BuildKitAddr() string {
	return h.buildKit.Addr
}

// RegistryAddr returns the registry address, or empty if not enabled.
func (h *Harness) RegistryAddr() string {
	if h.registry == nil {
		return ""
	}
	return h.registry.Addr
}

// ServerURL returns the server URL, or empty if not enabled.
func (h *Harness) ServerURL() string {
	if h.httpServer == nil {
		return ""
	}
	return h.httpServer.URL
}

// TempDir returns the temporary directory for test artifacts.
func (h *Harness) TempDir() string {
	return h.tempDir
}

// Context returns the harness context.
func (h *Harness) Context() context.Context {
	return h.ctx
}

// Client returns an API client configured for the test server.
// Panics if server is not enabled.
func (h *Harness) Client() *client.Client {
	if h.httpServer == nil {
		h.t.Fatal("server not enabled; use WithServer() option")
	}
	return client.New(h.httpServer.URL)
}

// WaitForServerReady waits for the server to be ready.
func (h *Harness) WaitForServerReady() error {
	if h.httpServer == nil {
		return nil
	}

	c := h.Client()
	ctx, cancel := context.WithTimeout(h.ctx, 10*time.Second)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if err := c.Health(ctx); err == nil {
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// Close cleans up harness resources.
func (h *Harness) Close() {
	// Stop scheduler first
	if h.schedulerCancel != nil {
		h.schedulerCancel()
		h.schedulerWg.Wait()
	}

	// Stop HTTP server
	if h.httpServer != nil {
		h.httpServer.Close()
	}

	// Close build store
	if h.buildStore != nil {
		h.buildStore.Close()
	}

	// Clean up temp directory
	if h.tempDir != "" {
		os.RemoveAll(h.tempDir)
	}

	// Cancel context
	if h.cancel != nil {
		h.cancel()
	}
}

// GetFreePort returns a free TCP port.
func GetFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()

	return l.Addr().(*net.TCPAddr).Port, nil
}

// WaitForHTTP waits for an HTTP endpoint to respond.
func WaitForHTTP(url string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			resp, err := http.Get(url) //nolint:gosec // URL is from trusted test harness
			if err == nil {
				resp.Body.Close()
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}
