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

// Command melange-server runs the melange build service.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof" //nolint:gosec // Intentionally exposing pprof for debugging
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/chainguard-dev/clog"
	"golang.org/x/sync/errgroup"

	"github.com/dlorenc/melange2/pkg/service/api"
	"github.com/dlorenc/melange2/pkg/service/buildkit"
	"github.com/dlorenc/melange2/pkg/service/scheduler"
	"github.com/dlorenc/melange2/pkg/service/storage"
	"github.com/dlorenc/melange2/pkg/service/store"
	"github.com/dlorenc/melange2/pkg/service/tracing"
)

var (
	listenAddr     = flag.String("listen-addr", ":8080", "HTTP listen address")
	buildkitAddr   = flag.String("buildkit-addr", "", "BuildKit daemon address (for single-backend mode, mutually exclusive with --backends-config)")
	backendsConfig = flag.String("backends-config", "", "Path to backends config file (YAML) for multi-backend mode")
	defaultArch    = flag.String("default-arch", "x86_64", "Default architecture for single-backend mode")
	outputDir      = flag.String("output-dir", "/var/lib/melange/output", "Directory for build outputs (local storage)")
	gcsBucket      = flag.String("gcs-bucket", "", "GCS bucket for build outputs (if set, uses GCS instead of local storage)")
	enableTracing  = flag.Bool("enable-tracing", false, "Enable OpenTelemetry tracing")
	maxParallel    = flag.Int("max-parallel", 0, "Maximum number of concurrent package builds (0 = use pool capacity)")
)

func main() {
	flag.Parse()

	// Set up logging
	logger := clog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx := clog.WithLogger(context.Background(), logger)

	// Handle signals for graceful shutdown
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)

	if err := run(ctx); err != nil {
		clog.ErrorContext(ctx, "error", "err", err)
		cancel()
		os.Exit(1)
	}
	cancel()
}

func run(ctx context.Context) error {
	log := clog.FromContext(ctx)

	// Initialize tracing
	shutdownTracing, err := tracing.Setup(ctx, tracing.Config{
		ServiceName:    "melange-server",
		ServiceVersion: "0.1.0",
		Enabled:        *enableTracing,
	})
	if err != nil {
		return fmt.Errorf("setting up tracing: %w", err)
	}
	defer func() {
		if err := shutdownTracing(context.Background()); err != nil {
			log.Errorf("error shutting down tracing: %v", err)
		}
	}()

	// Create shared components
	buildStore := store.NewMemoryBuildStore()

	// Initialize storage backend
	var storageBackend storage.Storage
	if *gcsBucket != "" {
		// Get GCS configuration from environment
		maxConcurrentUploads := 200 // Default for scale
		if v := os.Getenv("MAX_CONCURRENT_UPLOADS"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				maxConcurrentUploads = n
			}
		}
		log.Infof("using GCS storage: gs://%s (max concurrent uploads: %d)", *gcsBucket, maxConcurrentUploads)
		storageBackend, err = storage.NewGCSStorage(ctx, *gcsBucket,
			storage.WithMaxConcurrentUploads(maxConcurrentUploads))
		if err != nil {
			return fmt.Errorf("creating GCS storage: %w", err)
		}
	} else {
		log.Infof("using local storage: %s", *outputDir)
		storageBackend, err = storage.NewLocalStorage(*outputDir)
		if err != nil {
			return fmt.Errorf("creating local storage: %w", err)
		}
	}

	// Initialize BuildKit pool
	var pool *buildkit.Pool
	switch {
	case *backendsConfig != "":
		// Multi-backend mode from config file
		log.Infof("loading backends from config: %s", *backendsConfig)
		pool, err = buildkit.NewPoolFromConfig(*backendsConfig)
		if err != nil {
			return fmt.Errorf("creating buildkit pool from config: %w", err)
		}
		log.Infof("loaded %d backends for architectures: %v", len(pool.List()), pool.Architectures())
	case *buildkitAddr != "":
		// Single-backend mode (backward compatibility)
		log.Infof("using single buildkit backend: %s (arch: %s)", *buildkitAddr, *defaultArch)
		pool, err = buildkit.NewPoolFromSingleAddr(*buildkitAddr, *defaultArch)
		if err != nil {
			return fmt.Errorf("creating buildkit pool: %w", err)
		}
	default:
		// Default to localhost for development
		log.Infof("using default buildkit backend: tcp://localhost:1234 (arch: %s)", *defaultArch)
		pool, err = buildkit.NewPoolFromSingleAddr("tcp://localhost:1234", *defaultArch)
		if err != nil {
			return fmt.Errorf("creating buildkit pool: %w", err)
		}
	}

	// Create API server
	apiServer := api.NewServer(buildStore, pool)

	// Create a mux that routes /debug/pprof/ to pprof handlers and everything else to API
	mux := http.NewServeMux()
	mux.Handle("/debug/pprof/", http.DefaultServeMux) // pprof registers to DefaultServeMux
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Route non-pprof requests to API server
		if !strings.HasPrefix(r.URL.Path, "/debug/pprof/") {
			apiServer.ServeHTTP(w, r)
			return
		}
		http.DefaultServeMux.ServeHTTP(w, r)
	})

	httpServer := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	// Get cache configuration from environment
	cacheRegistry := os.Getenv("CACHE_REGISTRY")
	cacheMode := os.Getenv("CACHE_MODE")
	if cacheRegistry != "" {
		log.Infof("using registry cache: %s (mode=%s)", cacheRegistry, cacheMode)
	}

	// Get apko registry configuration from environment
	// When set, apko base images are cached in this registry for faster builds.
	// Default to "registry:5000/apko-cache" for in-cluster deployments.
	apkoRegistry := os.Getenv("APKO_REGISTRY")
	if apkoRegistry == "" {
		// Default to in-cluster registry for apko cache
		apkoRegistry = "registry:5000/apko-cache"
	}
	apkoRegistryInsecure := os.Getenv("APKO_REGISTRY_INSECURE") == "true"
	if apkoRegistry != "" {
		log.Infof("using apko registry cache: %s (insecure=%v)", apkoRegistry, apkoRegistryInsecure)
	}

	// Get scheduler poll interval from environment (default 1s, increase for large builds)
	pollInterval := time.Second
	if v := os.Getenv("POLL_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			pollInterval = d
		}
	}
	log.Infof("scheduler poll interval: %s", pollInterval)

	// Create scheduler
	sched := scheduler.New(buildStore, storageBackend, pool, scheduler.Config{
		OutputDir:            *outputDir,
		PollInterval:         pollInterval,
		MaxParallel:          *maxParallel,
		CacheRegistry:        cacheRegistry,
		CacheMode:            cacheMode,
		ApkoRegistry:         apkoRegistry,
		ApkoRegistryInsecure: apkoRegistryInsecure,
	})

	// Create output directory (for local storage)
	if *gcsBucket == "" {
		if err := os.MkdirAll(*outputDir, 0755); err != nil {
			return fmt.Errorf("creating output directory: %w", err)
		}
	}

	// Run everything
	eg, ctx := errgroup.WithContext(ctx)

	// Run HTTP server
	eg.Go(func() error {
		log.Infof("API server listening on %s", *listenAddr)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			return fmt.Errorf("HTTP server error: %w", err)
		}
		return nil
	})

	// Run scheduler
	eg.Go(func() error {
		return sched.Run(ctx)
	})

	// Handle shutdown
	eg.Go(func() error {
		<-ctx.Done()
		log.Info("shutting down...")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		return httpServer.Shutdown(shutdownCtx)
	})

	return eg.Wait()
}
