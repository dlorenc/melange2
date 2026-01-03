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

// Command melange-orchestrator runs the standalone orchestrator for the melange service.
// This is part of Phase 4 of the microservices architecture.
//
// In the microservices deployment:
//   - melange-api: handles HTTP API requests (builds, packages)
//   - melange-orchestrator: processes builds, manages backends
//
// The orchestrator communicates with the API server via HTTP to:
//   - Poll for active builds
//   - Claim packages for execution
//   - Update package status
//
// For the monolith (backward compatibility), use melange-server instead.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/chainguard-dev/clog"
	"golang.org/x/sync/errgroup"

	"github.com/dlorenc/melange2/pkg/service/buildkit"
	"github.com/dlorenc/melange2/pkg/service/client"
	"github.com/dlorenc/melange2/pkg/service/metrics"
	"github.com/dlorenc/melange2/pkg/service/orchestrator"
	"github.com/dlorenc/melange2/pkg/service/storage"
	"github.com/dlorenc/melange2/pkg/service/tracing"
)

var (
	listenAddr     = flag.String("listen-addr", ":8081", "HTTP listen address for health/metrics")
	apiServerAddr  = flag.String("api-server", "http://melange-api:8080", "Address of the melange-api server")
	buildkitAddr   = flag.String("buildkit-addr", "", "BuildKit daemon address (for single-backend mode)")
	backendsConfig = flag.String("backends-config", "", "Path to backends config file (YAML) for multi-backend mode")
	defaultArch    = flag.String("default-arch", "x86_64", "Default architecture for single-backend mode")
	outputDir      = flag.String("output-dir", "/var/lib/melange/output", "Directory for build outputs (local storage)")
	gcsBucket      = flag.String("gcs-bucket", "", "GCS bucket for build outputs (if set, uses GCS instead of local storage)")
	maxParallel    = flag.Int("max-parallel", 0, "Maximum number of concurrent package builds (0 = use pool capacity)")
	apkoServiceAddr = flag.String("apko-service-addr", "", "gRPC address of apko service for remote layer generation")
	// Observability flags
	enableTracing   = flag.Bool("enable-tracing", false, "Enable OpenTelemetry tracing")
	otlpEndpoint    = flag.String("otlp-endpoint", "", "OTLP collector endpoint for traces")
	otlpInsecure    = flag.Bool("otlp-insecure", true, "Use insecure OTLP connection")
	traceSampleRate = flag.Float64("trace-sample-rate", 1.0, "Trace sampling rate (0.0-1.0)")
	enableMetrics   = flag.Bool("enable-metrics", true, "Enable Prometheus metrics endpoint")
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
		ServiceName:    "melange-orchestrator",
		ServiceVersion: "0.1.0",
		Enabled:        *enableTracing,
		OTLPEndpoint:   *otlpEndpoint,
		OTLPInsecure:   *otlpInsecure,
		SampleRate:     *traceSampleRate,
	})
	if err != nil {
		return fmt.Errorf("setting up tracing: %w", err)
	}
	defer func() {
		if err := shutdownTracing(context.Background()); err != nil {
			log.Errorf("error shutting down tracing: %v", err)
		}
	}()

	// Initialize metrics
	var melangeMetrics *metrics.MelangeMetrics
	if *enableMetrics {
		melangeMetrics = metrics.NewMelangeMetrics()
		log.Info("Prometheus metrics enabled")
	}

	// Create storage backend
	var storageBackend storage.Storage
	if *gcsBucket != "" {
		log.Infof("using GCS storage: gs://%s", *gcsBucket)
		gcsStorage, err := storage.NewGCSStorage(ctx, *gcsBucket)
		if err != nil {
			return fmt.Errorf("creating GCS storage: %w", err)
		}
		storageBackend = gcsStorage
	} else {
		log.Infof("using local storage: %s", *outputDir)
		if err := os.MkdirAll(*outputDir, 0755); err != nil {
			return fmt.Errorf("creating output directory: %w", err)
		}
		localStorage, err := storage.NewLocalStorage(*outputDir)
		if err != nil {
			return fmt.Errorf("creating local storage: %w", err)
		}
		storageBackend = localStorage
	}

	// Create BuildKit manager (Phase 5: Manager interface)
	var manager *buildkit.StaticManager
	switch {
	case *backendsConfig != "":
		log.Infof("using backends config: %s", *backendsConfig)
		var err error
		manager, err = buildkit.NewStaticManagerFromConfigFile(*backendsConfig)
		if err != nil {
			return fmt.Errorf("creating buildkit manager from config: %w", err)
		}
	case *buildkitAddr != "":
		log.Infof("using single buildkit backend: %s (arch: %s)", *buildkitAddr, *defaultArch)
		var err error
		manager, err = buildkit.NewStaticManagerFromSingleAddr(*buildkitAddr, *defaultArch)
		if err != nil {
			return fmt.Errorf("creating buildkit manager: %w", err)
		}
	default:
		// Try default
		log.Infof("using default buildkit backend: tcp://localhost:1234 (arch: %s)", *defaultArch)
		var err error
		manager, err = buildkit.NewStaticManagerFromSingleAddr("tcp://localhost:1234", *defaultArch)
		if err != nil {
			return fmt.Errorf("creating buildkit manager: %w", err)
		}
	}

	// Create API client
	apiClient := client.New(*apiServerAddr)

	// Get cache configuration from environment
	cacheRegistry := os.Getenv("CACHE_REGISTRY")
	cacheMode := os.Getenv("CACHE_MODE")
	if cacheRegistry != "" {
		log.Infof("using registry cache: %s (mode=%s)", cacheRegistry, cacheMode)
	}

	// Get apko registry configuration
	apkoRegistry := os.Getenv("APKO_REGISTRY")
	if apkoRegistry == "" {
		apkoRegistry = "registry:5000/apko-cache"
	}
	apkoRegistryInsecure := os.Getenv("APKO_REGISTRY_INSECURE") == "true"

	// Get poll interval
	pollInterval := time.Second
	if v := os.Getenv("POLL_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			pollInterval = d
		}
	}
	log.Infof("orchestrator poll interval: %s", pollInterval)

	// Get apko service address
	apkoService := *apkoServiceAddr
	if apkoService == "" {
		apkoService = os.Getenv("APKO_SERVICE_ADDR")
	}
	if apkoService != "" {
		log.Infof("using apko service: %s", apkoService)
	}

	// Determine max parallel jobs
	maxJobs := *maxParallel
	if maxJobs <= 0 {
		maxJobs = manager.TotalCapacity()
	}
	log.Infof("max parallel jobs: %d", maxJobs)

	// Create orchestrator configuration
	orchestratorCfg := orchestrator.Config{
		PollInterval:         pollInterval,
		MaxParallel:          maxJobs,
		CacheRegistry:        cacheRegistry,
		CacheMode:            cacheMode,
		ApkoRegistry:         apkoRegistry,
		ApkoRegistryInsecure: apkoRegistryInsecure,
		ApkoServiceAddr:      apkoService,
	}

	// Create orchestrator (using Manager interface)
	orch := orchestrator.New(apiClient, storageBackend, manager, orchestratorCfg)

	// Create health/metrics HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/api/v1/backends", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"backends":      manager.List(),
			"architectures": manager.Architectures(),
		})
	})
	mux.HandleFunc("/api/v1/backends/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		status := manager.Status()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"type":              status.Type,
			"total_workers":     status.TotalWorkers,
			"available_workers": status.AvailableWorkers,
			"active_jobs":       status.ActiveJobs,
			"workers":           status.Workers,
		})
	})
	if melangeMetrics != nil {
		mux.Handle("/metrics", melangeMetrics.Handler())
	}

	httpServer := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	// Run everything
	eg, ctx := errgroup.WithContext(ctx)

	// Run HTTP server for health/metrics
	eg.Go(func() error {
		log.Infof("orchestrator health/metrics on %s", *listenAddr)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			return fmt.Errorf("HTTP server error: %w", err)
		}
		return nil
	})

	// Run orchestrator
	eg.Go(func() error {
		log.Infof("orchestrator connecting to API server at %s", *apiServerAddr)
		return orch.Run(ctx)
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
