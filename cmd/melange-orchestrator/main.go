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
// This is part of Phase 4/6/7 of the microservices architecture.
//
// In the microservices deployment:
//   - melange-api: handles HTTP API requests (builds, packages)
//   - melange-orchestrator: processes builds, coordinates with managers
//   - melange-buildkit-manager: manages BuildKit workers (Phase 6)
//   - melange-apko-manager: manages apko instances (Phase 7)
//
// The orchestrator communicates with the API server via HTTP to:
//   - Poll for active builds
//   - Claim packages for execution
//   - Update package status
//
// The orchestrator can connect to BuildKit workers either:
//   - Directly via --buildkit-addr or --backends-config (embedded mode)
//   - Via gRPC to melange-buildkit-manager (microservices mode, Phase 6)
//
// The orchestrator can connect to apko instances either:
//   - Directly via --apko-service-addr (direct mode)
//   - Via gRPC to melange-apko-manager (microservices mode, Phase 7)
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

	"github.com/dlorenc/melange2/pkg/service/apko"
	"github.com/dlorenc/melange2/pkg/service/buildkit"
	"github.com/dlorenc/melange2/pkg/service/client"
	"github.com/dlorenc/melange2/pkg/service/metrics"
	"github.com/dlorenc/melange2/pkg/service/orchestrator"
	"github.com/dlorenc/melange2/pkg/service/storage"
	"github.com/dlorenc/melange2/pkg/service/tracing"
)

var (
	listenAddr          = flag.String("listen-addr", ":8081", "HTTP listen address for health/metrics")
	apiServerAddr       = flag.String("api-server", "http://melange-api:8080", "Address of the melange-api server")
	buildkitManagerAddr = flag.String("buildkit-manager-addr", "", "gRPC address of BuildKit Manager service (Phase 6 microservices mode)")
	buildkitAddr        = flag.String("buildkit-addr", "", "BuildKit daemon address (for single-backend embedded mode)")
	backendsConfig      = flag.String("backends-config", "", "Path to backends config file (YAML) for multi-backend embedded mode")
	defaultArch         = flag.String("default-arch", "x86_64", "Default architecture for single-backend mode")
	outputDir           = flag.String("output-dir", "/var/lib/melange/output", "Directory for build outputs (local storage)")
	gcsBucket           = flag.String("gcs-bucket", "", "GCS bucket for build outputs (if set, uses GCS instead of local storage)")
	maxParallel         = flag.Int("max-parallel", 0, "Maximum number of concurrent package builds (0 = use pool capacity)")
	apkoServiceAddr     = flag.String("apko-service-addr", "", "gRPC address of apko service for remote layer generation (direct mode)")
	apkoManagerAddr     = flag.String("apko-manager-addr", "", "gRPC address of Apko Manager service (Phase 7 microservices mode)")
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

	// Create BuildKit manager (Phase 5/6: Manager interface)
	// Priority: buildkit-manager-addr (gRPC) > backends-config > buildkit-addr > default
	// Also check BUILDKIT_MANAGER_ADDR env var for Kubernetes deployments
	buildkitMgrAddr := *buildkitManagerAddr
	if buildkitMgrAddr == "" {
		buildkitMgrAddr = os.Getenv("BUILDKIT_MANAGER_ADDR")
	}

	var manager buildkit.Manager
	switch {
	case buildkitMgrAddr != "":
		// Phase 6: Connect to remote BuildKit Manager service via gRPC
		log.Infof("using BuildKit Manager service at %s", buildkitMgrAddr)
		grpcClient, err := buildkit.NewGRPCClient(ctx, buildkit.DefaultGRPCClientConfig(buildkitMgrAddr))
		if err != nil {
			return fmt.Errorf("creating buildkit manager gRPC client: %w", err)
		}
		defer grpcClient.Close()
		manager = grpcClient
	case *backendsConfig != "":
		log.Infof("using backends config: %s", *backendsConfig)
		staticManager, err := buildkit.NewStaticManagerFromConfigFile(*backendsConfig)
		if err != nil {
			return fmt.Errorf("creating buildkit manager from config: %w", err)
		}
		manager = staticManager
	case *buildkitAddr != "":
		log.Infof("using single buildkit backend: %s (arch: %s)", *buildkitAddr, *defaultArch)
		staticManager, err := buildkit.NewStaticManagerFromSingleAddr(*buildkitAddr, *defaultArch)
		if err != nil {
			return fmt.Errorf("creating buildkit manager: %w", err)
		}
		manager = staticManager
	default:
		// Try default
		log.Infof("using default buildkit backend: tcp://localhost:1234 (arch: %s)", *defaultArch)
		staticManager, err := buildkit.NewStaticManagerFromSingleAddr("tcp://localhost:1234", *defaultArch)
		if err != nil {
			return fmt.Errorf("creating buildkit manager: %w", err)
		}
		manager = staticManager
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

	// Get apko service configuration
	// Priority: apko-manager-addr (gRPC to manager) > apko-service-addr (direct to apko-server)
	apkoMgrAddr := *apkoManagerAddr
	if apkoMgrAddr == "" {
		apkoMgrAddr = os.Getenv("APKO_MANAGER_ADDR")
	}

	apkoService := *apkoServiceAddr
	if apkoService == "" {
		apkoService = os.Getenv("APKO_SERVICE_ADDR")
	}

	var apkoManager apko.Manager
	switch {
	case apkoMgrAddr != "":
		// Phase 7: Connect to remote Apko Manager service via gRPC
		log.Infof("using Apko Manager service at %s", apkoMgrAddr)
		apkoClient, err := apko.NewManagerGRPCClient(ctx, apko.DefaultManagerGRPCClientConfig(apkoMgrAddr))
		if err != nil {
			return fmt.Errorf("creating apko manager gRPC client: %w", err)
		}
		defer apkoClient.Close()
		apkoManager = apkoClient
	case apkoService != "":
		log.Infof("using direct apko service: %s", apkoService)
	default:
		log.Info("no apko service configured, using embedded apko")
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
	var orchestratorOpts []orchestrator.OrchestratorOption
	if apkoManager != nil {
		orchestratorOpts = append(orchestratorOpts, orchestrator.WithApkoManager(apkoManager))
	}
	orch := orchestrator.New(apiClient, storageBackend, manager, orchestratorCfg, orchestratorOpts...)

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
		// Use Status() which is available on all Manager implementations
		status := manager.Status()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"total_workers":     status.TotalWorkers,
			"available_workers": status.AvailableWorkers,
			"architectures":     manager.Architectures(),
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
	// Apko manager status endpoint (Phase 7)
	mux.HandleFunc("/api/v1/apko/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if apkoManager == nil {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"type":    "none",
				"message": "apko manager not configured",
			})
			return
		}
		status := apkoManager.Status()
		_ = json.NewEncoder(w).Encode(status)
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
