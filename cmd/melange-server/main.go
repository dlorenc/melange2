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
	"encoding/json"
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

	apkobuild "chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/apk/expandapk"
	"github.com/chainguard-dev/clog"
	"golang.org/x/sync/errgroup"

	"github.com/dlorenc/melange2/pkg/service/api"
	"github.com/dlorenc/melange2/pkg/service/buildkit"
	"github.com/dlorenc/melange2/pkg/service/metrics"
	"github.com/dlorenc/melange2/pkg/service/scheduler"
	"github.com/dlorenc/melange2/pkg/service/storage"
	"github.com/dlorenc/melange2/pkg/service/store"
	"github.com/dlorenc/melange2/pkg/service/tracing"
)

var (
	listenAddr      = flag.String("listen-addr", ":8080", "HTTP listen address")
	buildkitAddr    = flag.String("buildkit-addr", "", "BuildKit daemon address (for single-backend mode, mutually exclusive with --backends-config)")
	backendsConfig  = flag.String("backends-config", "", "Path to backends config file (YAML) for multi-backend mode")
	defaultArch     = flag.String("default-arch", "x86_64", "Default architecture for single-backend mode")
	outputDir       = flag.String("output-dir", "/var/lib/melange/output", "Directory for build outputs (local storage)")
	gcsBucket       = flag.String("gcs-bucket", "", "GCS bucket for build outputs (if set, uses GCS instead of local storage)")
	enableTracing   = flag.Bool("enable-tracing", false, "Enable OpenTelemetry tracing")
	maxParallel     = flag.Int("max-parallel", 0, "Maximum number of concurrent package builds (0 = use pool capacity)")
	apkoServiceAddr = flag.String("apko-service-addr", "", "gRPC address of apko service for remote layer generation (e.g., apko-server:9090)")
	// Observability flags
	otlpEndpoint    = flag.String("otlp-endpoint", "", "OTLP collector endpoint for traces (e.g., tempo:4317)")
	otlpInsecure    = flag.Bool("otlp-insecure", true, "Use insecure OTLP connection (no TLS)")
	traceSampleRate = flag.Float64("trace-sample-rate", 1.0, "Trace sampling rate (0.0-1.0)")
	enableMetrics   = flag.Bool("enable-metrics", true, "Enable Prometheus metrics endpoint")
	// PostgreSQL flags
	postgresDSN     = flag.String("postgres-dsn", "", "PostgreSQL connection string (if set, uses PostgreSQL instead of in-memory store)")
	postgresMaxConn = flag.Int("postgres-max-conn", 25, "Maximum PostgreSQL connections")
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

	// Configure apko pools for server mode (bounded memory, optimized for concurrent builds)
	apkobuild.ConfigurePoolsForService()
	log.Info("configured apko pools for service mode")

	// Create build store (PostgreSQL or in-memory)
	// Check environment variable if flag not set
	pgDSN := *postgresDSN
	if pgDSN == "" {
		pgDSN = os.Getenv("POSTGRES_DSN")
	}

	var buildStore store.BuildStore
	if pgDSN != "" {
		log.Infof("using PostgreSQL store")

		// Run migrations
		if err := store.RunMigrations(pgDSN); err != nil {
			return fmt.Errorf("running PostgreSQL migrations: %w", err)
		}

		pgStore, err := store.NewPostgresBuildStore(ctx, pgDSN,
			store.WithPostgresMaxConns(int32(*postgresMaxConn)),
		)
		if err != nil {
			return fmt.Errorf("creating PostgreSQL store: %w", err)
		}
		defer pgStore.Close()
		buildStore = pgStore
		log.Info("PostgreSQL store initialized")
	} else {
		log.Info("using in-memory store")
		buildStore = store.NewMemoryBuildStore()
	}

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
	mux.HandleFunc("/debug/apko/stats", handleApkoStats)
	// Add /metrics endpoint for Prometheus
	if melangeMetrics != nil {
		mux.Handle("/metrics", melangeMetrics.Handler())
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Route non-pprof requests to API server
		if !strings.HasPrefix(r.URL.Path, "/debug/pprof/") && !strings.HasPrefix(r.URL.Path, "/debug/apko/") && r.URL.Path != "/metrics" {
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

	// Get APK cache configuration from environment
	// APK_CACHE_DIR: Directory for persistent APK package cache
	// APK_CACHE_TTL: How long to keep cached APK files (default 1h)
	apkCacheDir := os.Getenv("APK_CACHE_DIR")
	var apkCacheTTL time.Duration
	if v := os.Getenv("APK_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			apkCacheTTL = d
		}
	}
	if apkCacheDir != "" {
		if apkCacheTTL == 0 {
			apkCacheTTL = time.Hour
		}
		log.Infof("using APK cache: dir=%s ttl=%s", apkCacheDir, apkCacheTTL)
		// Create the cache directory
		if err := os.MkdirAll(apkCacheDir, 0755); err != nil {
			return fmt.Errorf("creating APK cache directory: %w", err)
		}
	}

	// Get apko service configuration from flag or environment
	// When set, apko layer generation is delegated to the remote apko service
	apkoService := *apkoServiceAddr
	if apkoService == "" {
		apkoService = os.Getenv("APKO_SERVICE_ADDR")
	}
	if apkoService != "" {
		log.Infof("using apko service: %s", apkoService)
	}

	// Load server-side secret environment variables from SECRET_ENV_* environment variables.
	// These can be populated from Kubernetes secrets and are injected into all builds.
	// Example: SECRET_ENV_GITHUB_TOKEN=ghp_xxx becomes GITHUB_TOKEN=ghp_xxx in builds.
	secretEnv := loadSecretEnv()
	if len(secretEnv) > 0 {
		// Log keys only, not values
		keys := make([]string, 0, len(secretEnv))
		for k := range secretEnv {
			keys = append(keys, k)
		}
		log.Infof("loaded %d server-side secret env vars: %v", len(secretEnv), keys)
	}

	// Create scheduler with optional metrics
	var schedOpts []scheduler.SchedulerOption
	if melangeMetrics != nil {
		schedOpts = append(schedOpts, scheduler.WithMetrics(melangeMetrics))
	}
	sched := scheduler.New(buildStore, storageBackend, pool, scheduler.Config{
		OutputDir:            *outputDir,
		PollInterval:         pollInterval,
		MaxParallel:          *maxParallel,
		CacheRegistry:        cacheRegistry,
		CacheMode:            cacheMode,
		ApkoRegistry:         apkoRegistry,
		ApkoRegistryInsecure: apkoRegistryInsecure,
		ApkCacheDir:          apkCacheDir,
		ApkCacheTTL:          apkCacheTTL,
		ApkoServiceAddr:      apkoService,
		SecretEnv:            secretEnv,
	}, schedOpts...)

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

	// Run apko cache maintenance (evict stale entries, clear pools, log stats)
	eg.Go(func() error {
		return runApkoMaintenance(ctx, log)
	})

	// Run APK disk cache cleanup (if configured)
	eg.Go(func() error {
		return sched.RunCacheCleanup(ctx)
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

// runApkoMaintenance runs periodic maintenance on apko caches and pools.
// This helps prevent unbounded memory growth in long-running server processes.
func runApkoMaintenance(ctx context.Context, log *clog.Logger) error {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// Evict old image cache entries (older than 2 hours)
			evictedImages := apkobuild.DefaultImageCache().Evict(2 * time.Hour)

			// Evict unused tarfs entries (unused for 1 hour)
			evictedTarFS := expandapk.GlobalTarFSCache().Evict(time.Hour)

			// Clear pools and trigger GC
			apkobuild.ClearPools()

			// Log stats
			poolStats := apkobuild.AllPoolStats()
			imgStats := apkobuild.GetImageCacheStats()
			compStats := apkobuild.GetCompressionCacheStats()
			tarfsStats := expandapk.GetTarFSCacheStats()

			log.Infof("apko maintenance: evicted %d images, %d tarfs entries", evictedImages, evictedTarFS)
			log.Infof("apko image cache: hits=%d misses=%d coalesced=%d size=%d",
				imgStats.Hits, imgStats.Misses, imgStats.Coalesced, imgStats.Size)
			log.Infof("apko compression cache: hits=%d misses=%d evictions=%d",
				compStats.Hits, compStats.Misses, compStats.Evictions)
			log.Infof("apko tarfs cache: hits=%d misses=%d size=%d",
				tarfsStats.Hits, tarfsStats.Misses, tarfsStats.Size)

			// Log pool stats summary
			var totalHits, totalMisses, totalDrops int64
			for _, s := range poolStats {
				totalHits += s.Hits
				totalMisses += s.Misses
				totalDrops += s.Drops
			}
			log.Infof("apko pools: %d pools, total hits=%d misses=%d drops=%d",
				len(poolStats), totalHits, totalMisses, totalDrops)

			// Reset metrics for fresh monitoring period
			apkobuild.ResetPoolMetrics()
			apkobuild.ResetCompressionCacheStats()
		}
	}
}

// handleApkoStats returns apko cache and pool statistics as JSON.
func handleApkoStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := map[string]any{
		"pools":             apkobuild.AllPoolStats(),
		"image_cache":       apkobuild.GetImageCacheStats(),
		"compression_cache": apkobuild.GetCompressionCacheStats(),
		"tarfs_cache":       expandapk.GetTarFSCacheStats(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

// loadSecretEnv loads environment variables prefixed with SECRET_ENV_ and returns them
// as a map with the prefix stripped. These can be populated from Kubernetes secrets
// and are injected into all builds.
//
// Example:
//
//	SECRET_ENV_GITHUB_TOKEN=ghp_xxx -> {"GITHUB_TOKEN": "ghp_xxx"}
//	SECRET_ENV_NPM_TOKEN=npm_xxx   -> {"NPM_TOKEN": "npm_xxx"}
func loadSecretEnv() map[string]string {
	const prefix = "SECRET_ENV_"
	result := make(map[string]string)

	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, prefix) {
			continue
		}
		// Split on first = only (values may contain =)
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimPrefix(parts[0], prefix)
		value := strings.TrimSpace(parts[1])
		if key != "" && value != "" {
			result[key] = value
		}
	}

	return result
}
