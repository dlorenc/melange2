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

// Command apko-server runs the apko layer generation service.
// This service provides apko layer generation as a gRPC service,
// enabling fault isolation, retries, and independent scaling.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof" //nolint:gosec // Intentionally exposing pprof for debugging
	"os"
	"os/signal"
	"syscall"
	"time"

	apko_build "chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/apk/expandapk"
	"github.com/chainguard-dev/clog"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"github.com/dlorenc/melange2/pkg/service/apko"
	"github.com/dlorenc/melange2/pkg/service/tracing"
)

var (
	listenAddr       = flag.String("listen-addr", ":9090", "gRPC listen address")
	metricsAddr      = flag.String("metrics-addr", ":9091", "HTTP metrics/debug address")
	registry         = flag.String("registry", "registry:5000/apko-cache", "Registry for layer storage")
	registryInsecure = flag.Bool("registry-insecure", false, "Allow HTTP registry connections")
	maxConcurrent    = flag.Int("max-concurrent", 16, "Maximum concurrent builds")
	apkCacheDir      = flag.String("apk-cache-dir", "/var/cache/apk", "APK package cache directory")
	enableTracing    = flag.Bool("enable-tracing", false, "Enable OpenTelemetry tracing")
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
		ServiceName:    "apko-server",
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

	// Configure apko pools for server mode (bounded memory, optimized for concurrent builds)
	apko_build.ConfigurePoolsForService()
	log.Info("configured apko pools for service mode")

	// Create APK cache directory if needed
	if *apkCacheDir != "" {
		if err := os.MkdirAll(*apkCacheDir, 0755); err != nil {
			return fmt.Errorf("creating APK cache directory: %w", err)
		}
		log.Infof("using APK cache directory: %s", *apkCacheDir)
	}

	// Create the apko server
	server := apko.NewServer(apko.ServerConfig{
		Registry:         *registry,
		RegistryInsecure: *registryInsecure,
		ApkCacheDir:      *apkCacheDir,
		MaxConcurrent:    *maxConcurrent,
	})

	// Create gRPC server
	grpcServer := grpc.NewServer()
	apko.RegisterApkoServiceServer(grpcServer, server)

	// Register gRPC health check
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("apko.v1.ApkoService", grpc_health_v1.HealthCheckResponse_SERVING)

	// Enable reflection for debugging
	reflection.Register(grpcServer)

	// Create gRPC listener
	lis, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", *listenAddr, err)
	}

	// Create HTTP server for metrics/debug
	mux := http.NewServeMux()
	mux.Handle("/debug/pprof/", http.DefaultServeMux)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		stats := server.Stats()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(stats)
	})
	mux.HandleFunc("/debug/apko/stats", handleApkoStats)

	httpServer := &http.Server{
		Addr:              *metricsAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Run everything
	eg, ctx := errgroup.WithContext(ctx)

	// Run gRPC server
	eg.Go(func() error {
		log.Infof("gRPC server listening on %s", *listenAddr)
		log.Infof("registry: %s (insecure=%v)", *registry, *registryInsecure)
		log.Infof("max concurrent builds: %d", *maxConcurrent)
		if err := grpcServer.Serve(lis); err != nil {
			return fmt.Errorf("gRPC server error: %w", err)
		}
		return nil
	})

	// Run HTTP metrics server
	eg.Go(func() error {
		log.Infof("metrics server listening on %s", *metricsAddr)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			return fmt.Errorf("HTTP server error: %w", err)
		}
		return nil
	})

	// Run apko maintenance (periodic cleanup)
	eg.Go(func() error {
		return runApkoMaintenance(ctx, log)
	})

	// Handle shutdown
	eg.Go(func() error {
		<-ctx.Done()
		log.Info("shutting down...")

		// Update health status
		healthServer.SetServingStatus("apko.v1.ApkoService", grpc_health_v1.HealthCheckResponse_NOT_SERVING)

		// Graceful shutdown
		grpcServer.GracefulStop()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		return httpServer.Shutdown(shutdownCtx)
	})

	return eg.Wait()
}

// runApkoMaintenance runs periodic maintenance on apko caches and pools.
func runApkoMaintenance(ctx context.Context, log *clog.Logger) error {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// Evict old image cache entries
			evictedImages := apko_build.DefaultImageCache().Evict(2 * time.Hour)

			// Evict unused tarfs entries
			evictedTarFS := expandapk.GlobalTarFSCache().Evict(time.Hour)

			// Clear pools and trigger GC
			apko_build.ClearPools()

			// Log stats
			poolStats := apko_build.AllPoolStats()
			imgStats := apko_build.GetImageCacheStats()
			compStats := apko_build.GetCompressionCacheStats()
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
			apko_build.ResetPoolMetrics()
			apko_build.ResetCompressionCacheStats()
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
		"pools":             apko_build.AllPoolStats(),
		"image_cache":       apko_build.GetImageCacheStats(),
		"compression_cache": apko_build.GetCompressionCacheStats(),
		"tarfs_cache":       expandapk.GetTarFSCacheStats(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}
