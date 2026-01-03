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

// Command melange-buildkit-manager runs the BuildKit Manager as a gRPC service.
// This is part of Phase 6 of the microservices architecture.
//
// In the microservices deployment:
//   - melange-api: handles HTTP API requests (builds, packages)
//   - melange-orchestrator: processes builds, coordinates managers
//   - melange-buildkit-manager: manages BuildKit workers (this binary)
//
// The orchestrator communicates with the BuildKit Manager via gRPC to:
//   - Request workers for builds
//   - Release workers after builds complete
//   - Query status and capacity
//
// For the monolith (backward compatibility), use melange-server instead.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/chainguard-dev/clog"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/dlorenc/melange2/pkg/service/buildkit"
	"github.com/dlorenc/melange2/pkg/service/metrics"
	"github.com/dlorenc/melange2/pkg/service/tracing"
)

var (
	grpcAddr       = flag.String("grpc-addr", ":9090", "gRPC listen address")
	httpAddr       = flag.String("http-addr", ":8082", "HTTP listen address for health/metrics")
	buildkitAddr   = flag.String("buildkit-addr", "", "BuildKit daemon address (for single-backend mode)")
	backendsConfig = flag.String("backends-config", "", "Path to backends config file (YAML) for multi-backend mode")
	defaultArch    = flag.String("default-arch", "x86_64", "Default architecture for single-backend mode")

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
		ServiceName:    "melange-buildkit-manager",
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

	// Create BuildKit manager
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

	// Create gRPC server
	grpcServer := grpc.NewServer()
	buildkitServer := buildkit.NewGRPCServer(buildkit.GRPCServerConfig{
		Manager: manager,
	})
	buildkit.RegisterBuildKitManagerServiceServer(grpcServer, buildkitServer)

	// Enable reflection for grpcurl debugging
	reflection.Register(grpcServer)

	// Create health/metrics HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		// Check if we have at least one backend
		status := manager.Status()
		if status.TotalWorkers == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "no backends"})
			return
		}
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
		Addr:              *httpAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	// Run everything
	eg, ctx := errgroup.WithContext(ctx)

	// Run gRPC server
	eg.Go(func() error {
		listener, err := net.Listen("tcp", *grpcAddr)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", *grpcAddr, err)
		}
		log.Infof("buildkit-manager gRPC server on %s", *grpcAddr)
		if err := grpcServer.Serve(listener); err != nil {
			return fmt.Errorf("gRPC server error: %w", err)
		}
		return nil
	})

	// Run HTTP server for health/metrics
	eg.Go(func() error {
		log.Infof("buildkit-manager health/metrics on %s", *httpAddr)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			return fmt.Errorf("HTTP server error: %w", err)
		}
		return nil
	})

	// Handle shutdown
	eg.Go(func() error {
		<-ctx.Done()
		log.Info("shutting down...")

		// Stop accepting new gRPC requests
		grpcServer.GracefulStop()

		// Shutdown HTTP server
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Warnf("HTTP server shutdown error: %v", err)
		}

		// Close the manager
		if err := buildkitServer.Close(); err != nil {
			log.Warnf("manager close error: %v", err)
		}

		return nil
	})

	return eg.Wait()
}
