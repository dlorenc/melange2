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

// Command melange-apko-manager runs the Apko Manager as a gRPC service.
// This is part of Phase 7 of the microservices architecture.
//
// In the microservices deployment:
//   - melange-api: handles HTTP API requests (builds, packages)
//   - melange-orchestrator: processes builds, coordinates managers
//   - melange-buildkit-manager: manages BuildKit workers
//   - melange-apko-manager: manages apko instances (this binary)
//
// The orchestrator communicates with the Apko Manager via gRPC to:
//   - Request apko instances for layer builds
//   - Release instances after builds complete
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

	"github.com/dlorenc/melange2/pkg/service/apko"
	"github.com/dlorenc/melange2/pkg/service/metrics"
	"github.com/dlorenc/melange2/pkg/service/tracing"
)

var (
	grpcAddr        = flag.String("grpc-addr", ":9091", "gRPC listen address")
	httpAddr        = flag.String("http-addr", ":8083", "HTTP listen address for health/metrics")
	apkoAddr        = flag.String("apko-addr", "", "Single apko server address (for single-instance mode)")
	instancesConfig = flag.String("instances-config", "", "Path to instances config file (YAML) for multi-instance mode")
	maxConcurrent   = flag.Int("max-concurrent", 16, "Max concurrent builds per instance (single-instance mode)")

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
		ServiceName:    "melange-apko-manager",
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

	// Create Apko manager
	var manager *apko.StaticManager
	switch {
	case *instancesConfig != "":
		log.Infof("using instances config: %s", *instancesConfig)
		var err error
		manager, err = apko.NewStaticManagerFromConfigFile(*instancesConfig)
		if err != nil {
			return fmt.Errorf("creating apko manager from config: %w", err)
		}
	case *apkoAddr != "":
		log.Infof("using single apko instance: %s (max_concurrent: %d)", *apkoAddr, *maxConcurrent)
		var err error
		manager, err = apko.NewStaticManagerFromSingleAddr(*apkoAddr, *maxConcurrent)
		if err != nil {
			return fmt.Errorf("creating apko manager: %w", err)
		}
	default:
		// Try default
		log.Infof("using default apko instance: apko-server:9090 (max_concurrent: %d)", *maxConcurrent)
		var err error
		manager, err = apko.NewStaticManagerFromSingleAddr("apko-server:9090", *maxConcurrent)
		if err != nil {
			return fmt.Errorf("creating apko manager: %w", err)
		}
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()
	apkoServer := apko.NewManagerGRPCServer(apko.ManagerGRPCServerConfig{
		Manager: manager,
	})
	apko.RegisterApkoManagerServiceServer(grpcServer, apkoServer)

	// Enable reflection for grpcurl debugging
	reflection.Register(grpcServer)

	// Create health/metrics HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		// Check if we have at least one instance
		status := manager.Status()
		if status.TotalInstances == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "no instances"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/api/v1/instances", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"instances": manager.List(),
		})
	})
	mux.HandleFunc("/api/v1/instances/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		status := manager.Status()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"type":               status.Type,
			"total_instances":    status.TotalInstances,
			"total_capacity":     status.TotalCapacity,
			"active_builds":      status.ActiveBuilds,
			"instances":          status.Instances,
			"cache_hits":         status.CacheHits,
			"cache_misses":       status.CacheMisses,
			"available_capacity": manager.AvailableCapacity(),
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
		log.Infof("apko-manager gRPC server on %s", *grpcAddr)
		if err := grpcServer.Serve(listener); err != nil {
			return fmt.Errorf("gRPC server error: %w", err)
		}
		return nil
	})

	// Run HTTP server for health/metrics
	eg.Go(func() error {
		log.Infof("apko-manager health/metrics on %s", *httpAddr)
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
		if err := apkoServer.Close(); err != nil {
			log.Warnf("manager close error: %v", err)
		}

		return nil
	})

	return eg.Wait()
}
