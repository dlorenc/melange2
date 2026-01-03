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

// Command melange-api runs the standalone API server for the melange service.
// This is part of Phase 4 of the microservices architecture.
//
// In the microservices deployment:
//   - melange-api: handles HTTP API requests (builds, packages)
//   - melange-orchestrator: processes builds, manages backends
//
// For the monolith (backward compatibility), use melange-server instead.
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
	"strings"
	"syscall"
	"time"

	"github.com/chainguard-dev/clog"
	"golang.org/x/sync/errgroup"

	"github.com/dlorenc/melange2/pkg/service/api"
	"github.com/dlorenc/melange2/pkg/service/metrics"
	"github.com/dlorenc/melange2/pkg/service/store"
	"github.com/dlorenc/melange2/pkg/service/tracing"
)

var (
	listenAddr = flag.String("listen-addr", ":8080", "HTTP listen address")
	// Observability flags
	enableTracing   = flag.Bool("enable-tracing", false, "Enable OpenTelemetry tracing")
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
		ServiceName:    "melange-api",
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

	// Create build store (PostgreSQL or in-memory)
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

	// Create API server (no backends - handled by orchestrator in Phase 4+)
	apiServer := api.NewServer(buildStore)

	// Create a mux that routes requests appropriately
	mux := http.NewServeMux()
	mux.Handle("/debug/pprof/", http.DefaultServeMux) // pprof registers to DefaultServeMux
	// Add /metrics endpoint for Prometheus
	if melangeMetrics != nil {
		mux.Handle("/metrics", melangeMetrics.Handler())
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Route non-pprof requests to API server
		if !strings.HasPrefix(r.URL.Path, "/debug/pprof/") && r.URL.Path != "/metrics" {
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

	// Run everything
	eg, ctx := errgroup.WithContext(ctx)

	// Run HTTP server
	eg.Go(func() error {
		log.Infof("melange-api listening on %s", *listenAddr)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			return fmt.Errorf("HTTP server error: %w", err)
		}
		return nil
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
