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
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/chainguard-dev/clog"
	"golang.org/x/sync/errgroup"

	"github.com/dlorenc/melange2/pkg/service/api"
	"github.com/dlorenc/melange2/pkg/service/scheduler"
	"github.com/dlorenc/melange2/pkg/service/storage"
	"github.com/dlorenc/melange2/pkg/service/store"
)

var (
	listenAddr   = flag.String("listen-addr", ":8080", "HTTP listen address")
	buildkitAddr = flag.String("buildkit-addr", "tcp://localhost:1234", "BuildKit daemon address")
	outputDir    = flag.String("output-dir", "/var/lib/melange/output", "Directory for build outputs (local storage)")
	gcsBucket    = flag.String("gcs-bucket", "", "GCS bucket for build outputs (if set, uses GCS instead of local storage)")
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

	// Create shared components
	jobStore := store.NewMemoryStore()

	// Initialize storage backend
	var storageBackend storage.Storage
	var err error
	if *gcsBucket != "" {
		log.Infof("using GCS storage: gs://%s", *gcsBucket)
		storageBackend, err = storage.NewGCSStorage(ctx, *gcsBucket)
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

	// Create API server
	apiServer := api.NewServer(jobStore)
	httpServer := &http.Server{
		Addr:              *listenAddr,
		Handler:           apiServer,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	// Create scheduler
	sched := scheduler.New(jobStore, storageBackend, scheduler.Config{
		BuildKitAddr: *buildkitAddr,
		OutputDir:    *outputDir,
		PollInterval: time.Second,
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
