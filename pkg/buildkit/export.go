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

package buildkit

import (
	"context"
	"fmt"
	"io"
	"os"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/errgroup"
)

// ExportType specifies how to export a debug image.
type ExportType string

const (
	ExportTypeNone     ExportType = ""
	ExportTypeTarball  ExportType = "tarball"
	ExportTypeDocker   ExportType = "docker"
	ExportTypeRegistry ExportType = "registry"
)

// ExportConfig contains configuration for exporting a debug image.
type ExportConfig struct {
	// Type specifies how to export the image.
	Type ExportType

	// Ref is the path (for tarball) or image reference (for docker/registry).
	Ref string

	// Arch is the target architecture.
	Arch apko_types.Architecture

	// LocalDirs are the local directories to mount during export.
	LocalDirs map[string]string
}

// ExportDebugImage exports the given LLB state as a debug image.
// This is used to export the build environment when a build fails,
// allowing developers to inspect the container filesystem.
func (b *Builder) ExportDebugImage(ctx context.Context, state llb.State, cfg *ExportConfig) error {
	log := clog.FromContext(ctx)

	if cfg.Type == ExportTypeNone || cfg.Type == "" {
		return nil
	}

	log.Infof("exporting debug image as %s to %s", cfg.Type, cfg.Ref)

	// Marshal the state to LLB definition
	ociPlatform := cfg.Arch.ToOCIPlatform()
	platform := llb.Platform(ocispecs.Platform{
		OS:           ociPlatform.OS,
		Architecture: ociPlatform.Architecture,
		Variant:      ociPlatform.Variant,
	})

	def, err := state.Marshal(ctx, platform)
	if err != nil {
		return fmt.Errorf("marshaling debug image LLB: %w", err)
	}

	// Build export configuration based on type
	exports, err := buildExportEntries(cfg)
	if err != nil {
		return err
	}

	// Create progress writer (silent for debug export)
	progress := NewProgressWriter(io.Discard, ProgressModeQuiet, false)

	// Solve and export
	statusCh := make(chan *client.SolveStatus)
	eg, egCtx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		return progress.Write(egCtx, statusCh)
	})

	eg.Go(func() error {
		_, err := b.client.Client().Solve(ctx, def, client.SolveOpt{
			LocalDirs: cfg.LocalDirs,
			Exports:   exports,
		}, statusCh)
		return err
	})

	if err := eg.Wait(); err != nil {
		return fmt.Errorf("exporting debug image: %w", err)
	}

	log.Infof("debug image exported successfully to %s", cfg.Ref)
	return nil
}

// buildExportEntries creates the BuildKit export entries based on export type.
func buildExportEntries(cfg *ExportConfig) ([]client.ExportEntry, error) {
	switch cfg.Type {
	case ExportTypeTarball:
		// For tarball, we need to create a file writer
		// BuildKit's OCI exporter writes to a directory, so we use tar exporter
		return []client.ExportEntry{{
			Type:   client.ExporterOCI,
			Output: fixedWriteCloser(cfg.Ref),
		}}, nil

	case ExportTypeDocker:
		return []client.ExportEntry{{
			Type: client.ExporterDocker,
			Attrs: map[string]string{
				"name": cfg.Ref,
			},
		}}, nil

	case ExportTypeRegistry:
		return []client.ExportEntry{{
			Type: client.ExporterImage,
			Attrs: map[string]string{
				"name": cfg.Ref,
				"push": "true",
			},
		}}, nil

	default:
		return nil, fmt.Errorf("unknown export type: %s", cfg.Type)
	}
}

// fixedWriteCloser returns a function that creates a file writer for the given path.
// This is used with BuildKit's Output field which expects a function.
func fixedWriteCloser(path string) func(map[string]string) (io.WriteCloser, error) {
	return func(map[string]string) (io.WriteCloser, error) {
		return os.Create(path)
	}
}
