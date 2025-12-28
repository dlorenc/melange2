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
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/moby/buildkit/client/llb"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// ImageLoader handles loading OCI images into BuildKit.
type ImageLoader struct {
	// extractDir is where layers are extracted to.
	// If empty, a temp directory is created.
	extractDir string
}

// NewImageLoader creates a new ImageLoader.
// If extractDir is empty, a temp directory will be created for each load.
func NewImageLoader(extractDir string) *ImageLoader {
	return &ImageLoader{
		extractDir: extractDir,
	}
}

// LoadResult contains the result of loading an image.
type LoadResult struct {
	// State is the LLB state representing the loaded image.
	State llb.State

	// LocalName is the name used for the local mount.
	// This must be provided to SolveOpt.LocalDirs when solving.
	LocalName string

	// ExtractDir is the directory where the layer was extracted.
	// This is the value to use in LocalDirs[LocalName].
	ExtractDir string

	// Cleanup removes the extracted directory.
	// Should be called when the build is complete.
	Cleanup func() error
}

// LoadLayer loads a v1.Layer (as produced by apko) into BuildKit.
//
// The approach is:
// 1. Extract the layer tar to a local directory
// 2. Use llb.Local() to reference it
// 3. Copy from Local to Scratch to create the base state
//
// The caller must:
// - Include result.LocalName -> result.ExtractDir in SolveOpt.LocalDirs
// - Call result.Cleanup() when done
func (l *ImageLoader) LoadLayer(ctx context.Context, layer v1.Layer, name string) (*LoadResult, error) {
	// Create extraction directory
	var extractDir string
	var cleanup func() error

	if l.extractDir != "" {
		extractDir = filepath.Join(l.extractDir, name)
		if err := os.MkdirAll(extractDir, 0755); err != nil {
			return nil, fmt.Errorf("creating extract dir: %w", err)
		}
		cleanup = func() error {
			return os.RemoveAll(extractDir)
		}
	} else {
		var err error
		extractDir, err = os.MkdirTemp("", "melange-apko-"+name+"-*")
		if err != nil {
			return nil, fmt.Errorf("creating temp dir: %w", err)
		}
		cleanup = func() error {
			return os.RemoveAll(extractDir)
		}
	}

	// Extract the layer
	if err := extractLayer(layer, extractDir); err != nil {
		_ = cleanup() // Ignore cleanup error when extract fails
		return nil, fmt.Errorf("extracting layer: %w", err)
	}

	// Create the LLB state
	localName := "apko-" + name
	local := llb.Local(localName)

	// Copy from Local to Scratch to create our base image
	state := llb.Scratch().File(
		llb.Copy(local, "/", "/"),
		llb.WithCustomName("copy apko rootfs"),
	)

	return &LoadResult{
		State:      state,
		LocalName:  localName,
		ExtractDir: extractDir,
		Cleanup:    cleanup,
	}, nil
}

// extractLayer extracts a v1.Layer to a directory.
func extractLayer(layer v1.Layer, destDir string) error {
	rc, err := layer.Uncompressed()
	if err != nil {
		return fmt.Errorf("getting uncompressed layer: %w", err)
	}
	defer rc.Close()

	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}

		// Security: validate path to prevent path traversal
		// #nosec G305 - Path is validated by isValidPath below
		target := filepath.Join(destDir, hdr.Name)
		if !isValidPath(destDir, target, hdr.Name) {
			continue // Skip potentially unsafe paths
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
				return fmt.Errorf("creating directory %s: %w", target, err)
			}

		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("creating parent dir for %s: %w", target, err)
			}

			// Ensure file is at least readable (BuildKit needs to read xattrs)
			// This is needed because files like /etc/shadow have restrictive modes
			mode := os.FileMode(hdr.Mode)
			if mode&0400 == 0 {
				mode |= 0400 // Add owner read permission
			}

			// #nosec G304 - Extracting trusted container image
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return fmt.Errorf("creating file %s: %w", target, err)
			}

			// #nosec G110 - Trusted container image, size from tar header
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("writing file %s: %w", target, err)
			}
			f.Close()

		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("creating parent dir for symlink %s: %w", target, err)
			}
			// Remove existing symlink if any
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return fmt.Errorf("creating symlink %s -> %s: %w", target, hdr.Linkname, err)
			}

		case tar.TypeLink:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("creating parent dir for hardlink %s: %w", target, err)
			}
			// #nosec G305 - Source path already validated above
			linkTarget := filepath.Join(destDir, hdr.Linkname)
			_ = os.Remove(target)
			if err := os.Link(linkTarget, target); err != nil {
				return fmt.Errorf("creating hardlink %s -> %s: %w", target, linkTarget, err)
			}
		}
	}

	return nil
}

// isValidPath checks if a path is safe to extract.
func isValidPath(destDir, target, name string) bool {
	// Reject absolute paths in tar
	if filepath.IsAbs(name) {
		return false
	}

	// Reject paths with ..
	if strings.Contains(name, "..") {
		return false
	}

	// Verify the target is within destDir
	rel, err := filepath.Rel(destDir, target)
	if err != nil {
		return false
	}
	if strings.HasPrefix(rel, "..") {
		return false
	}

	return true
}

// MultiLayerResult contains the result of loading multiple layers.
type MultiLayerResult struct {
	// State is the combined LLB state representing all loaded layers.
	State llb.State

	// LocalDirs maps local names to their extracted directories.
	// These must all be provided to SolveOpt.LocalDirs when solving.
	LocalDirs map[string]string

	// LayerCount is the number of layers that were loaded.
	LayerCount int

	// Cleanup removes all extracted directories.
	// Should be called when the build is complete.
	Cleanup func() error
}

// LoadLayers loads multiple v1.Layer objects (as produced by apko's BuildLayers)
// into BuildKit. Each layer is extracted and loaded separately, allowing BuildKit
// to cache each layer independently for better cache efficiency.
//
// The approach is:
// 1. Extract each layer tar to its own local directory
// 2. Use llb.Local() to reference each layer
// 3. Progressively copy each layer on top of scratch to create the base state
//
// This enables better caching because:
// - Base OS layers (glibc, busybox) change rarely
// - Compiler layers (gcc, binutils) change occasionally
// - Package-specific dependencies change more frequently
// By splitting into layers, only changed layers need to be rebuilt/transferred.
//
// The caller must:
// - Include all result.LocalDirs entries in SolveOpt.LocalDirs
// - Call result.Cleanup() when done
func (l *ImageLoader) LoadLayers(ctx context.Context, layers []v1.Layer, baseName string) (*MultiLayerResult, error) {
	// If only one layer, use the simpler single-layer path
	if len(layers) == 1 {
		result, err := l.LoadLayer(ctx, layers[0], baseName)
		if err != nil {
			return nil, err
		}
		return &MultiLayerResult{
			State:      result.State,
			LocalDirs:  map[string]string{result.LocalName: result.ExtractDir},
			LayerCount: 1,
			Cleanup:    result.Cleanup,
		}, nil
	}

	localDirs := make(map[string]string, len(layers))
	var cleanupFuncs []func() error

	// Extract each layer
	for i, layer := range layers {
		layerName := fmt.Sprintf("%s-layer-%d", baseName, i)

		// Create extraction directory
		var extractDir string
		var cleanup func() error

		if l.extractDir != "" {
			extractDir = filepath.Join(l.extractDir, layerName)
			if err := os.MkdirAll(extractDir, 0755); err != nil {
				// Clean up any previously extracted layers
				for _, cf := range cleanupFuncs {
					_ = cf()
				}
				return nil, fmt.Errorf("creating extract dir for layer %d: %w", i, err)
			}
			cleanup = func() error {
				return os.RemoveAll(extractDir)
			}
		} else {
			var err error
			extractDir, err = os.MkdirTemp("", fmt.Sprintf("melange-apko-%s-*", layerName))
			if err != nil {
				// Clean up any previously extracted layers
				for _, cf := range cleanupFuncs {
					_ = cf()
				}
				return nil, fmt.Errorf("creating temp dir for layer %d: %w", i, err)
			}
			cleanup = func() error {
				return os.RemoveAll(extractDir)
			}
		}
		cleanupFuncs = append(cleanupFuncs, cleanup)

		// Extract the layer
		if err := extractLayer(layer, extractDir); err != nil {
			// Clean up all extracted layers on error
			for _, cf := range cleanupFuncs {
				_ = cf()
			}
			return nil, fmt.Errorf("extracting layer %d: %w", i, err)
		}

		localName := fmt.Sprintf("apko-%s", layerName)
		localDirs[localName] = extractDir
	}

	// Build the combined LLB state by progressively copying each layer
	state := llb.Scratch()
	for i := range layers {
		layerName := fmt.Sprintf("%s-layer-%d", baseName, i)
		localName := fmt.Sprintf("apko-%s", layerName)
		local := llb.Local(localName)

		state = state.File(
			llb.Copy(local, "/", "/"),
			llb.WithCustomName(fmt.Sprintf("copy apko layer %d/%d", i+1, len(layers))),
		)
	}

	// Create combined cleanup function
	cleanup := func() error {
		var errs []error
		for _, cf := range cleanupFuncs {
			if err := cf(); err != nil {
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("cleanup errors: %v", errs)
		}
		return nil
	}

	return &MultiLayerResult{
		State:      state,
		LocalDirs:  localDirs,
		LayerCount: len(layers),
		Cleanup:    cleanup,
	}, nil
}
