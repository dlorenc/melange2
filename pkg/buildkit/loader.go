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
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/moby/buildkit/client/llb"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// LayerLoadResult contains the result of loading layers into BuildKit.
type LayerLoadResult struct {
	// State is the LLB state representing the loaded layers.
	State llb.State

	// LocalDirs maps local names to their extracted directories.
	// These must be provided to SolveOpt.LocalDirs when solving.
	// For registry-based loading, this may be empty.
	LocalDirs map[string]string

	// Cleanup releases any resources used by the loaded layers.
	// Should be called when the build is complete.
	Cleanup func()
}

// LayerLoader defines the interface for loading layers into BuildKit.
// Different implementations handle different layer sources:
// - LocalLayerLoader: extracts layers to disk using llb.Local()
// - RegistryLayerLoader: pushes layers to registry using llb.Image()
// - ServiceLayerLoader: uses pre-built images from apko service
type LayerLoader interface {
	// Load loads layers and returns an LLB state ready for building.
	Load(ctx context.Context, layers []v1.Layer, cfg *BuildConfig) (*LayerLoadResult, error)
}

// LocalLayerLoader extracts layers to disk and references them via llb.Local().
// This is the traditional approach that works without any registry.
type LocalLayerLoader struct {
	imageLoader *ImageLoader
}

// NewLocalLayerLoader creates a new LocalLayerLoader.
func NewLocalLayerLoader(imageLoader *ImageLoader) *LocalLayerLoader {
	return &LocalLayerLoader{
		imageLoader: imageLoader,
	}
}

// Load extracts layers to disk and creates an LLB state.
func (l *LocalLayerLoader) Load(ctx context.Context, layers []v1.Layer, cfg *BuildConfig) (*LayerLoadResult, error) {
	log := clog.FromContext(ctx)

	if len(layers) == 0 {
		return nil, fmt.Errorf("at least one layer is required")
	}

	log.Infof("loading %d apko layer(s) into BuildKit (local mode)", len(layers))
	loadStart := time.Now()

	loadResult, err := l.imageLoader.LoadLayers(ctx, layers, cfg.PackageName)
	if err != nil {
		return nil, fmt.Errorf("loading apko layers: %w", err)
	}

	loadDuration := time.Since(loadStart)
	log.Infof("layer_load took %s", loadDuration)
	log.Infof("building LLB graph with %d layer(s)", loadResult.LayerCount)

	// Copy localDirs to avoid sharing the map
	localDirs := make(map[string]string, len(loadResult.LocalDirs))
	for k, v := range loadResult.LocalDirs {
		localDirs[k] = v
	}

	return &LayerLoadResult{
		State:     loadResult.State,
		LocalDirs: localDirs,
		Cleanup: func() {
			if err := loadResult.Cleanup(); err != nil {
				log.Warnf("cleanup failed: %v", err)
			}
		},
	}, nil
}

// RegistryLayerLoader pushes layers to a registry and references them via llb.Image().
// This provides better caching as BuildKit can cache layers by content address.
type RegistryLayerLoader struct{}

// NewRegistryLayerLoader creates a new RegistryLayerLoader.
func NewRegistryLayerLoader() *RegistryLayerLoader {
	return &RegistryLayerLoader{}
}

// Load pushes layers to the configured registry and creates an LLB state.
func (l *RegistryLayerLoader) Load(ctx context.Context, layers []v1.Layer, cfg *BuildConfig) (*LayerLoadResult, error) {
	log := clog.FromContext(ctx)

	if cfg.ApkoRegistryConfig == nil || cfg.ApkoRegistryConfig.Registry == "" {
		return nil, fmt.Errorf("ApkoRegistryConfig.Registry is required for registry-based loading")
	}

	if cfg.ImgConfig == nil {
		return nil, fmt.Errorf("ImgConfig is required for registry-based loading")
	}

	if len(layers) == 0 {
		return nil, fmt.Errorf("at least one layer is required")
	}

	log.Infof("using apko registry cache: %s", cfg.ApkoRegistryConfig.Registry)
	loadStart := time.Now()

	cache := NewApkoImageCache(cfg.ApkoRegistryConfig.Registry, cfg.ApkoRegistryConfig.Insecure)
	imgRef, cacheHit, err := cache.GetOrCreate(ctx, *cfg.ImgConfig, layers)
	if err != nil {
		return nil, fmt.Errorf("caching apko image: %w", err)
	}

	loadDuration := time.Since(loadStart)
	if cacheHit {
		log.Infof("apko_registry_cache_hit took %s", loadDuration)
	} else {
		log.Infof("apko_registry_push took %s", loadDuration)
	}

	// Use llb.Image() to reference the cached image
	state := llb.Image(imgRef, llb.WithCustomName("apko base image (cached)"))

	return &LayerLoadResult{
		State:     state,
		LocalDirs: make(map[string]string),
		Cleanup:   func() {}, // No cleanup needed for registry-based approach
	}, nil
}

// ServiceLayerLoader uses pre-built images from an apko service.
// The service has already pushed the image to the registry.
type ServiceLayerLoader struct{}

// NewServiceLayerLoader creates a new ServiceLayerLoader.
func NewServiceLayerLoader() *ServiceLayerLoader {
	return &ServiceLayerLoader{}
}

// Load creates an LLB state from a pre-built image reference.
// layers should be empty - the image is already built by the service.
func (l *ServiceLayerLoader) Load(ctx context.Context, layers []v1.Layer, cfg *BuildConfig) (*LayerLoadResult, error) {
	log := clog.FromContext(ctx)

	if cfg.ApkoRegistryConfig == nil || cfg.ApkoRegistryConfig.Registry == "" {
		return nil, fmt.Errorf("ApkoRegistryConfig.Registry is required (should contain image ref from service)")
	}

	if len(layers) > 0 {
		return nil, fmt.Errorf("layers should be empty when using service loader (service builds the image)")
	}

	imgRef := cfg.ApkoRegistryConfig.Registry
	log.Infof("using pre-built apko image from service: %s", imgRef)

	// Use llb.Image() to reference the pre-built image
	state := llb.Image(imgRef, llb.WithCustomName("apko base image (cached)"))

	return &LayerLoadResult{
		State:     state,
		LocalDirs: make(map[string]string),
		Cleanup:   func() {}, // No cleanup needed
	}, nil
}

// SelectLayerLoader chooses the appropriate layer loader based on configuration.
// Returns the loader and a description of the mode being used.
func SelectLayerLoader(cfg *BuildConfig, layers []v1.Layer, imageLoader *ImageLoader) LayerLoader {
	hasApkoRegistry := cfg.ApkoRegistryConfig != nil && cfg.ApkoRegistryConfig.Registry != ""

	switch {
	case hasApkoRegistry && len(layers) == 0:
		// Service mode: image was pre-built by apko service
		return NewServiceLayerLoader()

	case hasApkoRegistry && len(layers) > 0:
		// Registry mode: we push layers to registry ourselves
		return NewRegistryLayerLoader()

	default:
		// Local mode: extract layers to disk
		return NewLocalLayerLoader(imageLoader)
	}
}

// TestStateResult contains the result of providing a base state for tests.
type TestStateResult struct {
	// State is the LLB state to use as the base for tests.
	State llb.State

	// LocalDirs maps local names to their directories.
	// These must be provided to SolveOpt.LocalDirs when solving.
	LocalDirs map[string]string

	// Cleanup releases any resources. Should be called when done.
	Cleanup func()
}

// TestStateProvider provides a base LLB state for running tests.
// Different implementations handle different sources:
// - LayerTestStateProvider: loads from v1.Layer via ImageLoader
// - ImageTestStateProvider: uses llb.Image() directly
type TestStateProvider interface {
	// Provide creates the base state for running tests.
	Provide(ctx context.Context, pkgName string) (*TestStateResult, error)
}

// LayerTestStateProvider provides test state by loading layers from v1.Layer.
type LayerTestStateProvider struct {
	layers      []v1.Layer
	imageLoader *ImageLoader
}

// NewLayerTestStateProvider creates a new LayerTestStateProvider.
func NewLayerTestStateProvider(layers []v1.Layer, imageLoader *ImageLoader) *LayerTestStateProvider {
	return &LayerTestStateProvider{
		layers:      layers,
		imageLoader: imageLoader,
	}
}

// Provide loads layers and returns the base state.
func (p *LayerTestStateProvider) Provide(ctx context.Context, pkgName string) (*TestStateResult, error) {
	log := clog.FromContext(ctx)

	loadResult, err := p.imageLoader.LoadLayers(ctx, p.layers, pkgName+"-test")
	if err != nil {
		return nil, fmt.Errorf("loading apko layers: %w", err)
	}

	// Copy localDirs
	localDirs := make(map[string]string, len(loadResult.LocalDirs))
	for k, v := range loadResult.LocalDirs {
		localDirs[k] = v
	}

	return &TestStateResult{
		State:     loadResult.State,
		LocalDirs: localDirs,
		Cleanup: func() {
			if err := loadResult.Cleanup(); err != nil {
				log.Warnf("cleanup failed: %v", err)
			}
		},
	}, nil
}

// ImageTestStateProvider provides test state from an image reference.
type ImageTestStateProvider struct {
	imageRef string
}

// NewImageTestStateProvider creates a new ImageTestStateProvider.
func NewImageTestStateProvider(imageRef string) *ImageTestStateProvider {
	return &ImageTestStateProvider{
		imageRef: imageRef,
	}
}

// Provide creates a base state from the image reference.
func (p *ImageTestStateProvider) Provide(ctx context.Context, pkgName string) (*TestStateResult, error) {
	return &TestStateResult{
		State:     llb.Image(p.imageRef),
		LocalDirs: make(map[string]string),
		Cleanup:   func() {}, // No cleanup needed for image-based approach
	}, nil
}
