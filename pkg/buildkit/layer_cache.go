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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"sync"

	apko_build "chainguard.dev/apko/pkg/build"
	"github.com/chainguard-dev/clog"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// LayerCache manages per-layer caching of apko-generated layers in a registry.
// This enables sharing of common base layers across builds with different
// top-level packages.
type LayerCache struct {
	// Registry is the base registry URL for cached layers.
	// Example: "registry:5000/apko-layers"
	Registry string

	// Arch is the target architecture, included in cache keys for uniqueness.
	Arch string

	// Insecure allows connecting to registries over HTTP.
	Insecure bool
}

// NewLayerCache creates a new LayerCache.
func NewLayerCache(registry, arch string, insecure bool) *LayerCache {
	return &LayerCache{
		Registry: registry,
		Arch:     arch,
		Insecure: insecure,
	}
}

// LayerCacheKey computes a deterministic cache key for a layer group.
// The key is based on the architecture and sorted package names+versions.
func LayerCacheKey(arch string, group apko_build.LayerGroup) string {
	h := sha256.New()

	// Include architecture
	h.Write([]byte(arch + "\n"))

	// Sort packages for determinism (should already be sorted, but ensure it)
	pkgs := make([]string, len(group.Packages))
	for i, p := range group.Packages {
		pkgs[i] = fmt.Sprintf("%s=%s", p.Name, p.Version)
	}
	slices.Sort(pkgs)

	// Hash the package list
	for _, pkg := range pkgs {
		h.Write([]byte(pkg + "\n"))
	}

	return hex.EncodeToString(h.Sum(nil))[:16]
}

// CachedLayerRef represents a reference to a cached layer in the registry.
type CachedLayerRef struct {
	Key string // The cache key
	Ref string // The full registry reference
}

// CheckLayers checks which layers from the predicted groups exist in the registry.
// Returns a slice of CachedLayerRef for layers that exist, and a bool indicating
// if all layers were found (complete cache hit).
func (c *LayerCache) CheckLayers(ctx context.Context, groups []apko_build.LayerGroup) ([]CachedLayerRef, bool, error) {
	log := clog.FromContext(ctx)

	if c.Registry == "" {
		return nil, false, nil
	}

	// Compute cache keys for all groups
	keys := make([]string, len(groups))
	for i, g := range groups {
		keys[i] = LayerCacheKey(c.Arch, g)
	}

	// Check all layers in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex
	found := make([]CachedLayerRef, 0, len(groups))
	errs := make([]error, 0)

	opts := []name.Option{}
	if c.Insecure {
		opts = append(opts, name.Insecure)
	}
	remoteOpts := []remote.Option{remote.WithContext(ctx)}
	if c.Insecure {
		remoteOpts = append(remoteOpts, remote.WithTransport(&http.Transport{}))
	}

	for _, key := range keys {
		wg.Add(1)
		go func(k string) {
			defer wg.Done()

			ref := fmt.Sprintf("%s:%s", c.Registry, k)
			imgRef, err := name.ParseReference(ref, opts...)
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("parsing ref %s: %w", ref, err))
				mu.Unlock()
				return
			}

			if _, err := remote.Head(imgRef, remoteOpts...); err == nil {
				mu.Lock()
				found = append(found, CachedLayerRef{Key: k, Ref: ref})
				mu.Unlock()
			}
		}(key)
	}
	wg.Wait()

	if len(errs) > 0 {
		log.Warnf("errors checking layer cache: %v", errs)
	}

	allCached := len(found) == len(groups)
	log.Infof("layer cache: %d/%d layers found", len(found), len(groups))

	return found, allCached, nil
}

// PushLayers pushes individual layers to the registry with their cache keys.
// This should be called after BuildLayers to populate the cache for future builds.
func (c *LayerCache) PushLayers(ctx context.Context, layers []v1.Layer, groups []apko_build.LayerGroup) error {
	log := clog.FromContext(ctx)

	if c.Registry == "" {
		return nil
	}

	if len(layers) != len(groups) {
		return fmt.Errorf("layer count mismatch: %d layers vs %d groups", len(layers), len(groups))
	}

	opts := []name.Option{}
	if c.Insecure {
		opts = append(opts, name.Insecure)
	}
	remoteOpts := []remote.Option{remote.WithContext(ctx)}
	if c.Insecure {
		remoteOpts = append(remoteOpts, remote.WithTransport(&http.Transport{}))
	}

	for i, layer := range layers {
		key := LayerCacheKey(c.Arch, groups[i])
		ref := fmt.Sprintf("%s:%s", c.Registry, key)

		imgRef, err := name.ParseReference(ref, opts...)
		if err != nil {
			return fmt.Errorf("parsing ref %s: %w", ref, err)
		}

		// Check if already exists
		if _, err := remote.Head(imgRef, remoteOpts...); err == nil {
			log.Debugf("layer %s already cached", key)
			continue
		}

		// Wrap layer in a minimal image for storage
		img, err := mutate.AppendLayers(empty.Image, layer)
		if err != nil {
			return fmt.Errorf("wrapping layer %d: %w", i, err)
		}

		if err := remote.Write(imgRef, img, remoteOpts...); err != nil {
			return fmt.Errorf("pushing layer %s: %w", ref, err)
		}
		log.Debugf("pushed layer %s", key)
	}

	log.Infof("pushed %d layers to cache", len(layers))
	return nil
}

// PullLayers retrieves cached layers from the registry by their references.
// Returns the layers in the same order as the input refs.
func (c *LayerCache) PullLayers(ctx context.Context, refs []CachedLayerRef) ([]v1.Layer, error) {
	log := clog.FromContext(ctx)

	opts := []name.Option{}
	if c.Insecure {
		opts = append(opts, name.Insecure)
	}
	remoteOpts := []remote.Option{remote.WithContext(ctx)}
	if c.Insecure {
		remoteOpts = append(remoteOpts, remote.WithTransport(&http.Transport{}))
	}

	layers := make([]v1.Layer, len(refs))
	for i, ref := range refs {
		imgRef, err := name.ParseReference(ref.Ref, opts...)
		if err != nil {
			return nil, fmt.Errorf("parsing ref %s: %w", ref.Ref, err)
		}

		img, err := remote.Image(imgRef, remoteOpts...)
		if err != nil {
			return nil, fmt.Errorf("pulling layer %s: %w", ref.Ref, err)
		}

		imgLayers, err := img.Layers()
		if err != nil {
			return nil, fmt.Errorf("getting layers from %s: %w", ref.Ref, err)
		}

		if len(imgLayers) != 1 {
			return nil, fmt.Errorf("expected 1 layer in %s, got %d", ref.Ref, len(imgLayers))
		}

		layers[i] = imgLayers[0]
		log.Debugf("pulled cached layer %s", ref.Key)
	}

	log.Infof("pulled %d layers from cache", len(layers))
	return layers, nil
}
