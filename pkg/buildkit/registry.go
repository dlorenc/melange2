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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// ApkoImageCache caches apko-generated base images in a registry.
// This significantly speeds up builds by allowing BuildKit to use
// llb.Image() instead of llb.Local(), enabling native layer caching.
type ApkoImageCache struct {
	// Registry is the base registry URL for cached images.
	// Example: "registry:5000/apko-cache"
	Registry string

	// Insecure allows connecting to registries over HTTP.
	Insecure bool
}

// NewApkoImageCache creates a new ApkoImageCache.
func NewApkoImageCache(registry string, insecure bool) *ApkoImageCache {
	return &ApkoImageCache{
		Registry: registry,
		Insecure: insecure,
	}
}

// GetOrCreate returns the image reference for the given config and layers.
// If an image with the same configuration already exists in the registry,
// it returns the existing reference (cache hit). Otherwise, it pushes
// the layers as a new image and returns the new reference.
//
// The cache key is derived from the image configuration, so builds with
// identical environment configurations will share the same base image.
func (c *ApkoImageCache) GetOrCreate(ctx context.Context, imgConfig apko_types.ImageConfiguration, layers []v1.Layer) (string, bool, error) {
	log := clog.FromContext(ctx)

	// Hash the config to create a unique tag
	tag := c.hashConfig(imgConfig)
	ref := fmt.Sprintf("%s:%s", c.Registry, tag)

	// Parse the reference
	opts := []name.Option{}
	if c.Insecure {
		opts = append(opts, name.Insecure)
	}
	imgRef, err := name.ParseReference(ref, opts...)
	if err != nil {
		return "", false, fmt.Errorf("parsing ref %q: %w", ref, err)
	}

	// Build remote options
	remoteOpts := []remote.Option{remote.WithContext(ctx)}
	if c.Insecure {
		remoteOpts = append(remoteOpts, remote.WithTransport(&http.Transport{}))
	}

	// Check if image already exists
	if _, err := remote.Head(imgRef, remoteOpts...); err == nil {
		log.Infof("apko image cache hit: %s", ref)
		return ref, true, nil
	} else if !isNotFound(err) {
		// Log the error but continue to push - might be a transient issue
		log.Warnf("error checking for cached image %s: %v", ref, err)
	}

	log.Infof("apko image cache miss, pushing to %s", ref)
	pushStart := time.Now()

	// Build the image from layers
	// IMPORTANT: Use AppendLayers with all layers at once to avoid O(n²) memory
	// usage from nested lazy wrappers. Each individual AppendLayers call creates
	// a wrapper that triggers recursive compute() when the image is pushed.
	img, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		return "", false, fmt.Errorf("appending %d layers: %w", len(layers), err)
	}

	// Push the image
	if err := remote.Write(imgRef, img, remoteOpts...); err != nil {
		return "", false, fmt.Errorf("pushing image to %s: %w", ref, err)
	}

	pushDuration := time.Since(pushStart)
	log.Infof("apko_image_push took %s (%d layers)", pushDuration, len(layers))

	return ref, false, nil
}

// hashConfig creates a deterministic hash of the image configuration.
// This is used as the image tag to enable cache hits for identical configs.
func (c *ApkoImageCache) hashConfig(cfg apko_types.ImageConfiguration) string {
	// Create a normalized version of the config for hashing
	// We only hash the fields that affect the base image content
	hashInput := struct {
		Contents apko_types.ImageContents `json:"contents"`
		Archs    []apko_types.Architecture `json:"archs"`
		Layering *apko_types.Layering      `json:"layering,omitempty"`
	}{
		Contents: cfg.Contents,
		Archs:    cfg.Archs,
		Layering: cfg.Layering,
	}

	data, err := json.Marshal(hashInput)
	if err != nil {
		// Fallback to full config if marshaling fails
		data, _ = json.Marshal(cfg)
	}

	hash := sha256.Sum256(data)
	// Use first 16 chars of hex for readability while maintaining uniqueness
	return hex.EncodeToString(hash[:])[:16]
}

// isNotFound checks if an error indicates the image was not found.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	// Check for transport error with 404 status
	var terr *transport.Error
	if errors.As(err, &terr) {
		return terr.StatusCode == http.StatusNotFound
	}
	return false
}
