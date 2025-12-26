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
	"github.com/moby/buildkit/client/llb"
)

// CacheMount represents a cache mount configuration for BuildKit.
type CacheMount struct {
	// ID is a unique identifier for this cache mount.
	// Caches with the same ID are shared across builds.
	ID string

	// Target is the path where the cache will be mounted.
	Target string

	// Mode specifies the cache sharing mode.
	Mode llb.CacheMountSharingMode
}

// CacheMountOption returns the LLB run option for this cache mount.
func (c CacheMount) CacheMountOption() llb.RunOption {
	return llb.AddMount(c.Target, llb.Scratch(), llb.AsPersistentCacheDir(c.ID, c.Mode))
}

// CacheMountOptions returns LLB run options for multiple cache mounts.
func CacheMountOptions(mounts []CacheMount) []llb.RunOption {
	opts := make([]llb.RunOption, 0, len(mounts))
	for _, m := range mounts {
		opts = append(opts, m.CacheMountOption())
	}
	return opts
}

// Common cache mount IDs for package managers.
const (
	// GoModCacheID is the cache ID for Go module cache.
	GoModCacheID = "melange-go-mod-cache"

	// GoBuildCacheID is the cache ID for Go build cache.
	GoBuildCacheID = "melange-go-build-cache"

	// PipCacheID is the cache ID for pip cache.
	PipCacheID = "melange-pip-cache"

	// NpmCacheID is the cache ID for npm cache.
	NpmCacheID = "melange-npm-cache"

	// CargoRegistryCacheID is the cache ID for Cargo registry cache.
	CargoRegistryCacheID = "melange-cargo-registry-cache"

	// CargoBuildCacheID is the cache ID for Cargo build cache.
	CargoBuildCacheID = "melange-cargo-build-cache"

	// CcacheCacheID is the cache ID for ccache.
	CcacheCacheID = "melange-ccache-cache"

	// ApkCacheID is the cache ID for APK package cache.
	ApkCacheID = "melange-apk-cache"
)

// DefaultCacheMounts returns the default set of cache mounts for common
// package managers and build tools. These use shared mode so multiple
// builds can read from the cache concurrently.
func DefaultCacheMounts() []CacheMount {
	return []CacheMount{
		// Go caches
		{
			ID:     GoModCacheID,
			Target: "/go/pkg/mod",
			Mode:   llb.CacheMountShared,
		},
		{
			ID:     GoBuildCacheID,
			Target: "/root/.cache/go-build",
			Mode:   llb.CacheMountShared,
		},

		// Python pip cache
		{
			ID:     PipCacheID,
			Target: "/root/.cache/pip",
			Mode:   llb.CacheMountShared,
		},

		// Node.js npm cache
		{
			ID:     NpmCacheID,
			Target: "/root/.npm",
			Mode:   llb.CacheMountShared,
		},

		// Rust Cargo caches
		{
			ID:     CargoRegistryCacheID,
			Target: "/root/.cargo/registry",
			Mode:   llb.CacheMountShared,
		},
		{
			ID:     CargoBuildCacheID,
			Target: "/root/.cargo/git",
			Mode:   llb.CacheMountShared,
		},

		// C/C++ ccache
		{
			ID:     CcacheCacheID,
			Target: "/root/.ccache",
			Mode:   llb.CacheMountShared,
		},

		// APK package cache
		{
			ID:     ApkCacheID,
			Target: "/var/cache/apk",
			Mode:   llb.CacheMountShared,
		},
	}
}

// GoCacheMounts returns cache mounts optimized for Go builds.
func GoCacheMounts() []CacheMount {
	return []CacheMount{
		{
			ID:     GoModCacheID,
			Target: "/go/pkg/mod",
			Mode:   llb.CacheMountShared,
		},
		{
			ID:     GoBuildCacheID,
			Target: "/root/.cache/go-build",
			Mode:   llb.CacheMountShared,
		},
	}
}

// PythonCacheMounts returns cache mounts optimized for Python builds.
func PythonCacheMounts() []CacheMount {
	return []CacheMount{
		{
			ID:     PipCacheID,
			Target: "/root/.cache/pip",
			Mode:   llb.CacheMountShared,
		},
	}
}

// RustCacheMounts returns cache mounts optimized for Rust builds.
func RustCacheMounts() []CacheMount {
	return []CacheMount{
		{
			ID:     CargoRegistryCacheID,
			Target: "/root/.cargo/registry",
			Mode:   llb.CacheMountShared,
		},
		{
			ID:     CargoBuildCacheID,
			Target: "/root/.cargo/git",
			Mode:   llb.CacheMountShared,
		},
	}
}

// NodeCacheMounts returns cache mounts optimized for Node.js builds.
func NodeCacheMounts() []CacheMount {
	return []CacheMount{
		{
			ID:     NpmCacheID,
			Target: "/root/.npm",
			Mode:   llb.CacheMountShared,
		},
	}
}

// CCacheMounts returns cache mounts for C/C++ builds using ccache.
func CCacheMounts() []CacheMount {
	return []CacheMount{
		{
			ID:     CcacheCacheID,
			Target: "/root/.ccache",
			Mode:   llb.CacheMountShared,
		},
	}
}
