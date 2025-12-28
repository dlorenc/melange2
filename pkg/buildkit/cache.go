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
// All paths use /home/build instead of /root to support running as the
// build user (UID 1000).
func DefaultCacheMounts() []CacheMount {
	return []CacheMount{
		// Go caches - use /home/build paths to match build user's home
		{
			ID:     GoModCacheID,
			Target: "/home/build/go/pkg/mod",
			Mode:   llb.CacheMountShared,
		},
		{
			ID:     GoBuildCacheID,
			Target: "/home/build/.cache/go-build",
			Mode:   llb.CacheMountShared,
		},

		// Python pip cache
		{
			ID:     PipCacheID,
			Target: "/home/build/.cache/pip",
			Mode:   llb.CacheMountShared,
		},

		// Node.js npm cache
		{
			ID:     NpmCacheID,
			Target: "/home/build/.npm",
			Mode:   llb.CacheMountShared,
		},

		// Rust Cargo caches
		{
			ID:     CargoRegistryCacheID,
			Target: "/home/build/.cargo/registry",
			Mode:   llb.CacheMountShared,
		},
		{
			ID:     CargoBuildCacheID,
			Target: "/home/build/.cargo/git",
			Mode:   llb.CacheMountShared,
		},

		// C/C++ ccache
		{
			ID:     CcacheCacheID,
			Target: "/home/build/.ccache",
			Mode:   llb.CacheMountShared,
		},

		// APK package cache - system path, but cache mounts handle permissions
		{
			ID:     ApkCacheID,
			Target: "/var/cache/apk",
			Mode:   llb.CacheMountShared,
		},
	}
}

// GoCacheMounts returns cache mounts optimized for Go builds.
// Uses /home/build paths to support running as the build user.
func GoCacheMounts() []CacheMount {
	return []CacheMount{
		{
			ID:     GoModCacheID,
			Target: "/home/build/go/pkg/mod",
			Mode:   llb.CacheMountShared,
		},
		{
			ID:     GoBuildCacheID,
			Target: "/home/build/.cache/go-build",
			Mode:   llb.CacheMountShared,
		},
	}
}

// PythonCacheMounts returns cache mounts optimized for Python builds.
// Uses /home/build paths to support running as the build user.
func PythonCacheMounts() []CacheMount {
	return []CacheMount{
		{
			ID:     PipCacheID,
			Target: "/home/build/.cache/pip",
			Mode:   llb.CacheMountShared,
		},
	}
}

// RustCacheMounts returns cache mounts optimized for Rust builds.
// Uses /home/build paths to support running as the build user.
func RustCacheMounts() []CacheMount {
	return []CacheMount{
		{
			ID:     CargoRegistryCacheID,
			Target: "/home/build/.cargo/registry",
			Mode:   llb.CacheMountShared,
		},
		{
			ID:     CargoBuildCacheID,
			Target: "/home/build/.cargo/git",
			Mode:   llb.CacheMountShared,
		},
	}
}

// NodeCacheMounts returns cache mounts optimized for Node.js builds.
// Uses /home/build paths to support running as the build user.
func NodeCacheMounts() []CacheMount {
	return []CacheMount{
		{
			ID:     NpmCacheID,
			Target: "/home/build/.npm",
			Mode:   llb.CacheMountShared,
		},
	}
}

// CCacheMounts returns cache mounts for C/C++ builds using ccache.
// Uses /home/build paths to support running as the build user.
func CCacheMounts() []CacheMount {
	return []CacheMount{
		{
			ID:     CcacheCacheID,
			Target: "/home/build/.ccache",
			Mode:   llb.CacheMountShared,
		},
	}
}

// CacheEnvironment returns environment variables that configure tools
// to use the cache mount paths. These should be set in the build environment
// to ensure tools write to the correct cache locations.
func CacheEnvironment() map[string]string {
	return map[string]string{
		// Go cache configuration
		"GOMODCACHE": "/home/build/go/pkg/mod",
		"GOCACHE":    "/home/build/.cache/go-build",
		"GOPATH":     "/home/build/go",

		// Python pip cache
		"PIP_CACHE_DIR": "/home/build/.cache/pip",

		// npm cache
		"NPM_CONFIG_CACHE": "/home/build/.npm",

		// Cargo/Rust cache
		"CARGO_HOME": "/home/build/.cargo",

		// ccache
		"CCACHE_DIR": "/home/build/.ccache",
	}
}
