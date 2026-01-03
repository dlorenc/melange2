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

package apko

import (
	"context"
	"time"
)

// Manager provides apko instances for builds.
// This interface abstracts the instance management allowing for different
// implementations (static pool, Kubernetes autoscaling, etc.).
//
// Phase 7 of microservices architecture: See issue #186 for design details.
type Manager interface {
	// Request acquires an instance for the given build requirements.
	// The returned Instance must be released when the build completes.
	Request(ctx context.Context, req InstanceRequest) (*Instance, error)

	// Release returns an instance to the manager and records the build result.
	// This must be called when a build completes (regardless of outcome).
	Release(instance *Instance, result BuildResult)

	// Status returns current state of all instances for observability.
	Status() ManagerStatus

	// TotalCapacity returns the total build capacity across all instances.
	// Used for configuring orchestrator parallelism.
	TotalCapacity() int

	// AvailableCapacity returns the currently available capacity.
	AvailableCapacity() int

	// Close shuts down the manager and releases resources.
	Close() error
}

// InstanceRequest specifies requirements for acquiring an apko instance.
type InstanceRequest struct {
	// JobID is the identifier for this build job (for logging/tracing).
	JobID string

	// EstimatedDuration is the estimated build duration.
	// Used for load balancing decisions.
	EstimatedDuration time.Duration

	// Priority indicates the importance of this build (higher = more important).
	// Used for queue ordering when resources are constrained.
	Priority int
}

// Instance represents an acquired apko instance.
type Instance struct {
	// ID is a unique identifier for this instance.
	ID string

	// Addr is the apko service gRPC address (e.g., "apko-server:9090").
	Addr string

	// MaxConcurrent is the maximum concurrent builds this instance supports.
	MaxConcurrent int

	// AcquiredAt is when this instance was acquired.
	AcquiredAt time.Time
}

// BuildResult records the outcome of a build for tracking and circuit breaking.
type BuildResult struct {
	// Success indicates whether the build completed successfully.
	Success bool

	// Duration is how long the build took.
	Duration time.Duration

	// Error is the error message if the build failed.
	Error string

	// CacheHit indicates whether the result was served from cache.
	CacheHit bool
}

// ManagerStatus represents the current state of the manager for observability.
type ManagerStatus struct {
	// Type is the manager implementation type (e.g., "static", "kubernetes").
	Type string

	// TotalInstances is the total number of apko instances available.
	TotalInstances int

	// TotalCapacity is the total concurrent build capacity across all instances.
	TotalCapacity int

	// ActiveBuilds is the total number of builds currently running.
	ActiveBuilds int

	// Instances contains status for each individual instance.
	Instances []InstanceStatus

	// CacheHits is the total number of cache hits across all instances.
	CacheHits int64

	// CacheMisses is the total number of cache misses across all instances.
	CacheMisses int64
}

// InstanceStatus represents the current state of a single apko instance.
type InstanceStatus struct {
	// ID is the instance identifier.
	ID string

	// Addr is the apko service gRPC address.
	Addr string

	// ActiveBuilds is the number of builds currently running on this instance.
	ActiveBuilds int

	// MaxConcurrent is the maximum concurrent builds this instance supports.
	MaxConcurrent int

	// CircuitOpen indicates if the circuit breaker is open (instance excluded).
	CircuitOpen bool

	// Failures is the number of consecutive failures.
	Failures int

	// LastFailure is the time of the last failure.
	LastFailure time.Time

	// CacheHits is the number of cache hits on this instance.
	CacheHits int64

	// CacheMisses is the number of cache misses on this instance.
	CacheMisses int64
}
