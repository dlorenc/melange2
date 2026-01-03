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
	"time"
)

// Manager provides BuildKit workers for builds.
// This interface abstracts the backend management allowing for different
// implementations (static pool, Kubernetes autoscaling, cloud VMs, etc.).
//
// Phase 5 of microservices architecture: See issue #178 for design details.
type Manager interface {
	// Request acquires a worker for the given build requirements.
	// The returned Worker must be released when the build completes.
	Request(ctx context.Context, req WorkerRequest) (*Worker, error)

	// Release returns a worker to the manager and records the build result.
	// This must be called when a build completes (regardless of outcome).
	Release(worker *Worker, result BuildResult)

	// Status returns current state of all workers for observability.
	Status() ManagerStatus

	// TotalCapacity returns the total job capacity across all backends.
	// Used for configuring scheduler parallelism.
	TotalCapacity() int

	// Architectures returns a list of supported architectures.
	Architectures() []string

	// Close shuts down the manager and releases resources.
	Close() error
}

// WorkerRequest specifies requirements for acquiring a BuildKit worker.
type WorkerRequest struct {
	// Arch is the target architecture (e.g., "x86_64", "aarch64").
	// Required.
	Arch string

	// JobID is the identifier for this build job (for logging/tracing).
	JobID string

	// Selector is a label selector for filtering backends.
	// All specified labels must match.
	Selector map[string]string

	// Resources specifies estimated resource requirements for the build.
	// Used for binpacking and autoscaling decisions.
	Resources ResourceRequirements

	// Priority indicates the importance of this build (higher = more important).
	// Used for queue ordering when resources are constrained.
	Priority int
}

// ResourceRequirements specifies estimated resource needs for a build.
// These are hints used for binpacking and autoscaling decisions.
type ResourceRequirements struct {
	// MemoryMB is the estimated memory requirement in megabytes.
	MemoryMB int64

	// CPUCores is the estimated CPU requirement in cores.
	CPUCores float64

	// DiskGB is the estimated disk requirement in gigabytes.
	DiskGB int64

	// Timeout is the maximum duration for the build.
	Timeout time.Duration
}

// Worker represents an acquired BuildKit worker.
type Worker struct {
	// ID is a unique identifier for this worker instance.
	ID string

	// Addr is the BuildKit daemon address (e.g., "tcp://buildkit:1234").
	Addr string

	// Arch is the architecture this worker supports.
	Arch string

	// Labels are arbitrary key-value pairs for the worker.
	Labels map[string]string

	// AcquiredAt is when this worker was acquired.
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
}

// ManagerStatus represents the current state of the manager for observability.
type ManagerStatus struct {
	// Type is the manager implementation type (e.g., "static", "kubernetes").
	Type string

	// TotalWorkers is the total number of workers available.
	TotalWorkers int

	// AvailableWorkers is the number of workers currently available.
	AvailableWorkers int

	// ActiveJobs is the total number of jobs currently running.
	ActiveJobs int

	// Workers contains status for each individual worker.
	Workers []WorkerStatus
}

// WorkerStatus represents the current state of a single worker.
type WorkerStatus struct {
	// ID is the worker identifier.
	ID string

	// Addr is the BuildKit daemon address.
	Addr string

	// Arch is the worker's architecture.
	Arch string

	// Labels are the worker's labels.
	Labels map[string]string

	// ActiveJobs is the number of jobs currently running on this worker.
	ActiveJobs int

	// MaxJobs is the maximum concurrent jobs this worker can handle.
	MaxJobs int

	// CircuitOpen indicates if the circuit breaker is open (worker excluded).
	CircuitOpen bool

	// Failures is the number of consecutive failures.
	Failures int

	// LastFailure is the time of the last failure.
	LastFailure time.Time
}
