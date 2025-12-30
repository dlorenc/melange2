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

// Package buildkit provides BuildKit backend pool management.
package buildkit

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// Default configuration values.
const (
	DefaultMaxJobs         = 4
	DefaultFailureThreshold = 3
	DefaultRecoveryTimeout  = 30 * time.Second
)

// Errors returned by pool operations.
var (
	ErrNoAvailableBackend = errors.New("no available backend: all backends are at capacity or circuit-open")
	ErrBackendAtCapacity  = errors.New("backend is at capacity")
	ErrBackendNotFound    = errors.New("backend not found")
)

// Backend represents a BuildKit backend instance.
type Backend struct {
	// Addr is the BuildKit daemon address (e.g., "tcp://buildkit:1234").
	Addr string `json:"addr" yaml:"addr"`

	// Arch is the architecture this backend supports (e.g., "x86_64", "aarch64").
	Arch string `json:"arch" yaml:"arch"`

	// Labels are arbitrary key-value pairs for backend selection.
	// Examples: tier=high-memory, sandbox=privileged
	Labels map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`

	// MaxJobs is the maximum number of concurrent jobs this backend can handle.
	// If 0, the pool's DefaultMaxJobs is used.
	MaxJobs int `json:"maxJobs,omitempty" yaml:"maxJobs,omitempty"`
}

// backendState tracks runtime state for a backend (not serialized).
type backendState struct {
	// activeJobs is the current number of jobs running on this backend.
	activeJobs atomic.Int32

	// failures is the number of consecutive failures.
	failures atomic.Int32

	// lastFailure is the time of the last failure.
	lastFailure time.Time

	// circuitOpen is true if the circuit breaker is open (backend excluded).
	circuitOpen atomic.Bool

	// mu protects lastFailure
	mu sync.Mutex
}

// BackendStatus represents the current status of a backend for observability.
type BackendStatus struct {
	Backend
	ActiveJobs  int       `json:"activeJobs"`
	Failures    int       `json:"failures"`
	CircuitOpen bool      `json:"circuitOpen"`
	LastFailure time.Time `json:"lastFailure,omitempty"`
}

// PoolConfig is the configuration for a BuildKit pool.
type PoolConfig struct {
	Backends []Backend `json:"backends" yaml:"backends"`

	// DefaultMaxJobs is the default maximum concurrent jobs per backend.
	// Used when a backend's MaxJobs is 0. Defaults to DefaultMaxJobs constant.
	DefaultMaxJobs int `json:"defaultMaxJobs,omitempty" yaml:"defaultMaxJobs,omitempty"`

	// FailureThreshold is the number of consecutive failures before opening the circuit.
	// Defaults to DefaultFailureThreshold constant.
	FailureThreshold int `json:"failureThreshold,omitempty" yaml:"failureThreshold,omitempty"`

	// RecoveryTimeout is how long the circuit stays open before allowing a retry.
	// Defaults to DefaultRecoveryTimeout constant.
	RecoveryTimeout time.Duration `json:"recoveryTimeout,omitempty" yaml:"recoveryTimeout,omitempty"`
}

// Pool manages a collection of BuildKit backends.
type Pool struct {
	backends []Backend
	state    map[string]*backendState // keyed by Addr
	mu       sync.RWMutex

	// Configuration
	defaultMaxJobs   int
	failureThreshold int
	recoveryTimeout  time.Duration
}

// NewPool creates a new BuildKit pool from the given backends with default configuration.
func NewPool(backends []Backend) (*Pool, error) {
	return NewPoolWithConfig(PoolConfig{Backends: backends})
}

// NewPoolWithConfig creates a new BuildKit pool from a configuration.
func NewPoolWithConfig(config PoolConfig) (*Pool, error) {
	if len(config.Backends) == 0 {
		return nil, errors.New("at least one backend is required")
	}

	// Validate backends
	for i, b := range config.Backends {
		if b.Addr == "" {
			return nil, fmt.Errorf("backend %d: addr is required", i)
		}
		if b.Arch == "" {
			return nil, fmt.Errorf("backend %d (%s): arch is required", i, b.Addr)
		}
	}

	// Apply defaults
	defaultMaxJobs := config.DefaultMaxJobs
	if defaultMaxJobs == 0 {
		defaultMaxJobs = DefaultMaxJobs
	}
	failureThreshold := config.FailureThreshold
	if failureThreshold == 0 {
		failureThreshold = DefaultFailureThreshold
	}
	recoveryTimeout := config.RecoveryTimeout
	if recoveryTimeout == 0 {
		recoveryTimeout = DefaultRecoveryTimeout
	}

	// Initialize state for each backend
	state := make(map[string]*backendState)
	for _, b := range config.Backends {
		state[b.Addr] = &backendState{}
	}

	return &Pool{
		backends:         config.Backends,
		state:            state,
		defaultMaxJobs:   defaultMaxJobs,
		failureThreshold: failureThreshold,
		recoveryTimeout:  recoveryTimeout,
	}, nil
}

// NewPoolFromConfig creates a pool from a YAML config file.
func NewPoolFromConfig(configPath string) (*Pool, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var config PoolConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	return NewPoolWithConfig(config)
}

// NewPoolFromSingleAddr creates a pool with a single backend for backward compatibility.
// The architecture defaults to "x86_64" if not specified.
func NewPoolFromSingleAddr(addr, arch string) (*Pool, error) {
	if arch == "" {
		arch = "x86_64"
	}
	return NewPool([]Backend{
		{
			Addr:   addr,
			Arch:   arch,
			Labels: map[string]string{},
		},
	})
}

// Select chooses a backend matching the given architecture and selector.
// It uses load-aware selection, picking the least-loaded available backend.
// Backends with open circuits or at capacity are excluded.
// Returns ErrNoAvailableBackend if all matching backends are unavailable.
func (p *Pool) Select(arch string, selector map[string]string) (*Backend, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var best *Backend
	var bestLoad float64 = 2.0 // Start higher than max possible (1.0)

	now := time.Now()

	for i := range p.backends {
		b := &p.backends[i]

		// Filter by architecture
		if b.Arch != arch {
			continue
		}

		// Filter by labels
		if !matchesSelector(b.Labels, selector) {
			continue
		}

		state := p.state[b.Addr]
		if state == nil {
			continue
		}

		// Check circuit breaker
		if state.circuitOpen.Load() {
			state.mu.Lock()
			lastFailure := state.lastFailure
			state.mu.Unlock()

			if now.Sub(lastFailure) < p.recoveryTimeout {
				// Circuit still open, skip this backend
				continue
			}
			// Recovery timeout passed, allow one attempt (half-open state)
			// The circuit will be reset on success or stay open on failure
		}

		// Get max jobs for this backend
		maxJobs := b.MaxJobs
		if maxJobs == 0 {
			maxJobs = p.defaultMaxJobs
		}

		// Check capacity
		active := int(state.activeJobs.Load())
		if active >= maxJobs {
			continue // At capacity
		}

		// Calculate load ratio
		load := float64(active) / float64(maxJobs)
		if best == nil || load < bestLoad {
			best = b
			bestLoad = load
		}
	}

	if best == nil {
		return nil, ErrNoAvailableBackend
	}

	// Return a copy to avoid mutation
	result := *best
	return &result, nil
}

// SelectAndAcquire atomically selects a backend and acquires a slot.
// This eliminates the race condition between Select() and Acquire().
// Returns the backend if successful, or an error if no backend is available.
func (p *Pool) SelectAndAcquire(arch string, selector map[string]string) (*Backend, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	now := time.Now()

	// Try backends in load order, attempting to acquire atomically
	type candidate struct {
		backend *Backend
		state   *backendState
		maxJobs int
		load    float64
	}

	candidates := make([]candidate, 0, len(p.backends))

	for i := range p.backends {
		b := &p.backends[i]

		// Filter by architecture
		if b.Arch != arch {
			continue
		}

		// Filter by labels
		if !matchesSelector(b.Labels, selector) {
			continue
		}

		state := p.state[b.Addr]
		if state == nil {
			continue
		}

		// Check circuit breaker
		if state.circuitOpen.Load() {
			state.mu.Lock()
			lastFailure := state.lastFailure
			state.mu.Unlock()

			if now.Sub(lastFailure) < p.recoveryTimeout {
				continue
			}
		}

		maxJobs := b.MaxJobs
		if maxJobs == 0 {
			maxJobs = p.defaultMaxJobs
		}

		active := int(state.activeJobs.Load())
		if active >= maxJobs {
			continue
		}

		load := float64(active) / float64(maxJobs)
		candidates = append(candidates, candidate{
			backend: b,
			state:   state,
			maxJobs: maxJobs,
			load:    load,
		})
	}

	// Sort by load (least loaded first) and try to acquire
	for len(candidates) > 0 {
		// Find the least loaded candidate
		bestIdx := 0
		for i := 1; i < len(candidates); i++ {
			if candidates[i].load < candidates[bestIdx].load {
				bestIdx = i
			}
		}

		c := candidates[bestIdx]

		// Try to atomically acquire a slot
		for {
			current := c.state.activeJobs.Load()
			if int(current) >= c.maxJobs {
				// Backend filled up, remove from candidates and try next
				break
			}
			if c.state.activeJobs.CompareAndSwap(current, current+1) {
				// Successfully acquired
				result := *c.backend
				return &result, nil
			}
			// CAS failed, retry
		}

		// Remove this candidate and try the next one
		candidates = append(candidates[:bestIdx], candidates[bestIdx+1:]...)
	}

	return nil, ErrNoAvailableBackend
}

// Acquire increments the active job count for a backend.
// Returns true if a slot was acquired, false if the backend is at capacity.
// Deprecated: Use SelectAndAcquire() instead to avoid race conditions.
func (p *Pool) Acquire(addr string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	state := p.state[addr]
	if state == nil {
		return false
	}

	// Find the backend to get maxJobs
	var maxJobs int
	for i := range p.backends {
		if p.backends[i].Addr == addr {
			maxJobs = p.backends[i].MaxJobs
			break
		}
	}
	if maxJobs == 0 {
		maxJobs = p.defaultMaxJobs
	}

	// CAS loop to atomically increment if under capacity
	for {
		current := state.activeJobs.Load()
		if int(current) >= maxJobs {
			return false
		}
		if state.activeJobs.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

// Release decrements the active job count and records success/failure.
// This should be called when a job completes (regardless of outcome).
func (p *Pool) Release(addr string, success bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	state := p.state[addr]
	if state == nil {
		return
	}

	// Decrement active jobs
	state.activeJobs.Add(-1)

	if success {
		// Reset failure count on success
		state.failures.Store(0)
		// Close circuit if it was open (half-open -> closed)
		state.circuitOpen.Store(false)
	} else {
		// Increment failure count
		failures := state.failures.Add(1)

		// Update last failure time
		state.mu.Lock()
		state.lastFailure = time.Now()
		state.mu.Unlock()

		// Open circuit if threshold reached
		if int(failures) >= p.failureThreshold {
			state.circuitOpen.Store(true)
		}
	}
}

// matchesSelector checks if the backend labels match all selector requirements.
func matchesSelector(labels, selector map[string]string) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// List returns all backends in the pool.
func (p *Pool) List() []Backend {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]Backend, len(p.backends))
	copy(result, p.backends)
	return result
}

// ListByArch returns all backends for the given architecture.
func (p *Pool) ListByArch(arch string) []Backend {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var result []Backend
	for _, b := range p.backends {
		if b.Arch == arch {
			result = append(result, b)
		}
	}
	return result
}

// Architectures returns a list of unique architectures supported by the pool.
func (p *Pool) Architectures() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	seen := make(map[string]bool)
	var archs []string
	for _, b := range p.backends {
		if !seen[b.Arch] {
			seen[b.Arch] = true
			archs = append(archs, b.Arch)
		}
	}
	return archs
}

// Status returns the current status of all backends for observability.
func (p *Pool) Status() []BackendStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := make([]BackendStatus, 0, len(p.backends))
	for _, b := range p.backends {
		status := BackendStatus{
			Backend: b,
		}

		if state := p.state[b.Addr]; state != nil {
			status.ActiveJobs = int(state.activeJobs.Load())
			status.Failures = int(state.failures.Load())
			status.CircuitOpen = state.circuitOpen.Load()

			state.mu.Lock()
			status.LastFailure = state.lastFailure
			state.mu.Unlock()
		}

		result = append(result, status)
	}
	return result
}

// Add adds a new backend to the pool.
// Returns an error if the backend is invalid or already exists.
func (p *Pool) Add(backend Backend) error {
	if backend.Addr == "" {
		return errors.New("addr is required")
	}
	if backend.Arch == "" {
		return errors.New("arch is required")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Check for duplicates
	for _, b := range p.backends {
		if b.Addr == backend.Addr {
			return fmt.Errorf("backend with addr %s already exists", backend.Addr)
		}
	}

	// Initialize labels if nil
	if backend.Labels == nil {
		backend.Labels = map[string]string{}
	}

	// Add the backend and initialize its state
	p.backends = append(p.backends, backend)
	p.state[backend.Addr] = &backendState{}

	return nil
}

// TotalCapacity returns the total job capacity across all backends.
// This is useful for configuring scheduler parallelism.
func (p *Pool) TotalCapacity() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	total := 0
	for _, b := range p.backends {
		maxJobs := b.MaxJobs
		if maxJobs == 0 {
			maxJobs = p.defaultMaxJobs
		}
		total += maxJobs
	}
	return total
}

// Remove removes a backend from the pool by its address.
// Returns an error if the backend is not found or if it's the last backend.
func (p *Pool) Remove(addr string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.backends) == 1 {
		return errors.New("cannot remove the last backend")
	}

	// Find and remove the backend
	for i, b := range p.backends {
		if b.Addr == addr {
			p.backends = append(p.backends[:i], p.backends[i+1:]...)
			delete(p.state, addr)
			return nil
		}
	}

	return fmt.Errorf("backend with addr %s not found", addr)
}
