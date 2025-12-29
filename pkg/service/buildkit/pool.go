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

	"gopkg.in/yaml.v3"
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
}

// PoolConfig is the configuration for a BuildKit pool.
type PoolConfig struct {
	Backends []Backend `json:"backends" yaml:"backends"`
}

// Pool manages a collection of BuildKit backends.
type Pool struct {
	backends []Backend
	mu       sync.RWMutex

	// Round-robin counters per architecture
	counters map[string]*atomic.Uint64
}

// NewPool creates a new BuildKit pool from the given backends.
func NewPool(backends []Backend) (*Pool, error) {
	if len(backends) == 0 {
		return nil, errors.New("at least one backend is required")
	}

	// Validate backends
	for i, b := range backends {
		if b.Addr == "" {
			return nil, fmt.Errorf("backend %d: addr is required", i)
		}
		if b.Arch == "" {
			return nil, fmt.Errorf("backend %d (%s): arch is required", i, b.Addr)
		}
	}

	// Initialize counters for each architecture
	counters := make(map[string]*atomic.Uint64)
	for _, b := range backends {
		if _, exists := counters[b.Arch]; !exists {
			counters[b.Arch] = &atomic.Uint64{}
		}
	}

	return &Pool{
		backends: backends,
		counters: counters,
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

	return NewPool(config.Backends)
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
// If multiple backends match, round-robin selection is used.
// Returns an error if no matching backend is found.
func (p *Pool) Select(arch string, selector map[string]string) (*Backend, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Find all matching backends
	matches := make([]Backend, 0, len(p.backends))
	for _, b := range p.backends {
		if b.Arch != arch {
			continue
		}
		if !matchesSelector(b.Labels, selector) {
			continue
		}
		matches = append(matches, b)
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("no backend found for arch=%s selector=%v", arch, selector)
	}

	// Round-robin selection
	counter := p.counters[arch]
	idx := counter.Add(1) - 1
	selected := matches[idx%uint64(len(matches))]

	return &selected, nil
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

	// Add the backend
	p.backends = append(p.backends, backend)

	// Initialize counter for new architecture if needed
	if _, exists := p.counters[backend.Arch]; !exists {
		p.counters[backend.Arch] = &atomic.Uint64{}
	}

	return nil
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
			return nil
		}
	}

	return fmt.Errorf("backend with addr %s not found", addr)
}
