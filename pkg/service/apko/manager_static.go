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
	"fmt"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// StaticManager manages a static pool of apko instances.
// This provides a simple implementation for Phase 7 that manages multiple
// apko-server instances without autoscaling.
//
// Phase 7 of microservices architecture: See issue #186 for design details.
type StaticManager struct {
	mu        sync.RWMutex
	instances []*instanceState

	// Circuit breaker configuration
	circuitBreakerThreshold int
	circuitBreakerRecovery  time.Duration
}

// instanceState tracks the state of an apko instance.
type instanceState struct {
	ID            string
	Addr          string
	MaxConcurrent int

	// Runtime state
	activeBuilds int
	circuitOpen  bool
	failures     int
	lastFailure  time.Time
	cacheHits    int64
	cacheMisses  int64
}

// InstanceConfig configures a single apko instance.
type InstanceConfig struct {
	// ID is an optional unique identifier. If empty, Addr is used.
	ID string `yaml:"id,omitempty"`

	// Addr is the gRPC address of the apko server.
	Addr string `yaml:"addr"`

	// MaxConcurrent is the maximum concurrent builds (default: 16).
	MaxConcurrent int `yaml:"max_concurrent,omitempty"`
}

// StaticManagerConfig configures the static manager.
type StaticManagerConfig struct {
	// Instances is the list of apko instances to manage.
	Instances []InstanceConfig `yaml:"instances"`

	// CircuitBreakerThreshold is failures before opening circuit (default: 5).
	CircuitBreakerThreshold int `yaml:"circuit_breaker_threshold,omitempty"`

	// CircuitBreakerRecovery is time before testing a failed instance (default: 30s).
	CircuitBreakerRecovery time.Duration `yaml:"circuit_breaker_recovery,omitempty"`
}

// NewStaticManager creates a new StaticManager from configuration.
func NewStaticManager(cfg StaticManagerConfig) (*StaticManager, error) {
	if len(cfg.Instances) == 0 {
		return nil, fmt.Errorf("at least one apko instance is required")
	}

	instances := make([]*instanceState, 0, len(cfg.Instances))
	for _, inst := range cfg.Instances {
		if inst.Addr == "" {
			return nil, fmt.Errorf("instance addr is required")
		}

		id := inst.ID
		if id == "" {
			id = inst.Addr
		}

		maxConcurrent := inst.MaxConcurrent
		if maxConcurrent <= 0 {
			maxConcurrent = 16
		}

		instances = append(instances, &instanceState{
			ID:            id,
			Addr:          inst.Addr,
			MaxConcurrent: maxConcurrent,
		})
	}

	threshold := cfg.CircuitBreakerThreshold
	if threshold <= 0 {
		threshold = 5
	}

	recovery := cfg.CircuitBreakerRecovery
	if recovery <= 0 {
		recovery = 30 * time.Second
	}

	return &StaticManager{
		instances:               instances,
		circuitBreakerThreshold: threshold,
		circuitBreakerRecovery:  recovery,
	}, nil
}

// NewStaticManagerFromConfigFile creates a StaticManager from a YAML config file.
func NewStaticManagerFromConfigFile(path string) (*StaticManager, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg StaticManagerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	return NewStaticManager(cfg)
}

// NewStaticManagerFromSingleAddr creates a StaticManager with a single instance.
func NewStaticManagerFromSingleAddr(addr string, maxConcurrent int) (*StaticManager, error) {
	if maxConcurrent <= 0 {
		maxConcurrent = 16
	}

	return NewStaticManager(StaticManagerConfig{
		Instances: []InstanceConfig{
			{Addr: addr, MaxConcurrent: maxConcurrent},
		},
	})
}

// Request acquires an instance matching the requirements.
func (m *StaticManager) Request(ctx context.Context, req InstanceRequest) (*Instance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find the best available instance (least loaded)
	var best *instanceState
	var bestLoad float64 = 2.0 // Start above 100% load

	for _, inst := range m.instances {
		// Skip instances with open circuits (unless recovery period passed)
		if inst.circuitOpen {
			if time.Since(inst.lastFailure) < m.circuitBreakerRecovery {
				continue
			}
			// Allow a test request after recovery period
		}

		// Skip fully loaded instances
		if inst.activeBuilds >= inst.MaxConcurrent {
			continue
		}

		// Calculate load ratio
		load := float64(inst.activeBuilds) / float64(inst.MaxConcurrent)
		if load < bestLoad {
			best = inst
			bestLoad = load
		}
	}

	if best == nil {
		return nil, fmt.Errorf("no apko instances available")
	}

	// Acquire the instance
	best.activeBuilds++

	return &Instance{
		ID:            best.ID,
		Addr:          best.Addr,
		MaxConcurrent: best.MaxConcurrent,
		AcquiredAt:    time.Now(),
	}, nil
}

// Release returns an instance to the manager and records the build result.
func (m *StaticManager) Release(instance *Instance, result BuildResult) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find the instance
	for _, inst := range m.instances {
		if inst.ID != instance.ID {
			continue
		}

		// Update active count
		if inst.activeBuilds > 0 {
			inst.activeBuilds--
		}

		// Update cache stats
		if result.CacheHit {
			inst.cacheHits++
		} else {
			inst.cacheMisses++
		}

		// Update circuit breaker state
		if result.Success {
			inst.failures = 0
			inst.circuitOpen = false
		} else {
			inst.failures++
			inst.lastFailure = time.Now()
			if inst.failures >= m.circuitBreakerThreshold {
				inst.circuitOpen = true
			}
		}

		return
	}
}

// Status returns current state of all instances for observability.
func (m *StaticManager) Status() ManagerStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	instances := make([]InstanceStatus, 0, len(m.instances))
	var totalCapacity, activeBuilds int
	var cacheHits, cacheMisses int64

	for _, inst := range m.instances {
		instances = append(instances, InstanceStatus{
			ID:            inst.ID,
			Addr:          inst.Addr,
			ActiveBuilds:  inst.activeBuilds,
			MaxConcurrent: inst.MaxConcurrent,
			CircuitOpen:   inst.circuitOpen,
			Failures:      inst.failures,
			LastFailure:   inst.lastFailure,
			CacheHits:     inst.cacheHits,
			CacheMisses:   inst.cacheMisses,
		})

		totalCapacity += inst.MaxConcurrent
		activeBuilds += inst.activeBuilds
		cacheHits += inst.cacheHits
		cacheMisses += inst.cacheMisses
	}

	return ManagerStatus{
		Type:           "static",
		TotalInstances: len(m.instances),
		TotalCapacity:  totalCapacity,
		ActiveBuilds:   activeBuilds,
		Instances:      instances,
		CacheHits:      cacheHits,
		CacheMisses:    cacheMisses,
	}
}

// TotalCapacity returns the total build capacity across all instances.
func (m *StaticManager) TotalCapacity() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var total int
	for _, inst := range m.instances {
		total += inst.MaxConcurrent
	}
	return total
}

// AvailableCapacity returns the currently available capacity.
func (m *StaticManager) AvailableCapacity() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var available int
	for _, inst := range m.instances {
		// Skip instances with open circuits
		if inst.circuitOpen && time.Since(inst.lastFailure) < m.circuitBreakerRecovery {
			continue
		}
		available += inst.MaxConcurrent - inst.activeBuilds
	}
	return available
}

// Close shuts down the manager. For StaticManager, this is a no-op.
func (m *StaticManager) Close() error {
	return nil
}

// Add adds a new apko instance to the pool.
func (m *StaticManager) Add(cfg InstanceConfig) error {
	if cfg.Addr == "" {
		return fmt.Errorf("instance addr is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := cfg.ID
	if id == "" {
		id = cfg.Addr
	}

	// Check for duplicates
	for _, inst := range m.instances {
		if inst.ID == id || inst.Addr == cfg.Addr {
			return fmt.Errorf("instance %s already exists", id)
		}
	}

	maxConcurrent := cfg.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 16
	}

	m.instances = append(m.instances, &instanceState{
		ID:            id,
		Addr:          cfg.Addr,
		MaxConcurrent: maxConcurrent,
	})

	return nil
}

// Remove removes an apko instance from the pool.
func (m *StaticManager) Remove(idOrAddr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, inst := range m.instances {
		if inst.ID == idOrAddr || inst.Addr == idOrAddr {
			m.instances = append(m.instances[:i], m.instances[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("instance %s not found", idOrAddr)
}

// List returns all instances in the pool.
func (m *StaticManager) List() []InstanceConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	configs := make([]InstanceConfig, 0, len(m.instances))
	for _, inst := range m.instances {
		configs = append(configs, InstanceConfig{
			ID:            inst.ID,
			Addr:          inst.Addr,
			MaxConcurrent: inst.MaxConcurrent,
		})
	}
	return configs
}

// Verify StaticManager implements Manager interface.
var _ Manager = (*StaticManager)(nil)
