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
	"sync"
	"time"

	"github.com/chainguard-dev/clog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// ManagerGRPCClient implements the Manager interface by communicating with
// a remote Apko Manager service via gRPC.
type ManagerGRPCClient struct {
	conn   *grpc.ClientConn
	client ApkoManagerServiceClient
	config ManagerGRPCClientConfig

	// Circuit breaker state
	mu              sync.RWMutex
	failures        int
	lastFailure     time.Time
	circuitOpen     bool
	circuitOpenedAt time.Time

	// Cache for status responses (to avoid constant polling)
	statusCache      *ManagerStatus
	statusCacheTime  time.Time
	statusCacheTTL   time.Duration
	capacityCache    int
	cacheInitialized bool
}

// ManagerGRPCClientConfig configures the gRPC client.
type ManagerGRPCClientConfig struct {
	// Addr is the gRPC server address (e.g., "apko-manager:9091").
	Addr string

	// RequestTimeout is the timeout for each request attempt.
	// Default: 5 minutes (apko builds can take time)
	RequestTimeout time.Duration

	// MaxRetries is the maximum number of retry attempts.
	// Default: 3
	MaxRetries int

	// InitialBackoff is the initial backoff duration for retries.
	// Default: 100ms
	InitialBackoff time.Duration

	// MaxBackoff is the maximum backoff duration for retries.
	// Default: 10s
	MaxBackoff time.Duration

	// CircuitBreakerThreshold is the number of failures before opening the circuit.
	// Default: 5
	CircuitBreakerThreshold int

	// CircuitBreakerRecovery is the time to wait before trying to close the circuit.
	// Default: 30s
	CircuitBreakerRecovery time.Duration

	// StatusCacheTTL is how long to cache status/capacity.
	// Default: 5s
	StatusCacheTTL time.Duration
}

// DefaultManagerGRPCClientConfig returns a ManagerGRPCClientConfig with sensible defaults.
func DefaultManagerGRPCClientConfig(addr string) ManagerGRPCClientConfig {
	return ManagerGRPCClientConfig{
		Addr:                    addr,
		RequestTimeout:          5 * time.Minute,
		MaxRetries:              3,
		InitialBackoff:          100 * time.Millisecond,
		MaxBackoff:              10 * time.Second,
		CircuitBreakerThreshold: 5,
		CircuitBreakerRecovery:  30 * time.Second,
		StatusCacheTTL:          5 * time.Second,
	}
}

// NewManagerGRPCClient creates a new gRPC client for the Apko Manager service.
func NewManagerGRPCClient(ctx context.Context, cfg ManagerGRPCClientConfig) (*ManagerGRPCClient, error) {
	// Apply defaults
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 5 * time.Minute
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.InitialBackoff == 0 {
		cfg.InitialBackoff = 100 * time.Millisecond
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = 10 * time.Second
	}
	if cfg.CircuitBreakerThreshold == 0 {
		cfg.CircuitBreakerThreshold = 5
	}
	if cfg.CircuitBreakerRecovery == 0 {
		cfg.CircuitBreakerRecovery = 30 * time.Second
	}
	if cfg.StatusCacheTTL == 0 {
		cfg.StatusCacheTTL = 5 * time.Second
	}

	// Create gRPC connection
	conn, err := grpc.NewClient(cfg.Addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	)
	if err != nil {
		return nil, fmt.Errorf("creating gRPC connection: %w", err)
	}

	return &ManagerGRPCClient{
		conn:           conn,
		client:         NewApkoManagerServiceClient(conn),
		config:         cfg,
		statusCacheTTL: cfg.StatusCacheTTL,
	}, nil
}

// Request acquires an instance for the given build requirements.
// Implements the Manager interface.
func (c *ManagerGRPCClient) Request(ctx context.Context, req InstanceRequest) (*Instance, error) {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("apko-manager-client").Start(ctx, "Request")
	defer span.End()

	span.SetAttributes(
		attribute.String("job_id", req.JobID),
	)

	// Check circuit breaker
	if c.isCircuitOpen() {
		span.SetAttributes(attribute.Bool("circuit_open", true))
		return nil, fmt.Errorf("circuit breaker is open, apko manager unavailable")
	}

	// Convert to proto request
	protoReq := &RequestInstanceRequest{
		JobId:               req.JobID,
		EstimatedDurationMs: req.EstimatedDuration.Milliseconds(),
		Priority:            int32(req.Priority),
	}

	var lastErr error
	backoff := c.config.InitialBackoff

	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		if attempt > 0 {
			log.Infof("retrying Request (attempt %d/%d) after %s", attempt, c.config.MaxRetries, backoff)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > c.config.MaxBackoff {
				backoff = c.config.MaxBackoff
			}
		}

		resp, err := c.doRequest(ctx, protoReq)
		if err == nil {
			c.recordSuccess()

			// Convert proto response to Instance
			return &Instance{
				ID:            resp.Instance.Id,
				Addr:          resp.Instance.Addr,
				MaxConcurrent: int(resp.Instance.MaxConcurrent),
				AcquiredAt:    time.Unix(resp.Instance.AcquiredAtUnix, 0),
			}, nil
		}

		lastErr = err
		if !c.isRetryable(err) {
			c.recordFailure()
			span.RecordError(err)
			return nil, err
		}

		log.Warnf("Request attempt %d failed: %v", attempt+1, err)
	}

	c.recordFailure()
	span.RecordError(lastErr)
	return nil, fmt.Errorf("Request failed after %d attempts: %w", c.config.MaxRetries+1, lastErr)
}

func (c *ManagerGRPCClient) doRequest(ctx context.Context, req *RequestInstanceRequest) (*RequestInstanceResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.config.RequestTimeout)
	defer cancel()

	return c.client.RequestInstance(ctx, req)
}

// Release returns an instance to the manager and records the build result.
// Implements the Manager interface.
func (c *ManagerGRPCClient) Release(instance *Instance, result BuildResult) {
	ctx := context.Background()
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("apko-manager-client").Start(ctx, "Release")
	defer span.End()

	span.SetAttributes(
		attribute.String("instance_id", instance.ID),
		attribute.Bool("success", result.Success),
		attribute.Bool("cache_hit", result.CacheHit),
	)

	// Convert to proto request
	protoReq := &ReleaseInstanceRequest{
		InstanceId: instance.ID,
		Result: &BuildResultInfo{
			Success:    result.Success,
			DurationMs: result.Duration.Milliseconds(),
			Error:      result.Error,
			CacheHit:   result.CacheHit,
		},
	}

	ctx, cancel := context.WithTimeout(ctx, c.config.RequestTimeout)
	defer cancel()

	_, err := c.client.ReleaseInstance(ctx, protoReq)
	if err != nil {
		// Log but don't fail - the server will eventually clean up
		log.Warnf("failed to release instance %s: %v", instance.ID, err)
		span.RecordError(err)
	}
}

// Status returns current state of all instances for observability.
// Implements the Manager interface.
func (c *ManagerGRPCClient) Status() ManagerStatus {
	c.mu.RLock()
	if c.statusCache != nil && time.Since(c.statusCacheTime) < c.statusCacheTTL {
		status := *c.statusCache
		c.mu.RUnlock()
		return status
	}
	c.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), c.config.RequestTimeout)
	defer cancel()

	resp, err := c.client.GetStatus(ctx, &GetManagerStatusRequest{})
	if err != nil {
		// Return empty status on error
		return ManagerStatus{Type: "grpc-client-error"}
	}

	// Convert proto response to ManagerStatus
	managerStatus := ManagerStatus{
		Type:           resp.Status.Type,
		TotalInstances: int(resp.Status.TotalInstances),
		TotalCapacity:  int(resp.Status.TotalCapacity),
		ActiveBuilds:   int(resp.Status.ActiveBuilds),
		Instances:      make([]InstanceStatus, len(resp.Status.Instances)),
		CacheHits:      resp.Status.CacheHits,
		CacheMisses:    resp.Status.CacheMisses,
	}

	for i, inst := range resp.Status.Instances {
		var lastFailure time.Time
		if inst.LastFailureUnix > 0 {
			lastFailure = time.Unix(inst.LastFailureUnix, 0)
		}
		managerStatus.Instances[i] = InstanceStatus{
			ID:            inst.Id,
			Addr:          inst.Addr,
			ActiveBuilds:  int(inst.ActiveBuilds),
			MaxConcurrent: int(inst.MaxConcurrent),
			CircuitOpen:   inst.CircuitOpen,
			Failures:      int(inst.Failures),
			LastFailure:   lastFailure,
			CacheHits:     inst.CacheHits,
			CacheMisses:   inst.CacheMisses,
		}
	}

	// Cache the result
	c.mu.Lock()
	c.statusCache = &managerStatus
	c.statusCacheTime = time.Now()
	c.mu.Unlock()

	return managerStatus
}

// TotalCapacity returns the total build capacity across all instances.
// Implements the Manager interface.
func (c *ManagerGRPCClient) TotalCapacity() int {
	c.mu.RLock()
	if c.cacheInitialized {
		capacity := c.capacityCache
		c.mu.RUnlock()
		return capacity
	}
	c.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), c.config.RequestTimeout)
	defer cancel()

	resp, err := c.client.GetCapacity(ctx, &GetManagerCapacityRequest{})
	if err != nil {
		// Return default capacity on error
		return 1
	}

	c.mu.Lock()
	c.capacityCache = int(resp.TotalCapacity)
	c.cacheInitialized = true
	c.mu.Unlock()

	return int(resp.TotalCapacity)
}

// AvailableCapacity returns the currently available capacity.
// Implements the Manager interface.
func (c *ManagerGRPCClient) AvailableCapacity() int {
	ctx, cancel := context.WithTimeout(context.Background(), c.config.RequestTimeout)
	defer cancel()

	resp, err := c.client.GetCapacity(ctx, &GetManagerCapacityRequest{})
	if err != nil {
		return 0
	}

	return int(resp.AvailableCapacity)
}

// Close shuts down the client and releases resources.
// Implements the Manager interface.
func (c *ManagerGRPCClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// isRetryable returns true if the error is retryable.
func (c *ManagerGRPCClient) isRetryable(err error) bool {
	st, ok := status.FromError(err)
	if !ok {
		return false
	}

	switch st.Code() {
	case codes.Unavailable,
		codes.ResourceExhausted,
		codes.Aborted,
		codes.DeadlineExceeded:
		return true
	default:
		return false
	}
}

// isCircuitOpen returns true if the circuit breaker is open.
func (c *ManagerGRPCClient) isCircuitOpen() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.circuitOpen {
		return false
	}

	// Check if recovery period has passed
	if time.Since(c.circuitOpenedAt) > c.config.CircuitBreakerRecovery {
		return false // Allow a test request
	}

	return true
}

// recordSuccess records a successful request and potentially closes the circuit.
func (c *ManagerGRPCClient) recordSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.failures = 0
	c.circuitOpen = false
}

// recordFailure records a failed request and potentially opens the circuit.
func (c *ManagerGRPCClient) recordFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.failures++
	c.lastFailure = time.Now()

	if c.failures >= c.config.CircuitBreakerThreshold {
		c.circuitOpen = true
		c.circuitOpenedAt = time.Now()
	}
}

// Health checks the health of the Apko Manager service.
func (c *ManagerGRPCClient) Health(ctx context.Context) (*ManagerHealthResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return c.client.Health(ctx, &ManagerHealthRequest{})
}

// ManagerGRPCClientCircuitState represents the state of the circuit breaker.
type ManagerGRPCClientCircuitState struct {
	Open            bool          `json:"open"`
	Failures        int           `json:"failures"`
	LastFailure     time.Time     `json:"last_failure,omitempty"`
	OpenedAt        time.Time     `json:"opened_at,omitempty"`
	RecoveryTimeout time.Duration `json:"recovery_timeout"`
}

// GetCircuitState returns the current circuit breaker state.
func (c *ManagerGRPCClient) GetCircuitState() ManagerGRPCClientCircuitState {
	c.mu.RLock()
	defer c.mu.RUnlock()

	effectiveOpen := c.circuitOpen
	if c.circuitOpen && time.Since(c.circuitOpenedAt) > c.config.CircuitBreakerRecovery {
		effectiveOpen = false
	}

	return ManagerGRPCClientCircuitState{
		Open:            effectiveOpen,
		Failures:        c.failures,
		LastFailure:     c.lastFailure,
		OpenedAt:        c.circuitOpenedAt,
		RecoveryTimeout: c.config.CircuitBreakerRecovery,
	}
}

// ResetCircuit resets the circuit breaker state.
func (c *ManagerGRPCClient) ResetCircuit() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.failures = 0
	c.circuitOpen = false
	c.lastFailure = time.Time{}
	c.circuitOpenedAt = time.Time{}
}

// Verify ManagerGRPCClient implements Manager interface
var _ Manager = (*ManagerGRPCClient)(nil)
