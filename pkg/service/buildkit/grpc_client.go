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

// GRPCClient implements the Manager interface by communicating with
// a remote BuildKit Manager service via gRPC.
type GRPCClient struct {
	conn   *grpc.ClientConn
	client BuildKitManagerServiceClient
	config GRPCClientConfig

	// Circuit breaker state
	mu              sync.RWMutex
	failures        int
	lastFailure     time.Time
	circuitOpen     bool
	circuitOpenedAt time.Time

	// Cache for status responses (to avoid constant polling)
	statusCache       *ManagerStatus
	statusCacheTime   time.Time
	statusCacheTTL    time.Duration
	architectureCache []string
	capacityCache     int
	cacheInitialized  bool
}

// GRPCClientConfig configures the gRPC client.
type GRPCClientConfig struct {
	// Addr is the gRPC server address (e.g., "buildkit-manager:9090").
	Addr string

	// RequestTimeout is the timeout for each request attempt.
	// Default: 30 seconds
	RequestTimeout time.Duration

	// MaxRetries is the maximum number of retry attempts.
	// Default: 3
	MaxRetries int

	// InitialBackoff is the initial backoff duration for retries.
	// Default: 100ms
	InitialBackoff time.Duration

	// MaxBackoff is the maximum backoff duration for retries.
	// Default: 5s
	MaxBackoff time.Duration

	// CircuitBreakerThreshold is the number of failures before opening the circuit.
	// Default: 5
	CircuitBreakerThreshold int

	// CircuitBreakerRecovery is the time to wait before trying to close the circuit.
	// Default: 30s
	CircuitBreakerRecovery time.Duration

	// StatusCacheTTL is how long to cache status/capacity/architectures.
	// Default: 5s
	StatusCacheTTL time.Duration
}

// DefaultGRPCClientConfig returns a GRPCClientConfig with sensible defaults.
func DefaultGRPCClientConfig(addr string) GRPCClientConfig {
	return GRPCClientConfig{
		Addr:                    addr,
		RequestTimeout:          30 * time.Second,
		MaxRetries:              3,
		InitialBackoff:          100 * time.Millisecond,
		MaxBackoff:              5 * time.Second,
		CircuitBreakerThreshold: 5,
		CircuitBreakerRecovery:  30 * time.Second,
		StatusCacheTTL:          5 * time.Second,
	}
}

// NewGRPCClient creates a new gRPC client for the BuildKit Manager service.
func NewGRPCClient(ctx context.Context, cfg GRPCClientConfig) (*GRPCClient, error) {
	// Apply defaults
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 30 * time.Second
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.InitialBackoff == 0 {
		cfg.InitialBackoff = 100 * time.Millisecond
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = 5 * time.Second
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

	return &GRPCClient{
		conn:           conn,
		client:         NewBuildKitManagerServiceClient(conn),
		config:         cfg,
		statusCacheTTL: cfg.StatusCacheTTL,
	}, nil
}

// Request acquires a worker for the given build requirements.
// Implements the Manager interface.
func (c *GRPCClient) Request(ctx context.Context, req WorkerRequest) (*Worker, error) {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("buildkit-manager-client").Start(ctx, "Request")
	defer span.End()

	span.SetAttributes(
		attribute.String("arch", req.Arch),
		attribute.String("job_id", req.JobID),
	)

	// Check circuit breaker
	if c.isCircuitOpen() {
		span.SetAttributes(attribute.Bool("circuit_open", true))
		return nil, fmt.Errorf("circuit breaker is open, buildkit manager unavailable")
	}

	// Convert to proto request
	protoReq := &RequestWorkerRequest{
		Arch:     req.Arch,
		JobId:    req.JobID,
		Selector: req.Selector,
		Priority: int32(req.Priority),
	}

	if req.Resources.MemoryMB != 0 || req.Resources.CPUCores != 0 ||
		req.Resources.DiskGB != 0 || req.Resources.Timeout != 0 {
		protoReq.Resources = &ResourceRequirementsInfo{
			MemoryMb:       req.Resources.MemoryMB,
			CpuCores:       req.Resources.CPUCores,
			DiskGb:         req.Resources.DiskGB,
			TimeoutSeconds: int64(req.Resources.Timeout.Seconds()),
		}
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

			// Convert proto response to Worker
			return &Worker{
				ID:         resp.Worker.Id,
				Addr:       resp.Worker.Addr,
				Arch:       resp.Worker.Arch,
				Labels:     resp.Worker.Labels,
				AcquiredAt: time.Unix(resp.Worker.AcquiredAtUnix, 0),
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

func (c *GRPCClient) doRequest(ctx context.Context, req *RequestWorkerRequest) (*RequestWorkerResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.config.RequestTimeout)
	defer cancel()

	return c.client.RequestWorker(ctx, req)
}

// Release returns a worker to the manager and records the build result.
// Implements the Manager interface.
func (c *GRPCClient) Release(worker *Worker, result BuildResult) {
	ctx := context.Background()
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("buildkit-manager-client").Start(ctx, "Release")
	defer span.End()

	span.SetAttributes(
		attribute.String("worker_id", worker.ID),
		attribute.Bool("success", result.Success),
	)

	// Convert to proto request
	protoReq := &ReleaseWorkerRequest{
		WorkerId: worker.ID,
		Result: &BuildResultInfo{
			Success:    result.Success,
			DurationMs: result.Duration.Milliseconds(),
			Error:      result.Error,
		},
	}

	ctx, cancel := context.WithTimeout(ctx, c.config.RequestTimeout)
	defer cancel()

	_, err := c.client.ReleaseWorker(ctx, protoReq)
	if err != nil {
		// Log but don't fail - the server will eventually clean up
		log.Warnf("failed to release worker %s: %v", worker.ID, err)
		span.RecordError(err)
	}
}

// Status returns current state of all workers for observability.
// Implements the Manager interface.
func (c *GRPCClient) Status() ManagerStatus {
	c.mu.RLock()
	if c.statusCache != nil && time.Since(c.statusCacheTime) < c.statusCacheTTL {
		status := *c.statusCache
		c.mu.RUnlock()
		return status
	}
	c.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), c.config.RequestTimeout)
	defer cancel()

	resp, err := c.client.GetStatus(ctx, &GetStatusRequest{})
	if err != nil {
		// Return empty status on error
		return ManagerStatus{Type: "grpc-client-error"}
	}

	// Convert proto response to ManagerStatus
	status := ManagerStatus{
		Type:             resp.Status.Type,
		TotalWorkers:     int(resp.Status.TotalWorkers),
		AvailableWorkers: int(resp.Status.AvailableWorkers),
		ActiveJobs:       int(resp.Status.ActiveJobs),
		Workers:          make([]WorkerStatus, len(resp.Status.Workers)),
	}

	for i, w := range resp.Status.Workers {
		var lastFailure time.Time
		if w.LastFailureUnix > 0 {
			lastFailure = time.Unix(w.LastFailureUnix, 0)
		}
		status.Workers[i] = WorkerStatus{
			ID:          w.Id,
			Addr:        w.Addr,
			Arch:        w.Arch,
			Labels:      w.Labels,
			ActiveJobs:  int(w.ActiveJobs),
			MaxJobs:     int(w.MaxJobs),
			CircuitOpen: w.CircuitOpen,
			Failures:    int(w.Failures),
			LastFailure: lastFailure,
		}
	}

	// Cache the result
	c.mu.Lock()
	c.statusCache = &status
	c.statusCacheTime = time.Now()
	c.mu.Unlock()

	return status
}

// TotalCapacity returns the total job capacity across all backends.
// Implements the Manager interface.
func (c *GRPCClient) TotalCapacity() int {
	c.mu.RLock()
	if c.cacheInitialized {
		capacity := c.capacityCache
		c.mu.RUnlock()
		return capacity
	}
	c.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), c.config.RequestTimeout)
	defer cancel()

	resp, err := c.client.GetCapacity(ctx, &GetCapacityRequest{})
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

// Architectures returns a list of supported architectures.
// Implements the Manager interface.
func (c *GRPCClient) Architectures() []string {
	c.mu.RLock()
	if c.cacheInitialized && len(c.architectureCache) > 0 {
		archs := make([]string, len(c.architectureCache))
		copy(archs, c.architectureCache)
		c.mu.RUnlock()
		return archs
	}
	c.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), c.config.RequestTimeout)
	defer cancel()

	resp, err := c.client.GetArchitectures(ctx, &GetArchitecturesRequest{})
	if err != nil {
		// Return empty list on error
		return []string{}
	}

	c.mu.Lock()
	c.architectureCache = resp.Architectures
	c.cacheInitialized = true
	c.mu.Unlock()

	return resp.Architectures
}

// Close shuts down the client and releases resources.
// Implements the Manager interface.
func (c *GRPCClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// isRetryable returns true if the error is retryable.
func (c *GRPCClient) isRetryable(err error) bool {
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
func (c *GRPCClient) isCircuitOpen() bool {
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
func (c *GRPCClient) recordSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.failures = 0
	c.circuitOpen = false
}

// recordFailure records a failed request and potentially opens the circuit.
func (c *GRPCClient) recordFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.failures++
	c.lastFailure = time.Now()

	if c.failures >= c.config.CircuitBreakerThreshold {
		c.circuitOpen = true
		c.circuitOpenedAt = time.Now()
	}
}

// Health checks the health of the BuildKit Manager service.
func (c *GRPCClient) Health(ctx context.Context) (*HealthResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return c.client.Health(ctx, &HealthRequest{})
}

// CircuitState represents the state of the circuit breaker.
type GRPCClientCircuitState struct {
	Open            bool          `json:"open"`
	Failures        int           `json:"failures"`
	LastFailure     time.Time     `json:"last_failure,omitempty"`
	OpenedAt        time.Time     `json:"opened_at,omitempty"`
	RecoveryTimeout time.Duration `json:"recovery_timeout"`
}

// GetCircuitState returns the current circuit breaker state.
func (c *GRPCClient) GetCircuitState() GRPCClientCircuitState {
	c.mu.RLock()
	defer c.mu.RUnlock()

	effectiveOpen := c.circuitOpen
	if c.circuitOpen && time.Since(c.circuitOpenedAt) > c.config.CircuitBreakerRecovery {
		effectiveOpen = false
	}

	return GRPCClientCircuitState{
		Open:            effectiveOpen,
		Failures:        c.failures,
		LastFailure:     c.lastFailure,
		OpenedAt:        c.circuitOpenedAt,
		RecoveryTimeout: c.config.CircuitBreakerRecovery,
	}
}

// ResetCircuit resets the circuit breaker state.
func (c *GRPCClient) ResetCircuit() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.failures = 0
	c.circuitOpen = false
	c.lastFailure = time.Time{}
	c.circuitOpenedAt = time.Time{}
}

// Verify GRPCClient implements Manager interface
var _ Manager = (*GRPCClient)(nil)
