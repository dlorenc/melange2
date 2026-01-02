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

// Client is a gRPC client for the ApkoService with retry and circuit breaker.
type Client struct {
	conn   *grpc.ClientConn
	client ApkoServiceClient
	config ClientConfig

	// Circuit breaker state
	mu              sync.RWMutex
	failures        int
	lastFailure     time.Time
	circuitOpen     bool
	circuitOpenedAt time.Time
}

// ClientConfig configures the apko client.
type ClientConfig struct {
	// Addr is the gRPC server address.
	Addr string

	// RequestTimeout is the timeout for each request attempt.
	// Default: 5 minutes
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
}

// DefaultClientConfig returns a ClientConfig with sensible defaults.
func DefaultClientConfig(addr string) ClientConfig {
	return ClientConfig{
		Addr:                    addr,
		RequestTimeout:          5 * time.Minute,
		MaxRetries:              3,
		InitialBackoff:          100 * time.Millisecond,
		MaxBackoff:              10 * time.Second,
		CircuitBreakerThreshold: 5,
		CircuitBreakerRecovery:  30 * time.Second,
	}
}

// NewClient creates a new apko gRPC client.
func NewClient(ctx context.Context, cfg ClientConfig) (*Client, error) {
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

	// Create gRPC connection
	conn, err := grpc.NewClient(cfg.Addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	)
	if err != nil {
		return nil, fmt.Errorf("creating gRPC connection: %w", err)
	}

	return &Client{
		conn:   conn,
		client: NewApkoServiceClient(conn),
		config: cfg,
	}, nil
}

// Close closes the client connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// BuildLayers calls the BuildLayers RPC with retry and circuit breaker.
func (c *Client) BuildLayers(ctx context.Context, req *BuildLayersRequest) (*BuildLayersResponse, error) {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("apko-client").Start(ctx, "BuildLayers")
	defer span.End()

	span.SetAttributes(
		attribute.String("arch", req.Arch),
		attribute.String("request_id", req.RequestId),
	)

	// Check circuit breaker
	if c.isCircuitOpen() {
		span.SetAttributes(attribute.Bool("circuit_open", true))
		return nil, fmt.Errorf("circuit breaker is open, apko service unavailable")
	}

	var lastErr error
	backoff := c.config.InitialBackoff

	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		if attempt > 0 {
			log.Infof("retrying BuildLayers (attempt %d/%d) after %s", attempt, c.config.MaxRetries, backoff)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			// Exponential backoff with cap
			backoff *= 2
			if backoff > c.config.MaxBackoff {
				backoff = c.config.MaxBackoff
			}
		}

		resp, err := c.doRequest(ctx, req)
		if err == nil {
			c.recordSuccess()
			return resp, nil
		}

		lastErr = err
		if !c.isRetryable(err) {
			c.recordFailure()
			span.RecordError(err)
			return nil, err
		}

		log.Warnf("BuildLayers attempt %d failed: %v", attempt+1, err)
	}

	c.recordFailure()
	span.RecordError(lastErr)
	return nil, fmt.Errorf("BuildLayers failed after %d attempts: %w", c.config.MaxRetries+1, lastErr)
}

// doRequest performs a single request with timeout.
func (c *Client) doRequest(ctx context.Context, req *BuildLayersRequest) (*BuildLayersResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.config.RequestTimeout)
	defer cancel()

	return c.client.BuildLayers(ctx, req)
}

// isRetryable returns true if the error is retryable.
func (c *Client) isRetryable(err error) bool {
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
func (c *Client) isCircuitOpen() bool {
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
func (c *Client) recordSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.failures = 0
	c.circuitOpen = false
}

// recordFailure records a failed request and potentially opens the circuit.
func (c *Client) recordFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.failures++
	c.lastFailure = time.Now()

	if c.failures >= c.config.CircuitBreakerThreshold {
		c.circuitOpen = true
		c.circuitOpenedAt = time.Now()
	}
}

// Health checks the health of the apko service.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return c.client.Health(ctx, &HealthRequest{})
}

// CircuitState represents the state of the circuit breaker.
type CircuitState struct {
	Open            bool          `json:"open"`
	Failures        int           `json:"failures"`
	LastFailure     time.Time     `json:"last_failure,omitempty"`
	OpenedAt        time.Time     `json:"opened_at,omitempty"`
	RecoveryTimeout time.Duration `json:"recovery_timeout"`
}

// GetCircuitState returns the current circuit breaker state.
// The Open field reflects the effective state - it will be false if the
// recovery period has passed, even if the circuit was previously opened.
func (c *Client) GetCircuitState() CircuitState {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Use the same logic as isCircuitOpen() for consistency
	effectiveOpen := c.circuitOpen
	if c.circuitOpen && time.Since(c.circuitOpenedAt) > c.config.CircuitBreakerRecovery {
		effectiveOpen = false // Recovery period has passed
	}

	return CircuitState{
		Open:            effectiveOpen,
		Failures:        c.failures,
		LastFailure:     c.lastFailure,
		OpenedAt:        c.circuitOpenedAt,
		RecoveryTimeout: c.config.CircuitBreakerRecovery,
	}
}

// ResetCircuit resets the circuit breaker state.
func (c *Client) ResetCircuit() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.failures = 0
	c.circuitOpen = false
	c.lastFailure = time.Time{}
	c.circuitOpenedAt = time.Time{}
}
