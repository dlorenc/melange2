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

package scheduler

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/chainguard-dev/clog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RetryConfig configures retry behavior for transient BuildKit errors.
type RetryConfig struct {
	// MaxAttempts is the maximum number of attempts (including the initial attempt).
	// Defaults to 3 if not set.
	MaxAttempts int

	// InitialBackoff is the delay before the first retry.
	// Defaults to 1 second if not set.
	InitialBackoff time.Duration

	// MaxBackoff is the maximum backoff duration.
	// Defaults to 30 seconds if not set.
	MaxBackoff time.Duration

	// BackoffMultiplier is the factor by which backoff increases each retry.
	// Defaults to 2.0 if not set.
	BackoffMultiplier float64
}

// DefaultRetryConfig returns the default retry configuration.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:       3,
		InitialBackoff:    time.Second,
		MaxBackoff:        30 * time.Second,
		BackoffMultiplier: 2.0,
	}
}

// IsRetryableBuildKitError checks if an error is a transient BuildKit error
// that should be retried with a different backend.
//
// Retryable errors include:
// - DNS lookup failures (backend pod was scaled down)
// - Graceful stop errors (backend is draining)
// - Connection refused/reset (backend restarted)
// - Context deadline exceeded during connection (network issues)
func IsRetryableBuildKitError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// DNS lookup failures - BuildKit pod no longer exists
	// Example: "dial tcp: lookup buildkit-12.buildkit-headless.melange.svc.cluster.local: no such host"
	if strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "lookup") && strings.Contains(errStr, "server misbehaving") {
		return true
	}

	// Graceful stop - BuildKit is shutting down
	// Example: "received prior goaway: code: NO_ERROR, debug data: \"graceful_stop\""
	if strings.Contains(errStr, "graceful_stop") ||
		strings.Contains(errStr, "goaway") {
		return true
	}

	// Connection errors that indicate backend unavailability
	if strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "broken pipe") {
		return true
	}

	// gRPC Unavailable status - transient errors
	// Example: "rpc error: code = Unavailable desc = closing transport"
	if strings.Contains(errStr, "code = Unavailable") {
		return true
	}

	// Check for gRPC status codes that indicate transient errors
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.Unavailable:
			return true
		case codes.DeadlineExceeded:
			// Only retry deadline exceeded if it's a connection issue, not a build timeout
			if strings.Contains(errStr, "dial") || strings.Contains(errStr, "connect") {
				return true
			}
		}
	}

	// Check wrapped errors
	var unwrapped error
	if unwrapped = errors.Unwrap(err); unwrapped != nil {
		return IsRetryableBuildKitError(unwrapped)
	}

	return false
}

// RetryResult contains the outcome of a retried operation.
type RetryResult struct {
	// Attempts is the total number of attempts made.
	Attempts int

	// LastError is the last error encountered (nil if successful).
	LastError error

	// RetryErrors contains errors from all retry attempts (not including the final attempt).
	RetryErrors []error
}

// ShouldRetry determines if the current attempt should be retried.
func (r *RetryConfig) ShouldRetry(attempt int, err error) bool {
	if err == nil {
		return false
	}
	if attempt >= r.MaxAttempts {
		return false
	}
	return IsRetryableBuildKitError(err)
}

// BackoffDuration calculates the backoff duration for the given attempt (1-indexed).
func (r *RetryConfig) BackoffDuration(attempt int) time.Duration {
	backoff := r.InitialBackoff
	if backoff == 0 {
		backoff = time.Second
	}

	multiplier := r.BackoffMultiplier
	if multiplier == 0 {
		multiplier = 2.0
	}

	maxBackoff := r.MaxBackoff
	if maxBackoff == 0 {
		maxBackoff = 30 * time.Second
	}

	// Calculate exponential backoff: initialBackoff * multiplier^(attempt-1)
	for i := 1; i < attempt; i++ {
		backoff = time.Duration(float64(backoff) * multiplier)
		if backoff > maxBackoff {
			backoff = maxBackoff
			break
		}
	}

	return backoff
}

// WaitForBackoff waits for the appropriate backoff duration before the next retry.
// Returns an error if the context is cancelled during the wait.
func (r *RetryConfig) WaitForBackoff(ctx context.Context, attempt int) error {
	backoff := r.BackoffDuration(attempt)
	log := clog.FromContext(ctx)
	log.Infof("retry attempt %d: waiting %s before retry", attempt, backoff)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(backoff):
		return nil
	}
}

// LogRetryAttempt logs information about a retry attempt.
func LogRetryAttempt(ctx context.Context, attempt, maxAttempts int, err error) {
	log := clog.FromContext(ctx)
	log.Warnf("build attempt %d/%d failed with retryable error: %v", attempt, maxAttempts, err)
}

// LogRetrySuccess logs when a build succeeds after retries.
func LogRetrySuccess(ctx context.Context, attempts int) {
	log := clog.FromContext(ctx)
	if attempts > 1 {
		log.Infof("build succeeded after %d attempts", attempts)
	}
}

// LogRetryExhausted logs when all retry attempts have been exhausted.
func LogRetryExhausted(ctx context.Context, attempts int, lastErr error) {
	log := clog.FromContext(ctx)
	log.Errorf("build failed after %d attempts, last error: %v", attempts, lastErr)
}
