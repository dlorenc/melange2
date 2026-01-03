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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsRetryableBuildKitError(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		retryable bool
	}{
		{
			name:      "nil error",
			err:       nil,
			retryable: false,
		},
		{
			name:      "generic error",
			err:       errors.New("something went wrong"),
			retryable: false,
		},
		{
			name:      "DNS lookup failure - no such host",
			err:       errors.New("dial tcp: lookup buildkit-12.buildkit-headless.melange.svc.cluster.local: no such host"),
			retryable: true,
		},
		{
			name:      "DNS lookup failure - server misbehaving",
			err:       errors.New("lookup buildkit.melange.svc.cluster.local on 10.96.0.10:53: server misbehaving"),
			retryable: true,
		},
		{
			name:      "graceful stop",
			err:       errors.New("rpc error: code = Unavailable desc = closing transport due to: connection error: desc = \"error reading from server: EOF\", received prior goaway: code: NO_ERROR, debug data: \"graceful_stop\""),
			retryable: true,
		},
		{
			name:      "goaway without graceful_stop",
			err:       errors.New("received prior goaway: code: ENHANCE_YOUR_CALM"),
			retryable: true,
		},
		{
			name:      "connection refused",
			err:       errors.New("dial tcp 10.0.0.1:1234: connection refused"),
			retryable: true,
		},
		{
			name:      "connection reset by peer",
			err:       errors.New("read tcp 10.0.0.1:1234->10.0.0.2:5678: connection reset by peer"),
			retryable: true,
		},
		{
			name:      "broken pipe",
			err:       errors.New("write tcp 10.0.0.1:1234->10.0.0.2:5678: broken pipe"),
			retryable: true,
		},
		{
			name:      "gRPC Unavailable status in error string",
			err:       errors.New("rpc error: code = Unavailable desc = transport is closing"),
			retryable: true,
		},
		{
			name:      "gRPC Unavailable status code",
			err:       status.Error(codes.Unavailable, "transport is closing"),
			retryable: true,
		},
		{
			name:      "gRPC DeadlineExceeded during dial",
			err:       status.Error(codes.DeadlineExceeded, "context deadline exceeded while dialing"),
			retryable: true, // DeadlineExceeded is retryable for dial/connect errors
		},
		{
			name:      "gRPC DeadlineExceeded during build (not retryable)",
			err:       status.Error(codes.DeadlineExceeded, "context deadline exceeded"),
			retryable: false, // DeadlineExceeded without dial/connect is not retryable
		},
		{
			name:      "gRPC Internal error",
			err:       status.Error(codes.Internal, "internal server error"),
			retryable: false,
		},
		{
			name:      "build failure - not retryable",
			err:       errors.New("error: command exited with status 1"),
			retryable: false,
		},
		{
			name:      "missing dependency - not retryable",
			err:       errors.New("ERROR: unable to satisfy dependency: world[curl]"),
			retryable: false,
		},
		{
			name:      "wrapped DNS error",
			err:       errors.New("building package: connecting to buildkit: dial tcp: lookup buildkit-5.buildkit-headless: no such host"),
			retryable: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRetryableBuildKitError(tt.err)
			assert.Equal(t, tt.retryable, result)
		})
	}
}

func TestRetryConfig_ShouldRetry(t *testing.T) {
	cfg := RetryConfig{
		MaxAttempts: 3,
	}

	tests := []struct {
		name    string
		attempt int
		err     error
		want    bool
	}{
		{
			name:    "nil error",
			attempt: 1,
			err:     nil,
			want:    false,
		},
		{
			name:    "retryable error, first attempt",
			attempt: 1,
			err:     errors.New("no such host"),
			want:    true,
		},
		{
			name:    "retryable error, second attempt",
			attempt: 2,
			err:     errors.New("graceful_stop"),
			want:    true,
		},
		{
			name:    "retryable error, max attempts reached",
			attempt: 3,
			err:     errors.New("no such host"),
			want:    false,
		},
		{
			name:    "non-retryable error",
			attempt: 1,
			err:     errors.New("build failed"),
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cfg.ShouldRetry(tt.attempt, tt.err)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestRetryConfig_BackoffDuration(t *testing.T) {
	cfg := RetryConfig{
		InitialBackoff:    time.Second,
		MaxBackoff:        30 * time.Second,
		BackoffMultiplier: 2.0,
	}

	tests := []struct {
		name    string
		attempt int
		want    time.Duration
	}{
		{
			name:    "first attempt",
			attempt: 1,
			want:    time.Second,
		},
		{
			name:    "second attempt",
			attempt: 2,
			want:    2 * time.Second,
		},
		{
			name:    "third attempt",
			attempt: 3,
			want:    4 * time.Second,
		},
		{
			name:    "fourth attempt",
			attempt: 4,
			want:    8 * time.Second,
		},
		{
			name:    "large attempt - capped at max",
			attempt: 10,
			want:    30 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cfg.BackoffDuration(tt.attempt)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestRetryConfig_BackoffDuration_Defaults(t *testing.T) {
	// Zero config should use defaults
	cfg := RetryConfig{}

	// First attempt should use default initial backoff (1 second)
	result := cfg.BackoffDuration(1)
	assert.Equal(t, time.Second, result)

	// Second attempt with default multiplier (2.0)
	result = cfg.BackoffDuration(2)
	assert.Equal(t, 2*time.Second, result)
}

func TestRetryConfig_WaitForBackoff(t *testing.T) {
	cfg := RetryConfig{
		InitialBackoff:    10 * time.Millisecond,
		BackoffMultiplier: 2.0,
		MaxBackoff:        time.Second,
	}

	t.Run("successful wait", func(t *testing.T) {
		ctx := context.Background()
		start := time.Now()
		err := cfg.WaitForBackoff(ctx, 1)
		elapsed := time.Since(start)

		require.NoError(t, err)
		assert.GreaterOrEqual(t, elapsed, 10*time.Millisecond)
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err := cfg.WaitForBackoff(ctx, 1)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

func TestDefaultRetryConfig(t *testing.T) {
	cfg := DefaultRetryConfig()

	assert.Equal(t, 3, cfg.MaxAttempts)
	assert.Equal(t, time.Second, cfg.InitialBackoff)
	assert.Equal(t, 30*time.Second, cfg.MaxBackoff)
	assert.Equal(t, 2.0, cfg.BackoffMultiplier)
}

func TestIsRetryableBuildKitError_WrappedErrors(t *testing.T) {
	// Test wrapped errors using fmt.Errorf
	innerErr := errors.New("dial tcp: lookup buildkit-5: no such host")
	wrappedErr := errors.New("building package: " + innerErr.Error())

	assert.True(t, IsRetryableBuildKitError(wrappedErr))
}
