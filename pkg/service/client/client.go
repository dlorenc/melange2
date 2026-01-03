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

// Package client provides an HTTP client for the melange service API.
// This client is designed for use by both CLI tools and the orchestrator
// to communicate with the API server via HTTP.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dlorenc/melange2/pkg/service/buildkit"
	svcerrors "github.com/dlorenc/melange2/pkg/service/errors"
	"github.com/dlorenc/melange2/pkg/service/types"
)

// Client is an HTTP client for the melange service.
type Client struct {
	baseURL    string
	httpClient *http.Client
	retryOpts  RetryOptions
}

// RetryOptions configures retry behavior for transient errors.
type RetryOptions struct {
	// MaxRetries is the maximum number of retry attempts (default: 3).
	MaxRetries int
	// InitialBackoff is the initial backoff duration (default: 100ms).
	InitialBackoff time.Duration
	// MaxBackoff is the maximum backoff duration (default: 5s).
	MaxBackoff time.Duration
	// BackoffMultiplier is the multiplier for exponential backoff (default: 2.0).
	BackoffMultiplier float64
}

// DefaultRetryOptions returns sensible default retry options.
func DefaultRetryOptions() RetryOptions {
	return RetryOptions{
		MaxRetries:        3,
		InitialBackoff:    100 * time.Millisecond,
		MaxBackoff:        5 * time.Second,
		BackoffMultiplier: 2.0,
	}
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(c *http.Client) Option {
	return func(client *Client) {
		client.httpClient = c
	}
}

// WithRetryOptions sets custom retry options.
func WithRetryOptions(opts RetryOptions) Option {
	return func(client *Client) {
		client.retryOpts = opts
	}
}

// WithTimeout sets the HTTP client timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(client *Client) {
		client.httpClient.Timeout = timeout
	}
}

// New creates a new melange service client.
func New(baseURL string, opts ...Option) *Client {
	// Normalize base URL - remove trailing slash
	baseURL = strings.TrimSuffix(baseURL, "/")

	c := &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		retryOpts: DefaultRetryOptions(),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Health checks if the server is healthy.
func (c *Client) Health(ctx context.Context) error {
	return c.doWithRetry(ctx, http.MethodGet, "/healthz", nil, nil)
}

// BackendsResponse is the response from the backends endpoint.
type BackendsResponse struct {
	Backends      []buildkit.Backend `json:"backends"`
	Architectures []string           `json:"architectures"`
}

// ListBackends lists available BuildKit backends.
func (c *Client) ListBackends(ctx context.Context, arch string) (*BackendsResponse, error) {
	path := "/api/v1/backends"
	if arch != "" {
		path += "?" + url.Values{"arch": {arch}}.Encode()
	}

	var result BackendsResponse
	if err := c.doWithRetry(ctx, http.MethodGet, path, nil, &result); err != nil {
		return nil, fmt.Errorf("list backends: %w", err)
	}

	return &result, nil
}

// AddBackend adds a new backend to the pool.
func (c *Client) AddBackend(ctx context.Context, backend buildkit.Backend) (*buildkit.Backend, error) {
	var result buildkit.Backend
	if err := c.doWithRetry(ctx, http.MethodPost, "/api/v1/backends", backend, &result); err != nil {
		return nil, fmt.Errorf("add backend: %w", err)
	}
	return &result, nil
}

// RemoveBackend removes a backend from the pool by its address.
func (c *Client) RemoveBackend(ctx context.Context, addr string) error {
	req := map[string]string{"addr": addr}
	if err := c.doWithRetry(ctx, http.MethodDelete, "/api/v1/backends", req, nil); err != nil {
		return fmt.Errorf("remove backend: %w", err)
	}
	return nil
}

// SubmitBuild submits a build (single or multi-package).
// Deprecated: Use CreateBuild instead.
func (c *Client) SubmitBuild(ctx context.Context, req types.CreateBuildRequest) (*types.CreateBuildResponse, error) {
	return c.CreateBuild(ctx, &req)
}

// CreateBuild creates a new build.
func (c *Client) CreateBuild(ctx context.Context, req *types.CreateBuildRequest) (*types.CreateBuildResponse, error) {
	var result types.CreateBuildResponse
	if err := c.doWithRetry(ctx, http.MethodPost, "/api/v1/builds", req, &result); err != nil {
		return nil, fmt.Errorf("create build: %w", err)
	}
	return &result, nil
}

// GetBuild retrieves a build by ID.
func (c *Client) GetBuild(ctx context.Context, buildID string) (*types.Build, error) {
	if buildID == "" {
		return nil, errors.New("build ID is required")
	}

	var build types.Build
	if err := c.doWithRetry(ctx, http.MethodGet, "/api/v1/builds/"+url.PathEscape(buildID), nil, &build); err != nil {
		return nil, fmt.Errorf("get build: %w", err)
	}
	return &build, nil
}

// ListBuilds lists all builds.
func (c *Client) ListBuilds(ctx context.Context) ([]*types.Build, error) {
	var builds []*types.Build
	if err := c.doWithRetry(ctx, http.MethodGet, "/api/v1/builds", nil, &builds); err != nil {
		return nil, fmt.Errorf("list builds: %w", err)
	}
	return builds, nil
}

// ListActiveBuilds returns all non-terminal builds (pending/running).
// This is optimized for frequent polling by the orchestrator.
func (c *Client) ListActiveBuilds(ctx context.Context) ([]*types.Build, error) {
	var builds []*types.Build
	if err := c.doWithRetry(ctx, http.MethodGet, "/api/v1/builds/active", nil, &builds); err != nil {
		return nil, fmt.Errorf("list active builds: %w", err)
	}
	return builds, nil
}

// ClaimPackage atomically claims a package for execution.
// Returns the claimed package job on success.
// Returns svcerrors.ErrBuildNotFound if the build doesn't exist.
// Returns svcerrors.ErrPackageNotFound if the package doesn't exist.
// Returns svcerrors.ErrPackageNotReady if the package's dependencies aren't satisfied.
// Returns svcerrors.ErrPackageAlreadyClaimed if the package is already running or completed.
func (c *Client) ClaimPackage(ctx context.Context, buildID, packageName string) (*types.PackageJob, error) {
	if buildID == "" {
		return nil, errors.New("build ID is required")
	}
	if packageName == "" {
		return nil, errors.New("package name is required")
	}

	path := fmt.Sprintf("/api/v1/builds/%s/packages/%s/claim",
		url.PathEscape(buildID),
		url.PathEscape(packageName))

	var pkg types.PackageJob
	if err := c.doWithRetry(ctx, http.MethodPost, path, nil, &pkg); err != nil {
		return nil, fmt.Errorf("claim package: %w", err)
	}
	return &pkg, nil
}

// UpdatePackageRequest is the request body for updating a package.
type UpdatePackageRequest struct {
	Status     types.PackageStatus `json:"status"`
	Error      string              `json:"error,omitempty"`
	LogPath    string              `json:"log_path,omitempty"`
	OutputPath string              `json:"output_path,omitempty"`
}

// UpdatePackage updates the status of a package job.
// Returns svcerrors.ErrBuildNotFound if the build doesn't exist.
// Returns svcerrors.ErrPackageNotFound if the package doesn't exist.
func (c *Client) UpdatePackage(ctx context.Context, buildID, packageName string, req *UpdatePackageRequest) (*types.PackageJob, error) {
	if buildID == "" {
		return nil, errors.New("build ID is required")
	}
	if packageName == "" {
		return nil, errors.New("package name is required")
	}

	path := fmt.Sprintf("/api/v1/builds/%s/packages/%s",
		url.PathEscape(buildID),
		url.PathEscape(packageName))

	var pkg types.PackageJob
	if err := c.doWithRetry(ctx, http.MethodPut, path, req, &pkg); err != nil {
		return nil, fmt.Errorf("update package: %w", err)
	}
	return &pkg, nil
}

// GetPackage retrieves a specific package from a build.
// Returns svcerrors.ErrBuildNotFound if the build doesn't exist.
// Returns svcerrors.ErrPackageNotFound if the package doesn't exist.
func (c *Client) GetPackage(ctx context.Context, buildID, packageName string) (*types.PackageJob, error) {
	if buildID == "" {
		return nil, errors.New("build ID is required")
	}
	if packageName == "" {
		return nil, errors.New("package name is required")
	}

	path := fmt.Sprintf("/api/v1/builds/%s/packages/%s",
		url.PathEscape(buildID),
		url.PathEscape(packageName))

	var pkg types.PackageJob
	if err := c.doWithRetry(ctx, http.MethodGet, path, nil, &pkg); err != nil {
		return nil, fmt.Errorf("get package: %w", err)
	}
	return &pkg, nil
}

// WaitForBuild waits for a build to complete, polling at the given interval.
func (c *Client) WaitForBuild(ctx context.Context, buildID string, pollInterval time.Duration) (*types.Build, error) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			build, err := c.GetBuild(ctx, buildID)
			if err != nil {
				return nil, err
			}

			switch build.Status {
			case types.BuildStatusSuccess, types.BuildStatusFailed, types.BuildStatusPartial:
				return build, nil
			case types.BuildStatusPending, types.BuildStatusRunning:
				// Continue waiting
			}
		}
	}
}

// doWithRetry performs an HTTP request with retry logic for transient errors.
func (c *Client) doWithRetry(ctx context.Context, method, path string, body, result interface{}) error {
	var lastErr error
	backoff := c.retryOpts.InitialBackoff

	for attempt := 0; attempt <= c.retryOpts.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff = time.Duration(float64(backoff) * c.retryOpts.BackoffMultiplier)
			if backoff > c.retryOpts.MaxBackoff {
				backoff = c.retryOpts.MaxBackoff
			}
		}

		err := c.do(ctx, method, path, body, result)
		if err == nil {
			return nil
		}

		// Check if this is a retryable error
		if !isRetryable(err) {
			return err
		}

		lastErr = err
	}

	return fmt.Errorf("max retries exceeded: %w", lastErr)
}

// do performs a single HTTP request.
func (c *Client) do(ctx context.Context, method, path string, body, result interface{}) error {
	fullURL := c.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &NetworkError{Err: err}
	}
	defer resp.Body.Close()

	// Read the response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	// Check for error status codes
	if resp.StatusCode >= 400 {
		return parseHTTPError(resp.StatusCode, respBody)
	}

	// Parse successful response
	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("unmarshal response: %w", err)
		}
	}

	return nil
}

// parseHTTPError converts HTTP error responses to appropriate error types.
func parseHTTPError(statusCode int, body []byte) error {
	message := strings.TrimSpace(string(body))

	switch statusCode {
	case http.StatusNotFound:
		// Map specific error messages to typed errors
		if strings.Contains(message, "build not found") {
			return svcerrors.ErrBuildNotFound
		}
		if strings.Contains(message, "package not found") {
			return svcerrors.ErrPackageNotFound
		}
		return &HTTPError{StatusCode: statusCode, Message: message}

	case http.StatusConflict:
		if strings.Contains(message, "not ready") {
			return svcerrors.ErrPackageNotReady
		}
		if strings.Contains(message, "already claimed") {
			return svcerrors.ErrPackageAlreadyClaimed
		}
		return &HTTPError{StatusCode: statusCode, Message: message}

	case http.StatusNoContent:
		// Not an error, but we need to handle it
		return nil

	case http.StatusBadRequest:
		return &HTTPError{StatusCode: statusCode, Message: message}

	case http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return &ServerError{StatusCode: statusCode, Message: message}

	default:
		return &HTTPError{StatusCode: statusCode, Message: message}
	}
}

// isRetryable returns true if the error is transient and can be retried.
func isRetryable(err error) bool {
	// Network errors are retryable
	var netErr *NetworkError
	if errors.As(err, &netErr) {
		return true
	}

	// Server errors (5xx) are retryable
	var srvErr *ServerError
	if errors.As(err, &srvErr) {
		return true
	}

	// Context errors are not retryable
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	return false
}

// NetworkError represents a network-level error.
type NetworkError struct {
	Err error
}

func (e *NetworkError) Error() string {
	return fmt.Sprintf("network error: %v", e.Err)
}

func (e *NetworkError) Unwrap() error {
	return e.Err
}

// HTTPError represents an HTTP error response.
type HTTPError struct {
	StatusCode int
	Message    string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
}

// ServerError represents a server-side error (5xx) that may be transient.
type ServerError struct {
	StatusCode int
	Message    string
}

func (e *ServerError) Error() string {
	return fmt.Sprintf("server error (HTTP %d): %s", e.StatusCode, e.Message)
}
