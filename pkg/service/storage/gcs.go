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

package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"golang.org/x/sync/errgroup"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
)

// Default configuration for GCS storage.
const (
	// DefaultMaxConcurrentUploads limits parallel GCS uploads to avoid rate limiting.
	DefaultMaxConcurrentUploads = 50
	// DefaultMaxRetries is the number of retry attempts for transient failures.
	DefaultMaxRetries = 5
	// DefaultInitialBackoff is the initial backoff duration for retries.
	DefaultInitialBackoff = 100 * time.Millisecond
	// DefaultMaxBackoff caps the exponential backoff.
	DefaultMaxBackoff = 30 * time.Second
)

// GCSStorage stores artifacts and logs in Google Cloud Storage.
type GCSStorage struct {
	client *storage.Client
	bucket string

	// Concurrency and retry configuration
	maxConcurrentUploads int
	maxRetries           int
	initialBackoff       time.Duration
	maxBackoff           time.Duration

	// uploadSem limits concurrent uploads
	uploadSem chan struct{}
}

// GCSOption configures a GCSStorage instance.
type GCSOption func(*GCSStorage)

// WithMaxConcurrentUploads sets the maximum number of concurrent uploads.
func WithMaxConcurrentUploads(n int) GCSOption {
	return func(s *GCSStorage) {
		s.maxConcurrentUploads = n
		s.uploadSem = make(chan struct{}, n)
	}
}

// WithRetryConfig sets the retry configuration.
func WithRetryConfig(maxRetries int, initialBackoff, maxBackoff time.Duration) GCSOption {
	return func(s *GCSStorage) {
		s.maxRetries = maxRetries
		s.initialBackoff = initialBackoff
		s.maxBackoff = maxBackoff
	}
}

// NewGCSStorage creates a new GCS storage backend.
func NewGCSStorage(ctx context.Context, bucket string, opts ...GCSOption) (*GCSStorage, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating GCS client: %w", err)
	}

	s := &GCSStorage{
		client:               client,
		bucket:               bucket,
		maxConcurrentUploads: DefaultMaxConcurrentUploads,
		maxRetries:           DefaultMaxRetries,
		initialBackoff:       DefaultInitialBackoff,
		maxBackoff:           DefaultMaxBackoff,
	}

	// Apply options
	for _, opt := range opts {
		opt(s)
	}

	// Initialize semaphore if not set by option
	if s.uploadSem == nil {
		s.uploadSem = make(chan struct{}, s.maxConcurrentUploads)
	}

	return s, nil
}

// Close closes the GCS client.
func (s *GCSStorage) Close() error {
	return s.client.Close()
}

// isRetryableError checks if an error is transient and should be retried.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Check for Google API errors with retryable status codes
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) {
		switch apiErr.Code {
		case 429, // Too Many Requests
			500, // Internal Server Error
			502, // Bad Gateway
			503, // Service Unavailable
			504: // Gateway Timeout
			return true
		}
	}

	// Check for context deadline exceeded (but not context canceled)
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	// Check error message for common transient issues
	errStr := err.Error()
	if strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "temporary failure") {
		return true
	}

	return false
}

// uploadWithRetry uploads data to GCS with exponential backoff retry.
func (s *GCSStorage) uploadWithRetry(ctx context.Context, objectPath, contentType string, getData func() (io.Reader, error)) error {
	backoff := s.initialBackoff

	for attempt := 0; attempt <= s.maxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retry
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			// Exponential backoff with cap
			backoff *= 2
			if backoff > s.maxBackoff {
				backoff = s.maxBackoff
			}
		}

		// Get fresh reader for this attempt
		reader, err := getData()
		if err != nil {
			return fmt.Errorf("getting data for upload: %w", err)
		}

		// Attempt upload
		err = s.doUpload(ctx, objectPath, contentType, reader)
		if err == nil {
			return nil
		}

		if !isRetryableError(err) {
			return err
		}

		// Log retry (context may have logger)
		if attempt < s.maxRetries {
			// Will retry
			continue
		}
	}

	return fmt.Errorf("max retries (%d) exceeded", s.maxRetries)
}

// doUpload performs a single upload attempt.
func (s *GCSStorage) doUpload(ctx context.Context, objectPath, contentType string, r io.Reader) error {
	wc := s.client.Bucket(s.bucket).Object(objectPath).NewWriter(ctx)
	if contentType != "" {
		wc.ContentType = contentType
	}

	if _, err := io.Copy(wc, r); err != nil {
		wc.Close()
		return fmt.Errorf("writing to GCS: %w", err)
	}

	if err := wc.Close(); err != nil {
		return fmt.Errorf("closing GCS writer: %w", err)
	}

	return nil
}

// WriteLog writes a build log to GCS.
func (s *GCSStorage) WriteLog(ctx context.Context, jobID, pkgName string, r io.Reader) (string, error) {
	objectPath := fmt.Sprintf("builds/%s/logs/%s.log", jobID, pkgName)
	wc := s.client.Bucket(s.bucket).Object(objectPath).NewWriter(ctx)
	wc.ContentType = "text/plain"

	if _, err := io.Copy(wc, r); err != nil {
		wc.Close()
		return "", fmt.Errorf("writing log to GCS: %w", err)
	}

	if err := wc.Close(); err != nil {
		return "", fmt.Errorf("closing GCS writer: %w", err)
	}

	return fmt.Sprintf("gs://%s/%s", s.bucket, objectPath), nil
}

// WriteArtifact writes a build artifact to GCS.
func (s *GCSStorage) WriteArtifact(ctx context.Context, jobID, name string, r io.Reader) (string, error) {
	objectPath := fmt.Sprintf("builds/%s/artifacts/%s", jobID, name)
	wc := s.client.Bucket(s.bucket).Object(objectPath).NewWriter(ctx)

	// Set content type based on extension
	if strings.HasSuffix(name, ".apk") {
		wc.ContentType = "application/vnd.apk"
	} else if strings.HasSuffix(name, ".tar.gz") {
		wc.ContentType = "application/gzip"
	}

	if _, err := io.Copy(wc, r); err != nil {
		wc.Close()
		return "", fmt.Errorf("writing artifact to GCS: %w", err)
	}

	if err := wc.Close(); err != nil {
		return "", fmt.Errorf("closing GCS writer: %w", err)
	}

	return fmt.Sprintf("gs://%s/%s", s.bucket, objectPath), nil
}

// GetLogURL returns the URL for a job's log.
func (s *GCSStorage) GetLogURL(ctx context.Context, jobID, pkgName string) (string, error) {
	objectPath := fmt.Sprintf("builds/%s/logs/%s.log", jobID, pkgName)
	// Check if object exists
	_, err := s.client.Bucket(s.bucket).Object(objectPath).Attrs(ctx)
	if err != nil {
		return "", fmt.Errorf("log not found: %w", err)
	}
	return fmt.Sprintf("gs://%s/%s", s.bucket, objectPath), nil
}

// ListArtifacts lists all artifacts for a job.
func (s *GCSStorage) ListArtifacts(ctx context.Context, jobID string) ([]Artifact, error) {
	prefix := fmt.Sprintf("builds/%s/artifacts/", jobID)
	it := s.client.Bucket(s.bucket).Objects(ctx, &storage.Query{Prefix: prefix})

	var artifacts []Artifact
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("listing artifacts: %w", err)
		}

		// Skip if it's a "directory" (ends with /)
		if strings.HasSuffix(attrs.Name, "/") {
			continue
		}

		name := strings.TrimPrefix(attrs.Name, prefix)
		artifacts = append(artifacts, Artifact{
			Name: name,
			URL:  fmt.Sprintf("gs://%s/%s", s.bucket, attrs.Name),
			Size: attrs.Size,
		})
	}
	return artifacts, nil
}

// OutputDir returns a local temp directory for building.
// The contents will be uploaded to GCS via SyncOutputDir.
func (s *GCSStorage) OutputDir(ctx context.Context, jobID string) (string, error) {
	// Create a temp directory for the build
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("melange-build-%s-*", jobID))
	if err != nil {
		return "", fmt.Errorf("creating temp directory: %w", err)
	}
	return tmpDir, nil
}

// fileToUpload represents a file to be uploaded to GCS.
type fileToUpload struct {
	localPath   string
	objectPath  string
	contentType string
}

// SyncOutputDir uploads the contents of the local output directory to GCS.
// Uses concurrent uploads with rate limiting and retry logic.
func (s *GCSStorage) SyncOutputDir(ctx context.Context, jobID, localDir string) error {
	// First, collect all files to upload
	var files []fileToUpload

	err := filepath.Walk(localDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// Get relative path
		relPath, err := filepath.Rel(localDir, path)
		if err != nil {
			return fmt.Errorf("getting relative path: %w", err)
		}

		// Determine if this is a log or artifact
		var objectPath string
		if strings.Contains(relPath, "logs") || strings.HasSuffix(relPath, ".log") {
			objectPath = fmt.Sprintf("builds/%s/logs/%s", jobID, filepath.Base(relPath))
		} else {
			objectPath = fmt.Sprintf("builds/%s/artifacts/%s", jobID, filepath.Base(relPath))
		}

		// Determine content type
		var contentType string
		switch {
		case strings.HasSuffix(relPath, ".apk"):
			contentType = "application/vnd.apk"
		case strings.HasSuffix(relPath, ".tar.gz"):
			contentType = "application/gzip"
		case strings.HasSuffix(relPath, ".log"):
			contentType = "text/plain"
		}

		files = append(files, fileToUpload{
			localPath:   path,
			objectPath:  objectPath,
			contentType: contentType,
		})

		return nil
	})
	if err != nil {
		return fmt.Errorf("walking directory: %w", err)
	}

	// Upload files concurrently with bounded parallelism
	g, ctx := errgroup.WithContext(ctx)

	for _, f := range files {
		f := f // capture for goroutine

		g.Go(func() error {
			// Acquire semaphore slot
			select {
			case s.uploadSem <- struct{}{}:
				defer func() { <-s.uploadSem }()
			case <-ctx.Done():
				return ctx.Err()
			}

			// Upload with retry
			err := s.uploadWithRetry(ctx, f.objectPath, f.contentType, func() (io.Reader, error) {
				return os.Open(f.localPath)
			})
			if err != nil {
				return fmt.Errorf("uploading %s: %w", f.localPath, err)
			}
			return nil
		})
	}

	return g.Wait()
}
