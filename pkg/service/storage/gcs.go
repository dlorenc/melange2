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

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

// GCSStorage stores artifacts and logs in Google Cloud Storage.
type GCSStorage struct {
	client *storage.Client
	bucket string
}

// NewGCSStorage creates a new GCS storage backend.
func NewGCSStorage(ctx context.Context, bucket string) (*GCSStorage, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating GCS client: %w", err)
	}
	return &GCSStorage{
		client: client,
		bucket: bucket,
	}, nil
}

// Close closes the GCS client.
func (s *GCSStorage) Close() error {
	return s.client.Close()
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

// SyncOutputDir uploads the contents of the local output directory to GCS.
func (s *GCSStorage) SyncOutputDir(ctx context.Context, jobID, localDir string) error {
	// Walk the local directory and upload all files
	return filepath.Walk(localDir, func(path string, info os.FileInfo, err error) error {
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

		// Open local file
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("opening file %s: %w", path, err)
		}
		defer f.Close()

		// Determine if this is a log or artifact
		var objectPath string
		if strings.Contains(relPath, "logs") || strings.HasSuffix(relPath, ".log") {
			objectPath = fmt.Sprintf("builds/%s/logs/%s", jobID, filepath.Base(relPath))
		} else {
			objectPath = fmt.Sprintf("builds/%s/artifacts/%s", jobID, filepath.Base(relPath))
		}

		// Upload to GCS
		wc := s.client.Bucket(s.bucket).Object(objectPath).NewWriter(ctx)
		switch {
		case strings.HasSuffix(relPath, ".apk"):
			wc.ContentType = "application/vnd.apk"
		case strings.HasSuffix(relPath, ".tar.gz"):
			wc.ContentType = "application/gzip"
		case strings.HasSuffix(relPath, ".log"):
			wc.ContentType = "text/plain"
		}

		if _, err := io.Copy(wc, f); err != nil {
			wc.Close()
			return fmt.Errorf("uploading %s to GCS: %w", relPath, err)
		}

		if err := wc.Close(); err != nil {
			return fmt.Errorf("closing GCS writer for %s: %w", relPath, err)
		}

		return nil
	})
}
