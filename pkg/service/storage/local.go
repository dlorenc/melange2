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
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// LocalStorage stores artifacts and logs on the local filesystem.
type LocalStorage struct {
	baseDir string
}

// NewLocalStorage creates a new local storage backend.
func NewLocalStorage(baseDir string) (*LocalStorage, error) {
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("creating base directory: %w", err)
	}
	return &LocalStorage{baseDir: baseDir}, nil
}

// WriteLog writes a build log to local storage.
func (s *LocalStorage) WriteLog(ctx context.Context, jobID, pkgName string, r io.Reader) (string, error) {
	logDir := filepath.Join(s.baseDir, jobID, "logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return "", fmt.Errorf("creating log directory: %w", err)
	}

	logPath := filepath.Join(logDir, pkgName+".log")
	f, err := os.Create(logPath)
	if err != nil {
		return "", fmt.Errorf("creating log file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, r); err != nil {
		return "", fmt.Errorf("writing log: %w", err)
	}

	return "file://" + logPath, nil
}

// WriteArtifact writes a build artifact to local storage.
func (s *LocalStorage) WriteArtifact(ctx context.Context, jobID, name string, r io.Reader) (string, error) {
	artifactDir := filepath.Join(s.baseDir, jobID, "artifacts")
	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		return "", fmt.Errorf("creating artifact directory: %w", err)
	}

	artifactPath := filepath.Join(artifactDir, name)
	f, err := os.Create(artifactPath)
	if err != nil {
		return "", fmt.Errorf("creating artifact file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, r); err != nil {
		return "", fmt.Errorf("writing artifact: %w", err)
	}

	return "file://" + artifactPath, nil
}

// GetLogURL returns the URL for a job's log.
func (s *LocalStorage) GetLogURL(ctx context.Context, jobID, pkgName string) (string, error) {
	logPath := filepath.Join(s.baseDir, jobID, "logs", pkgName+".log")
	if _, err := os.Stat(logPath); err != nil {
		return "", fmt.Errorf("log not found: %w", err)
	}
	return "file://" + logPath, nil
}

// ListArtifacts lists all artifacts for a job.
func (s *LocalStorage) ListArtifacts(ctx context.Context, jobID string) ([]Artifact, error) {
	artifactDir := filepath.Join(s.baseDir, jobID, "artifacts")
	entries, err := os.ReadDir(artifactDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading artifact directory: %w", err)
	}

	artifacts := make([]Artifact, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		artifacts = append(artifacts, Artifact{
			Name: entry.Name(),
			URL:  "file://" + filepath.Join(artifactDir, entry.Name()),
			Size: info.Size(),
		})
	}
	return artifacts, nil
}

// OutputDir returns the local output directory for a job.
func (s *LocalStorage) OutputDir(ctx context.Context, jobID string) (string, error) {
	outputDir := filepath.Join(s.baseDir, jobID)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("creating output directory: %w", err)
	}
	return outputDir, nil
}

// SyncOutputDir is a no-op for local storage.
func (s *LocalStorage) SyncOutputDir(ctx context.Context, jobID, localDir string) error {
	// No-op for local storage - files are already in place
	return nil
}
