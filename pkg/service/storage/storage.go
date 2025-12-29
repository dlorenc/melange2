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

// Package storage provides artifact and log storage backends.
package storage

import (
	"context"
	"io"
)

// Artifact represents a stored build artifact.
type Artifact struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Size int64  `json:"size"`
}

// Storage defines the interface for artifact and log storage.
type Storage interface {
	// WriteLog writes a build log and returns its URL.
	WriteLog(ctx context.Context, jobID, pkgName string, r io.Reader) (url string, err error)

	// WriteArtifact writes a build artifact and returns its URL.
	WriteArtifact(ctx context.Context, jobID, name string, r io.Reader) (url string, err error)

	// GetLogURL returns the URL for a job's log.
	GetLogURL(ctx context.Context, jobID, pkgName string) (string, error)

	// ListArtifacts lists all artifacts for a job.
	ListArtifacts(ctx context.Context, jobID string) ([]Artifact, error)

	// OutputDir returns the local output directory for a job.
	// For GCS storage, this creates a temp directory that will be uploaded.
	OutputDir(ctx context.Context, jobID string) (string, error)

	// SyncOutputDir uploads the contents of the output directory to storage.
	// For local storage, this is a no-op.
	SyncOutputDir(ctx context.Context, jobID, localDir string) error
}
