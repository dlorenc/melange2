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

// Package types defines the core types for the melange service.
package types

import (
	"time"
)

// JobStatus represents the current state of a job.
type JobStatus string

const (
	JobStatusPending  JobStatus = "pending"
	JobStatusRunning  JobStatus = "running"
	JobStatusSuccess  JobStatus = "success"
	JobStatusFailed   JobStatus = "failed"
)

// Job represents a build job.
type Job struct {
	ID         string     `json:"id"`
	Status     JobStatus  `json:"status"`
	Spec       JobSpec    `json:"spec"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Error      string     `json:"error,omitempty"`
	LogPath    string     `json:"log_path,omitempty"`
	OutputPath string     `json:"output_path,omitempty"`
}

// JobSpec contains the specification for a build job.
type JobSpec struct {
	// ConfigYAML is the inline melange configuration.
	ConfigYAML string `json:"config_yaml"`

	// Arch is the target architecture (default: runtime arch).
	Arch string `json:"arch,omitempty"`

	// WithTest runs tests after build.
	WithTest bool `json:"with_test,omitempty"`

	// Debug enables debug logging.
	Debug bool `json:"debug,omitempty"`
}

// CreateJobRequest is the request body for creating a job.
type CreateJobRequest struct {
	ConfigYAML string `json:"config_yaml"`
	Arch       string `json:"arch,omitempty"`
	WithTest   bool   `json:"with_test,omitempty"`
	Debug      bool   `json:"debug,omitempty"`
}

// CreateJobResponse is the response body for creating a job.
type CreateJobResponse struct {
	ID string `json:"id"`
}
