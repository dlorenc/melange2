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

// Backend contains information about the BuildKit backend used for a build.
type Backend struct {
	Addr   string            `json:"addr"`
	Arch   string            `json:"arch"`
	Labels map[string]string `json:"labels,omitempty"`
}

// CreateBuildRequest is the request body for creating a build.
// Supports single config, multiple configs, or git source.
type CreateBuildRequest struct {
	// Single config - will create a build with one package
	ConfigYAML string `json:"config_yaml,omitempty"`

	// Multiple configs - creates a multi-package build
	Configs []string `json:"configs,omitempty"`

	// Git source - clones repo and builds packages from it
	GitSource *GitSource `json:"git_source,omitempty"`

	// Common fields
	Pipelines       map[string]string `json:"pipelines,omitempty"`
	Arch            string            `json:"arch,omitempty"`
	BackendSelector map[string]string `json:"backend_selector,omitempty"`
	WithTest        bool              `json:"with_test,omitempty"`
	Debug           bool              `json:"debug,omitempty"`

	// SourceFiles is a map of package names to their source files.
	// Each value is a map of relative file paths to their content.
	// This allows including local source directories (e.g., $pkgname/)
	// that will be available in the build workspace.
	SourceFiles map[string]map[string]string `json:"source_files,omitempty"`
}

// CreateBuildResponse is the response body for creating a build.
type CreateBuildResponse struct {
	ID       string   `json:"id"`
	Packages []string `json:"packages"` // Package names in build order
}

// BuildStatus represents the overall status of a build.
type BuildStatus string

const (
	BuildStatusPending BuildStatus = "pending"
	BuildStatusRunning BuildStatus = "running"
	BuildStatusSuccess BuildStatus = "success"
	BuildStatusFailed  BuildStatus = "failed"
	BuildStatusPartial BuildStatus = "partial" // some succeeded, some failed due to deps
)

// PackageStatus represents the status of a single package within a build.
type PackageStatus string

const (
	PackageStatusPending PackageStatus = "pending"
	PackageStatusBlocked PackageStatus = "blocked" // waiting on dependencies
	PackageStatusRunning PackageStatus = "running"
	PackageStatusSuccess PackageStatus = "success"
	PackageStatusFailed  PackageStatus = "failed"
	PackageStatusSkipped PackageStatus = "skipped" // skipped due to dependency failure
)

// PackageJob represents a single package within a build.
type PackageJob struct {
	Name         string            `json:"name"`
	Status       PackageStatus     `json:"status"`
	ConfigYAML   string            `json:"config_yaml"`
	Dependencies []string          `json:"dependencies"`
	StartedAt    *time.Time        `json:"started_at,omitempty"`
	FinishedAt   *time.Time        `json:"finished_at,omitempty"`
	Error        string            `json:"error,omitempty"`
	LogPath      string            `json:"log_path,omitempty"`
	OutputPath   string            `json:"output_path,omitempty"`
	Backend      *Backend          `json:"backend,omitempty"`
	Pipelines    map[string]string `json:"pipelines,omitempty"`
	// SourceFiles is a map of relative file paths to their content.
	// These files will be written to the source directory before building.
	SourceFiles map[string]string `json:"source_files,omitempty"`
}

// Build represents a multi-package build with dependency ordering.
type Build struct {
	ID         string       `json:"id"`
	Status     BuildStatus  `json:"status"`
	Packages   []PackageJob `json:"packages"`
	Spec       BuildSpec    `json:"spec"`
	CreatedAt  time.Time    `json:"created_at"`
	StartedAt  *time.Time   `json:"started_at,omitempty"`
	FinishedAt *time.Time   `json:"finished_at,omitempty"`
}

// BuildSpec contains the specification for a multi-package build.
type BuildSpec struct {
	// Configs is an array of inline YAML configurations.
	Configs []string `json:"configs,omitempty"`

	// GitSource specifies a git repository to clone for package configs.
	GitSource *GitSource `json:"git_source,omitempty"`

	// Pipelines is a map of pipeline paths to their YAML content.
	Pipelines map[string]string `json:"pipelines,omitempty"`

	// SourceFiles is a map of package names to their source files.
	// Each value is a map of relative file paths to their content.
	SourceFiles map[string]map[string]string `json:"source_files,omitempty"`

	// Arch is the target architecture (default: runtime arch).
	Arch string `json:"arch,omitempty"`

	// BackendSelector specifies label requirements for backend selection.
	BackendSelector map[string]string `json:"backend_selector,omitempty"`

	// WithTest runs tests after build.
	WithTest bool `json:"with_test,omitempty"`

	// Debug enables debug logging.
	Debug bool `json:"debug,omitempty"`
}

// GitSource specifies a git repository source for package configs.
type GitSource struct {
	// Repository is the git repository URL.
	Repository string `json:"repository"`

	// Ref is the branch, tag, or commit to checkout (default: HEAD).
	Ref string `json:"ref,omitempty"`

	// Pattern is the glob pattern for config files (default: "*.yaml").
	Pattern string `json:"pattern,omitempty"`

	// Path is the subdirectory within the repo to search.
	Path string `json:"path,omitempty"`
}
