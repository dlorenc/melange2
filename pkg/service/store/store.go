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

// Package store provides build storage implementations.
package store

import (
	"context"

	"github.com/dlorenc/melange2/pkg/service/dag"
	"github.com/dlorenc/melange2/pkg/service/types"
)

// BuildStore defines the interface for build storage.
type BuildStore interface {
	// CreateBuild creates a new multi-package build from DAG nodes.
	CreateBuild(ctx context.Context, packages []dag.Node, spec types.BuildSpec) (*types.Build, error)

	// GetBuild retrieves a build by ID.
	GetBuild(ctx context.Context, id string) (*types.Build, error)

	// UpdateBuild updates an existing build.
	UpdateBuild(ctx context.Context, build *types.Build) error

	// ListBuilds returns all builds.
	ListBuilds(ctx context.Context) ([]*types.Build, error)

	// ListActiveBuilds returns only non-terminal builds (pending/running).
	// This is optimized for frequent polling by the scheduler.
	ListActiveBuilds(ctx context.Context) ([]*types.Build, error)

	// ClaimReadyPackage atomically claims a package that is ready to build.
	// A package is ready when all its in-graph dependencies have succeeded.
	// Returns nil if no packages are ready.
	ClaimReadyPackage(ctx context.Context, buildID string) (*types.PackageJob, error)

	// UpdatePackageJob updates a package job within a build.
	UpdatePackageJob(ctx context.Context, buildID string, pkg *types.PackageJob) error
}

// IsTerminalStatus returns true if the build is in a terminal state.
func IsTerminalStatus(status types.BuildStatus) bool {
	switch status {
	case types.BuildStatusSuccess, types.BuildStatusFailed, types.BuildStatusPartial:
		return true
	default:
		return false
	}
}
