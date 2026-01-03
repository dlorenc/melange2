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

// Package errors provides typed errors for the melange service.
package errors

import "errors"

// Backend pool errors.
var (
	// ErrNoAvailableBackend is returned when all backends are at capacity or circuit-open.
	ErrNoAvailableBackend = errors.New("no available backend: all backends are at capacity or circuit-open")

	// ErrBackendAtCapacity is returned when a backend has reached its maximum job count.
	ErrBackendAtCapacity = errors.New("backend is at capacity")

	// ErrBackendNotFound is returned when a backend does not exist in the pool.
	ErrBackendNotFound = errors.New("backend not found")

	// ErrBackendAlreadyExists is returned when adding a backend that already exists.
	ErrBackendAlreadyExists = errors.New("backend already exists")
)

// Build store errors.
var (
	// ErrBuildNotFound is returned when a build does not exist.
	ErrBuildNotFound = errors.New("build not found")

	// ErrPackageNotFound is returned when a package job does not exist.
	ErrPackageNotFound = errors.New("package not found")

	// ErrPackageNotReady is returned when a package cannot be claimed
	// because its dependencies have not all completed successfully.
	ErrPackageNotReady = errors.New("package not ready: dependencies not satisfied")

	// ErrPackageAlreadyClaimed is returned when attempting to claim
	// a package that is already running or completed.
	ErrPackageAlreadyClaimed = errors.New("package already claimed or completed")
)
