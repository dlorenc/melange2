// Copyright 2022 Chainguard, Inc.
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

package container

import (
	"context"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Debugger is an optional interface that runners can implement to support
// interactive debugging sessions.
type Debugger interface {
	Debug(ctx context.Context, cfg *Config, envOverride map[string]string, cmd ...string) error
}

// Runner defines the interface for container runners used by the test command.
// The build command uses BuildKit instead.
type Runner interface {
	Close() error
	Name() string
	TestUsability(ctx context.Context) bool
	// OCIImageLoader returns a Loader that will load an OCI image.
	// The image will be used as the root filesystem when StartPod() creates the container.
	OCIImageLoader() Loader
	StartPod(ctx context.Context, cfg *Config) error
	Run(ctx context.Context, cfg *Config, envOverride map[string]string, cmd ...string) error
	TerminatePod(ctx context.Context, cfg *Config) error
	// TempDir returns the base for temporary directory, or "" if the system default is fine.
	TempDir() string
}

// Loader handles loading OCI images into the container runtime.
type Loader interface {
	LoadImage(ctx context.Context, layer v1.Layer, arch apko_types.Architecture, bc *apko_build.Context) (ref string, err error)
	RemoveImage(ctx context.Context, ref string) error
}
