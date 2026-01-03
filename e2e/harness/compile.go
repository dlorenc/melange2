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

package harness

import (
	"context"
	"fmt"

	apko_types "chainguard.dev/apko/pkg/build/types"

	"github.com/dlorenc/melange2/pkg/build"
	"github.com/dlorenc/melange2/pkg/config"
)

// CompileConfig holds configuration for compiling pipelines.
type CompileConfig struct {
	// Arch is the target architecture for substitution.
	Arch apko_types.Architecture

	// PipelineDirs are directories to search for pipeline definitions.
	PipelineDirs []string

	// BuildOptions are enabled build options for the compilation.
	BuildOptions []string
}

// DefaultCompileConfig returns a default compile configuration for e2e tests.
func DefaultCompileConfig() *CompileConfig {
	return &CompileConfig{
		Arch:         apko_types.Architecture("amd64"),
		PipelineDirs: []string{},
		BuildOptions: []string{},
	}
}

// CompileConfiguration compiles a configuration using the production compile code.
// This performs variable substitution, loads `uses:` pipelines, and gathers dependencies.
//
// The configuration is modified in place - pipelines will have their variables
// substituted after this call.
func CompileConfiguration(ctx context.Context, cfg *config.Configuration, cc *CompileConfig) error {
	if cc == nil {
		cc = DefaultCompileConfig()
	}

	// Create a minimal Build struct for compilation
	b := &build.Build{
		Configuration:       cfg,
		PipelineDirs:        cc.PipelineDirs,
		Arch:                cc.Arch,
		EnabledBuildOptions: cc.BuildOptions,
		Libc:                "gnu", // Default to glibc
	}

	// Compile the configuration using the production code
	if err := b.Compile(ctx); err != nil {
		return fmt.Errorf("compiling configuration: %w", err)
	}

	return nil
}
