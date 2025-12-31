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

package build

import (
	"context"
	"errors"
	"fmt"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"
)

// Executor is the interface for executing a single-architecture build or test.
type Executor interface {
	// Execute runs the build or test.
	Execute(ctx context.Context) error
	// Close cleans up any resources.
	Close(ctx context.Context) error
	// GetArch returns the target architecture.
	GetArch() apko_types.Architecture
}

// ExecutorFactory creates Executors from configuration.
type ExecutorFactory[C any] func(ctx context.Context, cfg *C) (Executor, error)

// ConfigCloner clones a configuration and sets the architecture.
type ConfigCloner[C any] func(cfg *C, arch apko_types.Architecture) *C

// Orchestrator handles multi-architecture build/test execution.
// It provides a unified way to run builds or tests across multiple architectures.
type Orchestrator[C any] struct {
	// BaseConfig is the base configuration to clone for each architecture.
	BaseConfig *C
	// Factory creates Executors for each architecture.
	Factory ExecutorFactory[C]
	// Cloner clones the config and sets the architecture.
	Cloner ConfigCloner[C]
	// SpanName is the name used for OpenTelemetry tracing.
	SpanName string
}

// RunForArchitectures executes the build/test for all specified architectures.
// If archs is empty, it defaults to all architectures.
func (o *Orchestrator[C]) RunForArchitectures(ctx context.Context, archs []apko_types.Architecture) error {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("melange").Start(ctx, o.SpanName)
	defer span.End()

	if len(archs) == 0 {
		archs = apko_types.AllArchs
	}

	// Create executors for each architecture.
	// We do this upfront to avoid race conditions and ensure all contexts
	// are valid before starting parallel execution.
	executors := []Executor{}
	for _, arch := range archs {
		// Clone config and set architecture
		cfg := o.Cloner(o.BaseConfig, arch)

		executor, err := o.Factory(ctx, cfg)
		if errors.Is(err, ErrSkipThisArch) {
			log.Warnf("skipping arch %s", arch)
			continue
		} else if err != nil {
			return err
		}

		defer executor.Close(ctx)
		executors = append(executors, executor)
	}

	if len(executors) == 0 {
		log.Warn("target-architecture and --arch do not overlap, nothing to do")
		return nil
	}

	var errg errgroup.Group

	for _, exec := range executors {
		errg.Go(func() error {
			lctx := ctx
			if len(executors) != 1 {
				alog := log.With("arch", exec.GetArch().ToAPK())
				lctx = clog.WithLogger(ctx, alog)
			}

			if err := exec.Execute(lctx); err != nil {
				return fmt.Errorf("execution failed: %w", err)
			}
			return nil
		})
	}

	return errg.Wait()
}

// buildExecutor wraps a Build to implement the Executor interface.
type buildExecutor struct {
	build *Build
}

func (e *buildExecutor) Execute(ctx context.Context) error {
	log := clog.FromContext(ctx)
	if err := e.build.BuildPackage(ctx); err != nil {
		if !e.build.Remove {
			log.Error("ERROR: failed to build package. the build environment has been preserved:")
			e.build.SummarizePaths(ctx)
		}
		return fmt.Errorf("failed to build package: %w", err)
	}
	return nil
}

func (e *buildExecutor) Close(ctx context.Context) error {
	return e.build.Close(ctx)
}

func (e *buildExecutor) GetArch() apko_types.Architecture {
	return e.build.Arch
}

// NewBuildExecutorFactory returns an ExecutorFactory for builds.
func NewBuildExecutorFactory() ExecutorFactory[BuildConfig] {
	return func(ctx context.Context, cfg *BuildConfig) (Executor, error) {
		bc, err := NewFromConfig(ctx, cfg)
		if err != nil {
			return nil, err
		}
		return &buildExecutor{build: bc}, nil
	}
}

// testExecutor wraps a TestBuildKit to implement the Executor interface.
type testExecutor struct {
	test *TestBuildKit
}

func (e *testExecutor) Execute(ctx context.Context) error {
	log := clog.FromContext(ctx)
	if err := e.test.TestPackage(ctx); err != nil {
		log.Errorf("ERROR: failed to test package: %v", err)
		return fmt.Errorf("failed to test package: %w", err)
	}
	return nil
}

func (e *testExecutor) Close(ctx context.Context) error {
	// TestBuildKit doesn't have explicit cleanup
	return nil
}

func (e *testExecutor) GetArch() apko_types.Architecture {
	return e.test.Config.Arch
}

// NewTestExecutorFactory returns an ExecutorFactory for tests.
func NewTestExecutorFactory() ExecutorFactory[TestConfig] {
	return func(ctx context.Context, cfg *TestConfig) (Executor, error) {
		tc, err := NewTestBuildKitFromConfig(ctx, cfg)
		if err != nil {
			return nil, err
		}
		return &testExecutor{test: tc}, nil
	}
}

// cloneBuildConfig clones a BuildConfig and sets the architecture.
func cloneBuildConfig(cfg *BuildConfig, arch apko_types.Architecture) *BuildConfig {
	clone := cfg.Clone()
	clone.Arch = arch
	return clone
}

// cloneTestConfig clones a TestConfig and sets the architecture.
func cloneTestConfig(cfg *TestConfig, arch apko_types.Architecture) *TestConfig {
	clone := cfg.Clone()
	clone.Arch = arch
	return clone
}

// NewBuildOrchestrator creates an Orchestrator for builds.
func NewBuildOrchestrator(cfg *BuildConfig) *Orchestrator[BuildConfig] {
	return &Orchestrator[BuildConfig]{
		BaseConfig: cfg,
		Factory:    NewBuildExecutorFactory(),
		Cloner:     cloneBuildConfig,
		SpanName:   "BuildCmd",
	}
}

// NewTestOrchestrator creates an Orchestrator for tests.
func NewTestOrchestrator(cfg *TestConfig) *Orchestrator[TestConfig] {
	return &Orchestrator[TestConfig]{
		BaseConfig: cfg,
		Factory:    NewTestExecutorFactory(),
		Cloner:     cloneTestConfig,
		SpanName:   "TestCmd",
	}
}
