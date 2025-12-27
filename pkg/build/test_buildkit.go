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
	"fmt"
	"maps"
	"os"
	"slices"

	"chainguard.dev/apko/pkg/apk/apk"
	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
	"chainguard.dev/apko/pkg/tarfs"
	"github.com/chainguard-dev/clog"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"go.opentelemetry.io/otel"
	"sigs.k8s.io/release-utils/version"

	"github.com/dlorenc/melange2/pkg/buildkit"
	"github.com/dlorenc/melange2/pkg/config"
	"github.com/dlorenc/melange2/pkg/util"
)

// TestBuildKit holds configuration for running tests with BuildKit.
type TestBuildKit struct {
	// Package to test (optional, defaults to main package name).
	Package       string
	Configuration config.Configuration
	ConfigFile    string
	WorkspaceDir  string
	// Ordered directories where to find 'uses' pipelines.
	PipelineDirs      []string
	SourceDir         string
	Arch              apko_types.Architecture
	ExtraKeys         []string
	ExtraRepos        []string
	ExtraTestPackages []string
	CacheDir          string
	ApkCacheDir       string
	CacheSource       string
	EnvFile           string
	Debug             bool
	Auth              map[string]options.Auth
	IgnoreSignatures  bool
	BuildKitAddr      string
}

// TestBuildKitOption is a functional option for TestBuildKit.
type TestBuildKitOption func(*TestBuildKit) error

// NewTestBuildKit creates a new TestBuildKit with the provided options.
func NewTestBuildKit(ctx context.Context, opts ...TestBuildKitOption) (*TestBuildKit, error) {
	t := &TestBuildKit{
		Arch:         apko_types.Architecture("amd64"),
		BuildKitAddr: buildkit.DefaultAddr,
	}

	for _, opt := range opts {
		if err := opt(t); err != nil {
			return nil, err
		}
	}

	// Parse configuration if ConfigFile is set
	if t.ConfigFile != "" {
		parsedCfg, err := config.ParseConfiguration(ctx, t.ConfigFile,
			config.WithEnvFileForParsing(t.EnvFile),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to load configuration: %w", err)
		}
		t.Configuration = *parsedCfg
	}

	return t, nil
}

// IsTestless returns true if the test context does not actually do any testing.
func (t *TestBuildKit) IsTestless() bool {
	if t.Configuration.Test != nil && len(t.Configuration.Test.Pipeline) > 0 {
		return false
	}
	for _, sp := range t.Configuration.Subpackages {
		if sp.Test != nil && len(sp.Test.Pipeline) > 0 {
			return false
		}
	}
	return true
}

// TestPackage runs tests for the package using BuildKit.
func (t *TestBuildKit) TestPackage(ctx context.Context) error {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("melange").Start(ctx, "testPackageBuildKit")
	defer span.End()

	log.Infof("melange %s with BuildKit at %s is testing:", version.GetVersionInfo().GitVersion, t.BuildKitAddr)
	log.Debugf("  configuration file: %s", t.ConfigFile)

	pkg := &t.Configuration.Package

	// Check architecture
	inarchs := len(pkg.TargetArchitecture) == 0
	for _, ta := range pkg.TargetArchitecture {
		if apko_types.ParseArchitecture(ta) == t.Arch {
			inarchs = true
			break
		}
	}
	if !inarchs {
		log.Warnf("skipping test for %s on %s", pkg.Name, t.Arch)
		return nil
	}

	// Compile the configuration to resolve 'uses' pipelines
	log.Debugf("evaluating pipelines for test requirements")
	if err := t.Compile(ctx); err != nil {
		return fmt.Errorf("compiling %s tests: %w", t.ConfigFile, err)
	}

	// Filter out any subpackages with false If conditions
	t.Configuration.Subpackages = slices.DeleteFunc(t.Configuration.Subpackages, func(sp config.Subpackage) bool {
		result, err := shouldRun(sp.If)
		if err != nil {
			panic(err)
		}
		if !result {
			log.Infof("skipping subpackage %s because %s == false", sp.Name, sp.If)
		}
		return !result
	})

	// Skip if no tests
	if t.IsTestless() {
		log.Info("no test pipelines defined, skipping")
		return nil
	}

	// Create BuildKit builder
	builder, err := buildkit.NewBuilder(t.BuildKitAddr)
	if err != nil {
		return fmt.Errorf("creating buildkit builder: %w", err)
	}
	defer builder.Close()

	if t.Debug {
		builder.WithShowLogs(true)
	}

	// Build the test environment with apko (with package installed)
	log.Info("building test environment with apko")
	layer, cleanup, err := t.buildTestLayer(ctx)
	if err != nil {
		return fmt.Errorf("building test layer: %w", err)
	}
	defer cleanup()

	// Build base environment
	baseEnv := map[string]string{
		"HOME": "/home/build",
	}
	if t.Configuration.Test != nil {
		maps.Copy(baseEnv, t.Configuration.Test.Environment.Environment)
	}

	// Build test pipelines
	var testPipelines []config.Pipeline
	if t.Configuration.Test != nil {
		testPipelines = t.Configuration.Test.Pipeline
	}

	// Build subpackage test configs
	var subpackageTests []buildkit.SubpackageTestConfig
	for _, sp := range t.Configuration.Subpackages {
		if sp.Test != nil && len(sp.Test.Pipeline) > 0 {
			subpackageTests = append(subpackageTests, buildkit.SubpackageTestConfig{
				Name:      sp.Name,
				Pipelines: sp.Test.Pipeline,
			})
		}
	}

	// Create workspace directory
	workspaceDir := t.WorkspaceDir
	if workspaceDir == "" {
		workspaceDir, err = os.MkdirTemp("", "melange-test-*")
		if err != nil {
			return fmt.Errorf("creating workspace dir: %w", err)
		}
		defer os.RemoveAll(workspaceDir)
	}

	// Configure and run tests
	testCfg := &buildkit.TestConfig{
		PackageName:     pkg.Name,
		Arch:            t.Arch,
		TestPipelines:   testPipelines,
		SubpackageTests: subpackageTests,
		BaseEnv:         baseEnv,
		SourceDir:       t.SourceDir,
		WorkspaceDir:    workspaceDir,
		CacheDir:        t.CacheDir,
		Debug:           t.Debug,
	}

	log.Info("running tests with BuildKit")
	if err := builder.Test(ctx, layer, testCfg); err != nil {
		return fmt.Errorf("buildkit test failed: %w", err)
	}

	log.Info("all tests passed")
	return nil
}

// Compile compiles test pipelines by loading any 'uses' pipelines and substituting variables.
func (t *TestBuildKit) Compile(ctx context.Context) error {
	cfg := t.Configuration
	flavor := "gnu"

	sm, err := NewSubstitutionMap(&cfg, t.Arch, flavor, nil)
	if err != nil {
		return err
	}

	ignore := &Compiled{
		PipelineDirs: t.PipelineDirs,
	}

	// Compile build pipelines (to evaluate but not accumulate deps)
	if err := ignore.CompilePipelines(ctx, sm, cfg.Pipeline); err != nil {
		return fmt.Errorf("compiling package %q pipelines: %w", t.Package, err)
	}

	for i, sp := range cfg.Subpackages {
		sm := sm.Subpackage(&sp)
		if sp.If != "" {
			sp.If, err = util.MutateAndQuoteStringFromMap(sm.Substitutions, sp.If)
			if err != nil {
				return fmt.Errorf("mutating subpackage if: %w", err)
			}
		}

		// Compile subpackage build pipelines
		if err := ignore.CompilePipelines(ctx, sm, sp.Pipeline); err != nil {
			return fmt.Errorf("compiling subpackage %q: %w", sp.Name, err)
		}

		if sp.Test == nil {
			continue
		}

		test := &Compiled{
			PipelineDirs: t.PipelineDirs,
		}

		te := &cfg.Subpackages[i].Test.Environment.Contents

		// Append the subpackage that we're testing to be installed
		te.Packages = append(te.Packages, sp.Name)

		if err := test.CompilePipelines(ctx, sm, sp.Test.Pipeline); err != nil {
			return fmt.Errorf("compiling subpackage %q tests: %w", sp.Name, err)
		}

		// Append anything this subpackage test needs
		te.Packages = append(te.Packages, test.Needs...)

		// Sort and remove duplicates
		te.Packages = slices.Compact(slices.Sorted(slices.Values(te.Packages)))
	}

	if cfg.Test != nil {
		test := &Compiled{
			PipelineDirs: t.PipelineDirs,
		}

		te := &t.Configuration.Test.Environment.Contents

		// Append the main test package to be installed
		if t.Package != "" {
			te.Packages = append(te.Packages, t.Package)
		} else {
			te.Packages = append(te.Packages, t.Configuration.Package.Name)
		}

		if err := test.CompilePipelines(ctx, sm, cfg.Test.Pipeline); err != nil {
			return fmt.Errorf("compiling %q test pipelines: %w", t.Package, err)
		}

		// Append anything the main package test needs
		te.Packages = append(te.Packages, test.Needs...)

		// Sort and remove duplicates
		te.Packages = slices.Compact(slices.Sorted(slices.Values(te.Packages)))
	}

	return nil
}

// buildTestLayer builds the apko image for testing and returns the layer.
func (t *TestBuildKit) buildTestLayer(ctx context.Context) (v1.Layer, func(), error) {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("melange").Start(ctx, "buildTestLayer")
	defer span.End()

	tmp, err := os.MkdirTemp(os.TempDir(), "apko-test-*")
	if err != nil {
		return nil, nil, fmt.Errorf("creating apko tempdir: %w", err)
	}
	cleanup := func() { os.RemoveAll(tmp) }

	// Get the test environment configuration
	var imgConfig apko_types.ImageConfiguration
	if t.Configuration.Test != nil {
		imgConfig = t.Configuration.Test.Environment
	}
	imgConfig.Archs = []apko_types.Architecture{t.Arch}

	opts := []apko_build.Option{
		apko_build.WithImageConfiguration(imgConfig),
		apko_build.WithArch(t.Arch),
		apko_build.WithExtraKeys(t.ExtraKeys),
		apko_build.WithExtraBuildRepos(t.ExtraRepos),
		apko_build.WithExtraPackages(t.ExtraTestPackages),
		apko_build.WithCache(t.ApkCacheDir, false, apk.NewCache(true)),
		apko_build.WithTempDir(tmp),
		apko_build.WithIgnoreSignatures(t.IgnoreSignatures),
	}

	guestFS := tarfs.New()
	bc, err := apko_build.New(ctx, guestFS, opts...)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("unable to create build context: %w", err)
	}

	bc.Summarize(ctx)

	// Build the image
	if err := bc.BuildImage(ctx); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("unable to generate image: %w", err)
	}

	// Get the layer
	_, layer, err := bc.ImageLayoutToLayer(ctx)
	if err != nil {
		cleanup()
		return nil, nil, err
	}

	log.Debug("successfully built test environment with apko")
	return layer, cleanup, nil
}

// Option functions for TestBuildKit

func WithTestBuildKitConfig(configFile string) TestBuildKitOption {
	return func(t *TestBuildKit) error {
		t.ConfigFile = configFile
		return nil
	}
}

func WithTestBuildKitPackage(pkg string) TestBuildKitOption {
	return func(t *TestBuildKit) error {
		t.Package = pkg
		return nil
	}
}

func WithTestBuildKitArch(arch apko_types.Architecture) TestBuildKitOption {
	return func(t *TestBuildKit) error {
		t.Arch = arch
		return nil
	}
}

func WithTestBuildKitAddr(addr string) TestBuildKitOption {
	return func(t *TestBuildKit) error {
		t.BuildKitAddr = addr
		return nil
	}
}

func WithTestBuildKitSourceDir(dir string) TestBuildKitOption {
	return func(t *TestBuildKit) error {
		t.SourceDir = dir
		return nil
	}
}

func WithTestBuildKitWorkspaceDir(dir string) TestBuildKitOption {
	return func(t *TestBuildKit) error {
		t.WorkspaceDir = dir
		return nil
	}
}

func WithTestBuildKitCacheDir(dir string) TestBuildKitOption {
	return func(t *TestBuildKit) error {
		t.CacheDir = dir
		return nil
	}
}

func WithTestBuildKitApkCacheDir(dir string) TestBuildKitOption {
	return func(t *TestBuildKit) error {
		t.ApkCacheDir = dir
		return nil
	}
}

func WithTestBuildKitExtraKeys(keys []string) TestBuildKitOption {
	return func(t *TestBuildKit) error {
		t.ExtraKeys = keys
		return nil
	}
}

func WithTestBuildKitExtraRepos(repos []string) TestBuildKitOption {
	return func(t *TestBuildKit) error {
		t.ExtraRepos = repos
		return nil
	}
}

func WithTestBuildKitExtraTestPackages(pkgs []string) TestBuildKitOption {
	return func(t *TestBuildKit) error {
		t.ExtraTestPackages = pkgs
		return nil
	}
}

func WithTestBuildKitPipelineDir(dir string) TestBuildKitOption {
	return func(t *TestBuildKit) error {
		t.PipelineDirs = append(t.PipelineDirs, dir)
		return nil
	}
}

func WithTestBuildKitEnvFile(file string) TestBuildKitOption {
	return func(t *TestBuildKit) error {
		t.EnvFile = file
		return nil
	}
}

func WithTestBuildKitDebug(debug bool) TestBuildKitOption {
	return func(t *TestBuildKit) error {
		t.Debug = debug
		return nil
	}
}

func WithTestBuildKitIgnoreSignatures(ignore bool) TestBuildKitOption {
	return func(t *TestBuildKit) error {
		t.IgnoreSignatures = ignore
		return nil
	}
}
