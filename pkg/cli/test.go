// Copyright 2023 Chainguard, Inc.
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

package cli

import (
	"context"
	"fmt"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"

	"github.com/dlorenc/melange2/pkg/build"
	"github.com/dlorenc/melange2/pkg/buildkit"
)

// addTestFlags registers all test command flags to the provided FlagSet using the TestFlags struct
func addTestFlags(fs *pflag.FlagSet, flags *TestFlags) {
	fs.StringVar(&flags.WorkspaceDir, "workspace-dir", "", "directory used for the workspace at /home/build")
	fs.StringSliceVar(&flags.PipelineDirs, "pipeline-dirs", []string{}, "directories used to extend defined built-in pipelines")
	fs.StringVar(&flags.SourceDir, "source-dir", "", "directory used for included sources")
	fs.StringVar(&flags.CacheDir, "cache-dir", "", "directory used for cached inputs")
	fs.StringVar(&flags.ApkCacheDir, "apk-cache-dir", "", "directory used for cached apk packages (default is system-defined cache directory)")
	fs.StringSliceVar(&flags.Archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config")
	fs.StringSliceVarP(&flags.ExtraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the build environment keyring")
	fs.StringVar(&flags.EnvFile, "env-file", "", "file to use for preloaded environment variables")
	fs.BoolVar(&flags.Debug, "debug", false, "enables debug logging of test pipelines (sets -x for steps)")
	fs.StringSliceVarP(&flags.ExtraRepos, "repository-append", "r", []string{}, "path to extra repositories to include in the build environment")
	fs.StringSliceVar(&flags.ExtraTestPackages, "test-package-append", []string{}, "extra packages to install for each of the test environments")
	fs.BoolVar(&flags.IgnoreSignatures, "ignore-signatures", false, "ignore repository signature verification")
	fs.StringVar(&flags.BuildKitAddr, "buildkit-addr", buildkit.DefaultAddr, "BuildKit daemon address (e.g., tcp://localhost:1234)")
}

// TestFlags holds all parsed test command flags
type TestFlags struct {
	WorkspaceDir      string
	SourceDir         string
	CacheDir          string
	ApkCacheDir       string
	Archstrs          []string
	PipelineDirs      []string
	ExtraKeys         []string
	ExtraRepos        []string
	EnvFile           string
	Debug             bool
	ExtraTestPackages []string
	IgnoreSignatures  bool
	BuildKitAddr      string
}

// ParseTestFlags parses test flags from the provided args and returns a TestFlags struct
func ParseTestFlags(args []string) (*TestFlags, []string, error) {
	flags := &TestFlags{}

	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	addTestFlags(fs, flags)

	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}

	return flags, fs.Args(), nil
}

// TestOptions converts TestFlags into a slice of build.TestBuildKitOption
func (flags *TestFlags) TestOptions(ctx context.Context, args ...string) ([]build.TestBuildKitOption, error) {
	options := []build.TestBuildKitOption{
		build.WithTestBuildKitWorkspaceDir(flags.WorkspaceDir),
		build.WithTestBuildKitCacheDir(flags.CacheDir),
		build.WithTestBuildKitApkCacheDir(flags.ApkCacheDir),
		build.WithTestBuildKitExtraKeys(flags.ExtraKeys),
		build.WithTestBuildKitExtraRepos(flags.ExtraRepos),
		build.WithTestBuildKitExtraTestPackages(flags.ExtraTestPackages),
		build.WithTestBuildKitEnvFile(flags.EnvFile),
		build.WithTestBuildKitDebug(flags.Debug),
		build.WithTestBuildKitIgnoreSignatures(flags.IgnoreSignatures),
		build.WithTestBuildKitAddr(flags.BuildKitAddr),
	}

	if len(args) > 0 {
		options = append(options, build.WithTestBuildKitConfig(args[0]))
	}
	if len(args) > 1 {
		options = append(options, build.WithTestBuildKitPackage(args[1]))
	}

	if flags.SourceDir != "" {
		options = append(options, build.WithTestBuildKitSourceDir(flags.SourceDir))
	}

	for i := range flags.PipelineDirs {
		options = append(options, build.WithTestBuildKitPipelineDir(flags.PipelineDirs[i]))
	}
	options = append(options, build.WithTestBuildKitPipelineDir(BuiltinPipelineDir))

	return options, nil
}

func test() *cobra.Command {
	// Create TestFlags struct (defaults are set in addTestFlags)
	flags := &TestFlags{}

	cmd := &cobra.Command{
		Use:     "test",
		Short:   "Test a package with a YAML configuration file",
		Long:    `Test a package from a YAML configuration file containing a test pipeline.`,
		Example: `  melange test <test.yaml> [package-name]`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			archs := apko_types.ParseArchitectures(flags.Archstrs)
			options, err := flags.TestOptions(ctx, args...)
			if err != nil {
				return fmt.Errorf("getting test options from flags: %w", err)
			}

			return TestCmd(cmd.Context(), archs, options...)
		},
	}

	// Register all flags using the helper function
	addTestFlags(cmd.Flags(), flags)

	return cmd
}

func TestCmd(ctx context.Context, archs []apko_types.Architecture, baseOpts ...build.TestBuildKitOption) error {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("melange").Start(ctx, "TestCmd")
	defer span.End()

	if len(archs) == 0 {
		archs = apko_types.AllArchs
	}

	// Set up the test contexts before running them.
	tcs := []*build.TestBuildKit{}
	for _, arch := range archs {
		opts := []build.TestBuildKitOption{build.WithTestBuildKitArch(arch)}
		opts = append(opts, baseOpts...)

		tc, err := build.NewTestBuildKit(ctx, opts...)
		if err != nil {
			return err
		}

		tcs = append(tcs, tc)
	}

	if len(tcs) == 0 {
		log.Warnf("target-architecture and --arch do not overlap, nothing to test")
		return nil
	}

	var errg errgroup.Group

	for _, tc := range tcs {
		errg.Go(func() error {
			if err := tc.TestPackage(ctx); err != nil {
				log.Errorf("ERROR: failed to test package: %v", err)
				return fmt.Errorf("failed to test package: %w", err)
			}
			return nil
		})
	}
	return errg.Wait()
}
