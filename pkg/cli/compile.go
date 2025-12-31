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

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"

	"github.com/dlorenc/melange2/pkg/build"
	"github.com/dlorenc/melange2/pkg/convention"
)

func compile() *cobra.Command {
	var buildDate string
	var workspaceDir string
	var pipelineDir string
	var sourceDir string
	var cacheDir string
	var apkCacheDir string
	var signingKey string
	var generateIndex bool
	var emptyWorkspace bool
	var stripOriginName bool
	var outDir string
	var archstr string
	var extraKeys []string
	var extraRepos []string
	var dependencyLog string
	var envFile string
	var varsFile string
	var purlNamespace string
	var buildOption []string
	var logPolicy []string
	var createBuildLog bool
	var debug bool
	var remove bool
	var extraPackages []string
	var configFileGitCommit string
	var configFileGitRepoURL string
	var configFileLicense string
	var generateProvenance bool

	cmd := &cobra.Command{
		Use:     "compile",
		Short:   "Compile a YAML configuration file",
		Long:    `Compile a YAML configuration file.`,
		Example: `  melange compile [config.yaml]`,
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			log := clog.FromContext(ctx)

			var buildConfigFilePath string
			if len(args) > 0 {
				buildConfigFilePath = args[0] // e.g. "crane.yaml"
			}

			// Favor explicit, user-provided information for the git provenance of the
			// melange build definition. As a fallback, detect this from local git state.
			// Git auto-detection should be "best effort" and not fail the build if it
			// fails.
			if configFileGitCommit == "" {
				log.Debugf("git commit for build config not provided, attempting to detect automatically")
				commit, err := detectGitHead(ctx, buildConfigFilePath)
				if err != nil {
					log.Warnf("unable to detect commit for build config file: %v", err)
					configFileGitCommit = "unknown"
				} else {
					configFileGitCommit = commit
				}
			}
			if configFileGitRepoURL == "" {
				log.Warnf("git repository URL for build config not provided")
				configFileGitRepoURL = "https://unknown/unknown/unknown"
			}

			arch := apko_types.ParseArchitecture(archstr)

			// Build configuration using BuildConfig
			cfg := build.NewBuildConfig()
			cfg.Arch = arch
			cfg.WorkspaceDir = workspaceDir
			cfg.CacheDir = cacheDir
			cfg.ApkCacheDir = apkCacheDir
			cfg.SigningKey = signingKey
			cfg.GenerateIndex = generateIndex
			cfg.EmptyWorkspace = emptyWorkspace
			cfg.OutDir = outDir
			cfg.ExtraKeys = extraKeys
			cfg.ExtraRepos = extraRepos
			cfg.ExtraPackages = extraPackages
			cfg.DependencyLog = dependencyLog
			cfg.StripOriginName = stripOriginName
			cfg.EnvFile = envFile
			cfg.VarsFile = varsFile
			cfg.Namespace = purlNamespace
			cfg.EnabledBuildOptions = buildOption
			cfg.CreateBuildLog = createBuildLog
			cfg.Debug = debug
			cfg.Remove = remove
			cfg.ConfigFileRepositoryCommit = configFileGitCommit
			cfg.ConfigFileRepositoryURL = configFileGitRepoURL
			cfg.ConfigFileLicense = configFileLicense
			cfg.GenerateProvenance = generateProvenance

			// Add pipeline directories
			if pipelineDir != "" {
				cfg.PipelineDirs = append(cfg.PipelineDirs, pipelineDir)
			}
			cfg.PipelineDirs = append(cfg.PipelineDirs, convention.BuiltinPipelineDir)

			if len(args) > 0 {
				cfg.ConfigFile = args[0]

				if sourceDir == "" {
					sourceDir = filepath.Dir(args[0])
				}
			}

			if sourceDir != "" {
				cfg.SourceDir = sourceDir
			}

			// Handle HTTP_AUTH environment variable
			if auth, ok := os.LookupEnv("HTTP_AUTH"); ok {
				parts := strings.SplitN(auth, ":", 4)
				if len(parts) != 4 {
					return fmt.Errorf("HTTP_AUTH must be in the form 'basic:REALM:USERNAME:PASSWORD' (got %d parts)", len(parts))
				}
				if parts[0] != "basic" {
					return fmt.Errorf("HTTP_AUTH must be in the form 'basic:REALM:USERNAME:PASSWORD' (got %q for first part)", parts[0])
				}
				domain, user, pass := parts[1], parts[2], parts[3]
				if cfg.Auth == nil {
					cfg.Auth = make(map[string]options.Auth)
				}
				cfg.Auth[domain] = options.Auth{User: user, Pass: pass}
			}

			// Suppress unused variable warnings
			_ = logPolicy
			_ = buildDate

			return CompileCmd(ctx, cfg)
		},
	}

	cmd.Flags().StringVar(&archstr, "arch", "", "architectures to compile for")
	if err := cmd.MarkFlagRequired("arch"); err != nil {
		panic(err)
	}

	cmd.Flags().StringVar(&buildDate, "build-date", "", "date used for the timestamps of the files inside the image")
	cmd.Flags().StringVar(&workspaceDir, "workspace-dir", "", "directory used for the workspace at /home/build")
	cmd.Flags().StringVar(&pipelineDir, "pipeline-dir", "", "directory used to extend defined built-in pipelines")
	cmd.Flags().StringVar(&sourceDir, "source-dir", "", "directory used for included sources")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "./melange-cache/", "directory used for cached inputs")
	cmd.Flags().StringVar(&apkCacheDir, "apk-cache-dir", "", "directory used for cached apk packages (default is system-defined cache directory)")
	cmd.Flags().StringVar(&signingKey, "signing-key", "", "key to use for signing")
	cmd.Flags().StringVar(&envFile, "env-file", "", "file to use for preloaded environment variables")
	cmd.Flags().StringVar(&varsFile, "vars-file", "", "file to use for preloaded build configuration variables")
	cmd.Flags().BoolVar(&generateIndex, "generate-index", true, "whether to generate APKINDEX.tar.gz")
	cmd.Flags().BoolVar(&emptyWorkspace, "empty-workspace", false, "whether the build workspace should be empty")
	cmd.Flags().BoolVar(&stripOriginName, "strip-origin-name", false, "whether origin names should be stripped (for bootstrap)")
	cmd.Flags().StringVar(&outDir, "out-dir", "./packages/", "directory where packages will be output")
	cmd.Flags().StringVar(&dependencyLog, "dependency-log", "", "log dependencies to a specified file")
	cmd.Flags().StringVar(&purlNamespace, "namespace", "unknown", "namespace to use in package URLs in SBOM (eg wolfi, alpine)")
	cmd.Flags().StringSliceVar(&buildOption, "build-option", []string{}, "build options to enable")
	cmd.Flags().StringSliceVar(&logPolicy, "log-policy", []string{"builtin:stderr"}, "logging policy to use")
	cmd.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the build environment keyring")
	cmd.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{}, "path to extra repositories to include in the build environment")
	cmd.Flags().StringSliceVar(&extraPackages, "package-append", []string{}, "extra packages to install for each of the build environments")
	cmd.Flags().BoolVar(&createBuildLog, "create-build-log", false, "creates a package.log file containing a list of packages that were built by the command")
	cmd.Flags().BoolVar(&debug, "debug", false, "enables debug logging of build pipelines")
	cmd.Flags().BoolVar(&remove, "rm", false, "clean up intermediate artifacts (e.g. container images)")
	cmd.Flags().BoolVar(&generateProvenance, "generate-provenance", false, "generate SLSA provenance for builds (included in a separate .attest.tar.gz file next to the APK)")

	cmd.Flags().StringVar(&configFileGitCommit, "git-commit", "", "commit hash of the git repository containing the build config file (defaults to detecting HEAD)")
	cmd.Flags().StringVar(&configFileGitRepoURL, "git-repo-url", "", "URL of the git repository containing the build config file (defaults to detecting from configured git remotes)")
	cmd.Flags().StringVar(&configFileLicense, "license", "NOASSERTION", "license to use for the build config file itself")

	return cmd
}

// CompileCmd compiles a melange configuration file using BuildConfig.
func CompileCmd(ctx context.Context, cfg *build.BuildConfig) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "CompileCmd")
	defer span.End()

	bc, err := build.NewFromConfig(ctx, cfg)
	if err != nil {
		return err
	}

	defer bc.Close(ctx)

	if err := bc.Compile(ctx); err != nil {
		return fmt.Errorf("failed to compile %s: %w", bc.ConfigFile, err)
	}

	return json.NewEncoder(os.Stdout).Encode(bc.Configuration)
}
