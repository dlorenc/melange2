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

package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
	"github.com/chainguard-dev/clog"
	"github.com/go-git/go-git/v5"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/trace"

	"github.com/dlorenc/melange2/pkg/build"
	"github.com/dlorenc/melange2/pkg/buildkit"
	"github.com/dlorenc/melange2/pkg/convention"
	"github.com/dlorenc/melange2/pkg/linter"
)

// addBuildFlags registers all build command flags to the provided FlagSet using the BuildFlags struct
func addBuildFlags(fs *pflag.FlagSet, flags *BuildFlags) {
	fs.StringVar(&flags.BuildDate, "build-date", "", "date used for the timestamps of the files inside the image")
	fs.StringVar(&flags.WorkspaceDir, "workspace-dir", "", "directory used for the workspace at /home/build")
	fs.StringVar(&flags.PipelineDir, "pipeline-dir", "", "directory used to extend defined built-in pipelines")
	fs.StringVar(&flags.SourceDir, "source-dir", "", "directory used for included sources")
	fs.StringVar(&flags.CacheDir, "cache-dir", "./melange-cache/", "directory used for cached inputs")
	fs.StringVar(&flags.ApkCacheDir, "apk-cache-dir", "", "directory used for cached apk packages (default is system-defined cache directory)")
	fs.StringVar(&flags.SigningKey, "signing-key", "", "key to use for signing")
	fs.StringVar(&flags.EnvFile, "env-file", "", "file to use for preloaded environment variables")
	fs.StringVar(&flags.VarsFile, "vars-file", "", "file to use for preloaded build configuration variables")
	fs.BoolVar(&flags.GenerateIndex, "generate-index", true, "whether to generate APKINDEX.tar.gz")
	fs.BoolVar(&flags.EmptyWorkspace, "empty-workspace", false, "whether the build workspace should be empty")
	fs.BoolVar(&flags.StripOriginName, "strip-origin-name", false, "whether origin names should be stripped (for bootstrap)")
	fs.StringVar(&flags.OutDir, "out-dir", "./packages/", "directory where packages will be output")
	fs.StringVar(&flags.DependencyLog, "dependency-log", "", "log dependencies to a specified file")
	fs.StringVar(&flags.PurlNamespace, "namespace", "unknown", "namespace to use in package URLs in SBOM (eg wolfi, alpine)")
	fs.StringSliceVar(&flags.Archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config")
	fs.StringVar(&flags.Libc, "override-host-triplet-libc-substitution-flavor", "gnu", "override the flavor of libc for ${{host.triplet.*}} substitutions (e.g. gnu,musl) -- default is gnu")
	fs.StringSliceVar(&flags.BuildOption, "build-option", []string{}, "build options to enable")
	fs.StringVar(&flags.BuildKitAddr, "buildkit-addr", buildkit.DefaultAddr, "BuildKit daemon address (e.g., tcp://localhost:1234)")
	fs.IntVar(&flags.MaxLayers, "max-layers", 50, "maximum number of layers for build environment (1 for single layer, higher for better cache efficiency)")
	fs.StringSliceVarP(&flags.ExtraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the build environment keyring")
	fs.StringSliceVarP(&flags.ExtraRepos, "repository-append", "r", []string{}, "path to extra repositories to include in the build environment")
	fs.StringSliceVar(&flags.ExtraPackages, "package-append", []string{}, "extra packages to install for each of the build environments")
	fs.BoolVar(&flags.CreateBuildLog, "create-build-log", false, "creates a package.log file containing a list of packages that were built by the command")
	fs.BoolVar(&flags.PersistLintResults, "persist-lint-results", false, "persist lint results to JSON files in packages/{arch}/ directory")
	fs.BoolVar(&flags.Debug, "debug", false, "enables debug logging of build pipelines")
	fs.BoolVar(&flags.Remove, "rm", true, "clean up intermediate artifacts (e.g. container images, temp dirs)")
	fs.StringVar(&flags.TraceFile, "trace", "", "where to write trace output")
	fs.StringSliceVar(&flags.LintRequire, "lint-require", linter.DefaultRequiredLinters(), "linters that must pass")
	fs.StringSliceVar(&flags.LintWarn, "lint-warn", linter.DefaultWarnLinters(), "linters that will generate warnings")
	fs.BoolVar(&flags.IgnoreSignatures, "ignore-signatures", false, "ignore repository signature verification")
	fs.BoolVar(&flags.Cleanup, "cleanup", true, "when enabled, the temp dir used for the guest will be cleaned up after completion")
	fs.StringVar(&flags.ConfigFileGitCommit, "git-commit", "", "commit hash of the git repository containing the build config file (defaults to detecting HEAD)")
	fs.StringVar(&flags.ConfigFileGitRepoURL, "git-repo-url", "", "URL of the git repository containing the build config file (defaults to detecting from configured git remotes)")
	fs.StringVar(&flags.ConfigFileLicense, "license", "NOASSERTION", "license to use for the build config file itself")
	fs.BoolVar(&flags.GenerateProvenance, "generate-provenance", false, "generate SLSA provenance for builds (included in a separate .attest.tar.gz file next to the APK)")
	fs.StringVar(&flags.ExportOnFailure, "export-on-failure", "none", "export build environment on failure: none, tarball, docker, or registry (registry requires docker login)")
	fs.StringVar(&flags.ExportRef, "export-ref", "", "path (for tarball) or image reference (for docker/registry) for debug image export")
	fs.StringVar(&flags.ApkoRegistry, "apko-registry", "", "registry URL for caching apko base images (e.g., registry:5000/apko-cache)")
	fs.BoolVar(&flags.ApkoRegistryInsecure, "apko-registry-insecure", false, "allow insecure (HTTP) connection to apko registry")

	_ = fs.Bool("fail-on-lint-warning", false, "DEPRECATED: DO NOT USE")
	_ = fs.MarkDeprecated("fail-on-lint-warning", "use --lint-require and --lint-warn instead")
}

// BuildFlags holds all parsed build command flags
type BuildFlags struct {
	BuildDate            string
	WorkspaceDir         string
	PipelineDir          string
	SourceDir   string
	CacheDir    string
	ApkCacheDir string
	SigningKey           string
	GenerateIndex        bool
	EmptyWorkspace       bool
	StripOriginName      bool
	OutDir               string
	Archstrs             []string
	ExtraKeys            []string
	ExtraRepos           []string
	DependencyLog        string
	EnvFile              string
	VarsFile             string
	PurlNamespace        string
	BuildOption          []string
	CreateBuildLog       bool
	PersistLintResults bool
	Debug              bool
	Remove             bool
	BuildKitAddr       string
	MaxLayers          int
	ExtraPackages      []string
	Libc                 string
	LintRequire          []string
	LintWarn             []string
	IgnoreSignatures     bool
	Cleanup              bool
	ConfigFileGitCommit  string
	ConfigFileGitRepoURL string
	ConfigFileLicense    string
	GenerateProvenance     bool
	TraceFile              string
	ExportOnFailure        string
	ExportRef              string
	ApkoRegistry           string
	ApkoRegistryInsecure   bool
}

// ParseBuildFlags parses build flags from the provided args and returns a BuildFlags struct
func ParseBuildFlags(args []string) (*BuildFlags, []string, error) {
	flags := &BuildFlags{}

	fs := pflag.NewFlagSet("build", pflag.ContinueOnError)
	addBuildFlags(fs, flags)

	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}

	return flags, fs.Args(), nil
}

// ToBuildConfig converts BuildFlags into a BuildConfig struct.
// This is the preferred way to create build configuration from CLI flags.
func (flags *BuildFlags) ToBuildConfig(ctx context.Context, args ...string) (*build.BuildConfig, error) {
	log := clog.FromContext(ctx)

	cfg := build.NewBuildConfig()

	// Favor explicit, user-provided information for the git provenance
	var buildConfigFilePath string
	if len(args) > 0 {
		buildConfigFilePath = args[0]
		cfg.ConfigFile = buildConfigFilePath
	}

	// Git commit detection
	if flags.ConfigFileGitCommit == "" {
		log.Debugf("git commit for build config not provided, attempting to detect automatically")
		commit, err := detectGitHead(ctx, buildConfigFilePath)
		if err != nil {
			log.Warnf("unable to detect commit for build config file: %v", err)
			cfg.ConfigFileRepositoryCommit = "unknown"
		} else {
			cfg.ConfigFileRepositoryCommit = commit
		}
	} else {
		cfg.ConfigFileRepositoryCommit = flags.ConfigFileGitCommit
	}

	// Git repo URL
	if flags.ConfigFileGitRepoURL == "" {
		log.Warnf("git repository URL for build config not provided")
		cfg.ConfigFileRepositoryURL = "https://unknown/unknown/unknown"
	} else {
		cfg.ConfigFileRepositoryURL = flags.ConfigFileGitRepoURL
	}

	cfg.ConfigFileLicense = flags.ConfigFileLicense

	// Convention: auto-detect pipeline directory
	pipelineDir := flags.PipelineDir
	if pipelineDir == "" {
		if detected := convention.DetectPipelineDir(); detected != "" {
			log.Infof("using conventional pipeline directory: %s", detected)
			pipelineDir = detected
		}
	}
	if pipelineDir != "" {
		cfg.PipelineDirs = append(cfg.PipelineDirs, pipelineDir)
	}
	cfg.PipelineDirs = append(cfg.PipelineDirs, convention.BuiltinPipelineDir)

	// Convention: auto-detect signing key
	signingKey := flags.SigningKey
	if signingKey == "" {
		if detected := convention.DetectSigningKey(); detected != "" {
			log.Infof("using conventional signing key: %s", detected)
			signingKey = detected
		}
	}
	cfg.SigningKey = signingKey

	// Convention: auto-detect source directory
	if flags.SourceDir != "" {
		cfg.SourceDir = flags.SourceDir
	} else if len(args) > 0 {
		if detected := convention.DetectSourceDir(buildConfigFilePath); detected != "" {
			log.Infof("using conventional source directory: %s", detected)
			cfg.SourceDir = detected
		}
	}

	// Simple field mappings
	cfg.WorkspaceDir = flags.WorkspaceDir
	cfg.CacheDir = flags.CacheDir
	cfg.ApkCacheDir = flags.ApkCacheDir
	cfg.GenerateIndex = flags.GenerateIndex
	cfg.EmptyWorkspace = flags.EmptyWorkspace
	cfg.OutDir = flags.OutDir
	cfg.ExtraKeys = flags.ExtraKeys
	cfg.ExtraRepos = flags.ExtraRepos
	cfg.ExtraPackages = flags.ExtraPackages
	cfg.DependencyLog = flags.DependencyLog
	cfg.StripOriginName = flags.StripOriginName
	cfg.EnvFile = flags.EnvFile
	cfg.VarsFile = flags.VarsFile
	cfg.Namespace = flags.PurlNamespace
	cfg.EnabledBuildOptions = flags.BuildOption
	cfg.CreateBuildLog = flags.CreateBuildLog
	cfg.PersistLintResults = flags.PersistLintResults
	cfg.Debug = flags.Debug
	cfg.Remove = flags.Remove
	cfg.LintRequire = flags.LintRequire
	cfg.LintWarn = flags.LintWarn
	cfg.Libc = flags.Libc
	cfg.IgnoreSignatures = flags.IgnoreSignatures
	cfg.GenerateProvenance = flags.GenerateProvenance
	cfg.BuildKitAddr = flags.BuildKitAddr
	cfg.MaxLayers = flags.MaxLayers
	cfg.ExportOnFailure = flags.ExportOnFailure
	cfg.ExportRef = flags.ExportRef
	cfg.ApkoRegistry = flags.ApkoRegistry
	cfg.ApkoRegistryInsecure = flags.ApkoRegistryInsecure

	// Handle HTTP_AUTH environment variable
	if auth, ok := os.LookupEnv("HTTP_AUTH"); ok {
		parts := strings.SplitN(auth, ":", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("HTTP_AUTH must be in the form 'basic:REALM:USERNAME:PASSWORD' (got %d parts)", len(parts))
		}
		if parts[0] != "basic" {
			return nil, fmt.Errorf("HTTP_AUTH must be in the form 'basic:REALM:USERNAME:PASSWORD' (got %q for first part)", parts[0])
		}
		domain, user, pass := parts[1], parts[2], parts[3]
		if cfg.Auth == nil {
			cfg.Auth = make(map[string]options.Auth)
		}
		cfg.Auth[domain] = options.Auth{User: user, Pass: pass}
	}

	return cfg, nil
}

func buildCmd() *cobra.Command {
	// Create BuildFlags struct (defaults are set in addBuildFlags)
	flags := &BuildFlags{}

	cmd := &cobra.Command{
		Use:     "build",
		Short:   "Build a package from a YAML configuration file",
		Long:    `Build a package from a YAML configuration file.`,
		Example: `  melange build [config.yaml]`,
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			log := clog.FromContext(ctx)

			if flags.TraceFile != "" {
				w, err := os.Create(flags.TraceFile) // #nosec G304 - User-specified trace file output
				if err != nil {
					return fmt.Errorf("creating trace file: %w", err)
				}
				defer w.Close()
				exporter, err := stdouttrace.New(stdouttrace.WithWriter(w))
				if err != nil {
					return fmt.Errorf("creating stdout exporter: %w", err)
				}
				tp := trace.NewTracerProvider(trace.WithBatcher(exporter))
				otel.SetTracerProvider(tp)

				defer func() {
					if err := tp.Shutdown(context.WithoutCancel(ctx)); err != nil {
						log.Errorf("shutting down trace provider: %v", err)
					}
				}()

				tctx, span := otel.Tracer("melange").Start(ctx, "build")
				defer span.End()
				ctx = tctx
			}

			archs := apko_types.ParseArchitectures(flags.Archstrs)
			log.Infof("melange version %s with buildkit@%s building %s at commit %s for arches %s", cmd.Version, flags.BuildKitAddr, args, flags.ConfigFileGitCommit, archs)

			cfg, err := flags.ToBuildConfig(ctx, args...)
			if err != nil {
				return fmt.Errorf("creating build config from flags: %w", err)
			}

			return BuildCmdWithConfig(ctx, archs, cfg)
		},
	}

	// Register all flags using the helper function
	addBuildFlags(cmd.Flags(), flags)

	return cmd
}

// Detect the git state from the build config file's parent directory.
func detectGitHead(ctx context.Context, buildConfigFilePath string) (string, error) {
	repoDir := filepath.Dir(buildConfigFilePath)
	clog.FromContext(ctx).Debugf("detecting git state from %q", repoDir)

	repo, err := git.PlainOpenWithOptions(repoDir, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return "", fmt.Errorf("opening git repository: %w", err)
	}

	head, err := repo.Head()
	if err != nil {
		return "", fmt.Errorf("determining HEAD: %w", err)
	}
	commit := head.Hash().String()
	return commit, nil
}

// BuildCmdWithConfig executes builds for the given architectures using the provided BuildConfig.
// This is the preferred entry point for programmatic builds.
func BuildCmdWithConfig(ctx context.Context, archs []apko_types.Architecture, baseCfg *build.BuildConfig) error {
	orchestrator := build.NewBuildOrchestrator(baseCfg)
	return orchestrator.RunForArchitectures(ctx, archs)
}
