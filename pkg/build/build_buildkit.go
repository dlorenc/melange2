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
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/apk/auth"
	apkofs "chainguard.dev/apko/pkg/apk/fs"
	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/tarfs"
	"github.com/chainguard-dev/clog"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"go.opentelemetry.io/otel"
	"sigs.k8s.io/release-utils/version"

	"github.com/dlorenc/melange2/pkg/build/sbom"
	"github.com/dlorenc/melange2/pkg/build/sbom/spdx"
	"github.com/dlorenc/melange2/pkg/buildkit"
	"github.com/dlorenc/melange2/pkg/config"
	"github.com/dlorenc/melange2/pkg/output"
)

// buildPackageBuildKit implements package building using BuildKit.
// This is called when BuildKitAddr is set.
func (b *Build) buildPackageBuildKit(ctx context.Context) error {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("melange").Start(ctx, "buildPackageBuildKit")
	defer span.End()

	log.Infof("melange %s with BuildKit at %s is building:", version.GetVersionInfo().GitVersion, b.BuildKitAddr)
	log.Debugf("  configuration file: %s", b.ConfigFile)
	b.SummarizePaths(ctx)

	ver := b.Configuration.Package.Version
	if _, err := apk.ParseVersion(ver); err != nil {
		return fmt.Errorf("unable to parse version '%s' for %s: %w", ver, b.ConfigFile, err)
	}

	namespace := b.Namespace
	if namespace == "" {
		namespace = "unknown"
	}

	if to := b.Configuration.Package.Timeout; to > 0 {
		tctx, cancel := context.WithTimeoutCause(ctx, to,
			fmt.Errorf("build exceeded its timeout of %s", to))
		defer cancel()
		ctx = tctx
	}

	log.Debugf("evaluating pipelines for package requirements")
	if err := b.Compile(ctx); err != nil {
		return fmt.Errorf("compiling %s: %w", b.ConfigFile, err)
	}

	// Filter out any subpackages with false If conditions.
	b.Configuration.Subpackages = slices.DeleteFunc(b.Configuration.Subpackages, func(sp config.Subpackage) bool {
		result, err := shouldRun(sp.If)
		if err != nil {
			panic(err)
		}
		if !result {
			log.Infof("skipping subpackage %s because %s == false", sp.Name, sp.If)
		}
		return !result
	})

	// Initialize SBOMGroup for the main package and all subpackages
	pkgNames := []string{b.Configuration.Package.Name}
	for _, sp := range b.Configuration.Subpackages {
		pkgNames = append(pkgNames, sp.Name)
	}
	b.SBOMGroup = spdx.NewSBOMGroup(pkgNames...)

	// Prepare workspace directory
	if !b.EmptyWorkspace {
		if err := os.MkdirAll(b.WorkspaceDir, 0o755); err != nil {
			return fmt.Errorf("mkdir -p %s: %w", b.WorkspaceDir, err)
		}

		fs := apkofs.DirFS(ctx, b.SourceDir)
		if fs != nil {
			log.Infof("populating workspace %s from %s", b.WorkspaceDir, b.SourceDir)
			if err := b.populateWorkspace(ctx, fs); err != nil {
				return fmt.Errorf("unable to populate workspace: %w", err)
			}
		}
	}

	// Create melange-out directories
	if err := os.MkdirAll(filepath.Join(b.WorkspaceDir, melangeOutputDirName, b.Configuration.Package.Name), 0o755); err != nil {
		return err
	}
	for _, sp := range b.Configuration.Subpackages {
		if err := os.MkdirAll(filepath.Join(b.WorkspaceDir, melangeOutputDirName, sp.Name), 0o755); err != nil {
			return err
		}
	}

	// Build the guest environment with apko and get the layer(s)
	log.Info("building guest environment with apko")
	apkoStart := time.Now()
	layers, releaseData, layerCleanup, err := b.buildGuestLayers(ctx)
	apkoDuration := time.Since(apkoStart)
	if err != nil {
		return fmt.Errorf("building guest layers: %w", err)
	}
	defer layerCleanup()
	log.Infof("apko_layer_generation took %s (%d layers)", apkoDuration, len(layers))

	// Create BuildKit builder
	builder, err := buildkit.NewBuilder(b.BuildKitAddr)
	if err != nil {
		return fmt.Errorf("creating buildkit builder: %w", err)
	}
	defer builder.Close()

	// Enable verbose output in debug mode
	if b.Debug {
		builder.WithShowLogs(true)
	}

	// Build base environment from apko configuration
	// Use a minimum SOURCE_DATE_EPOCH of Jan 1, 1980 (315532800) to avoid issues
	// with software that can't handle very old timestamps (e.g., Ruby's gem build)
	sourceEpoch := b.SourceDateEpoch.Unix()
	if sourceEpoch < 315532800 {
		sourceEpoch = 315532800
	}
	baseEnv := map[string]string{
		"SOURCE_DATE_EPOCH": fmt.Sprintf("%d", sourceEpoch),
	}
	maps.Copy(baseEnv, b.Configuration.Environment.Environment)

	// Run the build
	cfg := &buildkit.BuildConfig{
		PackageName:     b.Configuration.Package.Name,
		Arch:            b.Arch,
		Pipelines:       b.Configuration.Pipeline,
		Subpackages:     b.Configuration.Subpackages,
		BaseEnv:         baseEnv,
		SourceDir:       b.SourceDir,
		WorkspaceDir:    b.WorkspaceDir,
		CacheDir:        b.CacheDir,
		Debug:           b.Debug,
		ExportOnFailure: b.ExportOnFailure,
		ExportRef:       b.ExportRef,
	}

	// Add cache config if registry is configured
	if b.CacheRegistry != "" {
		cfg.CacheConfig = &buildkit.CacheConfig{
			Registry: b.CacheRegistry,
			Mode:     b.CacheMode,
		}
	}

	// Add apko registry config if configured
	// This enables caching apko base images in a registry for faster subsequent builds
	if b.ApkoRegistry != "" {
		cfg.ApkoRegistryConfig = &buildkit.ApkoRegistryConfig{
			Registry: b.ApkoRegistry,
			Insecure: b.ApkoRegistryInsecure,
		}
		// Pass the image configuration for cache key generation
		cfg.ImgConfig = &b.Configuration.Environment
	}

	log.Info("running build with BuildKit")
	buildkitStart := time.Now()
	if err := builder.BuildWithLayers(ctx, layers, cfg); err != nil {
		return fmt.Errorf("buildkit build failed: %w", err)
	}
	buildkitDuration := time.Since(buildkitStart)
	log.Infof("buildkit_solve took %s", buildkitDuration)

	// Load the workspace output into memory for further processing
	log.Infof("loading workspace from: %s", b.WorkspaceDir)
	b.WorkspaceDirFS = apkofs.DirFS(ctx, b.WorkspaceDir)

	// Get build config PURL for SBOM generation
	buildConfigPURL, err := b.getBuildConfigPURL()
	if err != nil {
		return fmt.Errorf("getting PURL for build config: %w", err)
	}

	// Run post-build processing using the output processor
	processor := &output.Processor{
		Options: output.ProcessOptions{
			SkipIndex: !b.GenerateIndex,
		},
		Lint: output.LintConfig{
			Require:        b.LintRequire,
			Warn:           b.LintWarn,
			PersistResults: b.PersistLintResults,
			OutDir:         b.OutDir,
		},
		SBOM: output.SBOMConfig{
			Generator: b.SBOMGenerator,
			Namespace: namespace,
			ConfigFile: &sbom.ConfigFile{
				Path:          b.ConfigFile,
				RepositoryURL: b.ConfigFileRepositoryURL,
				Commit:        b.ConfigFileRepositoryCommit,
				License:       b.ConfigFileLicense,
				PURL:          buildConfigPURL,
			},
			ReleaseData: releaseData,
		},
		Emit: output.EmitConfig{
			Emitter: b.Emit,
		},
		Index: output.IndexConfig{
			SigningKey: b.SigningKey,
		},
	}

	processInput := &output.ProcessInput{
		Configuration:   b.Configuration,
		WorkspaceDir:    b.WorkspaceDir,
		WorkspaceDirFS:  b.WorkspaceDirFS,
		OutDir:          b.OutDir,
		Arch:            b.Arch.ToAPK(),
		SourceDateEpoch: b.SourceDateEpoch,
	}

	if err := processor.Process(ctx, processInput); err != nil {
		return err
	}

	// Clean up workspace
	log.Debugf("cleaning workspace")
	if err := os.RemoveAll(b.WorkspaceDir); err != nil {
		log.Warnf("unable to clean workspace: %s", err)
	}

	return nil
}

// buildGuestLayers builds the apko image and returns layers for BuildKit.
// The number of layers is controlled by MaxLayers:
// - MaxLayers == 1: single layer (original behavior)
// - MaxLayers > 1: multiple layers for better cache efficiency
//
// When using multiple layers, they are ordered from base to top:
// - Base OS layers (glibc, busybox) - change rarely
// - Compiler layers (gcc, binutils) - change occasionally
// - Package-specific dependencies - change frequently
//
// The returned cleanup function should be called after the layers have been loaded.
func (b *Build) buildGuestLayers(ctx context.Context) ([]v1.Layer, *apko_build.ReleaseData, func(), error) {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("melange").Start(ctx, "buildGuestLayers")
	defer span.End()

	tmp, err := os.MkdirTemp(os.TempDir(), "apko-temp-*")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating apko tempdir: %w", err)
	}
	cleanup := func() { os.RemoveAll(tmp) }

	imgConfig := b.Configuration.Environment
	imgConfig.Archs = []apko_types.Architecture{b.Arch}

	// Inject default repositories if none are specified in the config
	// This allows packages without inline repos to use the default Wolfi repos
	if len(imgConfig.Contents.Repositories) == 0 && len(b.ExtraRepos) > 0 {
		log.Infof("no repositories in config, using default repos: %v", b.ExtraRepos)
		imgConfig.Contents.Repositories = append(imgConfig.Contents.Repositories, b.ExtraRepos...)
	}
	if len(imgConfig.Contents.Keyring) == 0 && len(b.ExtraKeys) > 0 {
		log.Infof("no keyring in config, using default keys: %v", b.ExtraKeys)
		imgConfig.Contents.Keyring = append(imgConfig.Contents.Keyring, b.ExtraKeys...)
	}

	// Set the layer budget based on MaxLayers configuration
	// Default to 50 if not set
	maxLayers := b.MaxLayers
	if maxLayers == 0 {
		maxLayers = 50
	}
	// Use "origin" strategy which partitions packages by their origin
	// This groups related packages together for better cache efficiency
	imgConfig.Layering = &apko_types.Layering{
		Strategy: "origin",
		Budget:   maxLayers,
	}
	log.Infof("using layer budget of %d with origin strategy", maxLayers)

	opts := []apko_build.Option{
		apko_build.WithImageConfiguration(imgConfig),
		apko_build.WithArch(b.Arch),
		apko_build.WithExtraKeys(b.ExtraKeys),
		apko_build.WithExtraBuildRepos(b.ExtraRepos),
		apko_build.WithExtraPackages(b.ExtraPackages),
		apko_build.WithCache(b.ApkCacheDir, false, apk.NewCache(true)),
		apko_build.WithTempDir(tmp),
		apko_build.WithIgnoreSignatures(b.IgnoreSignatures),
	}

	// Convert auth config to apko authenticator
	if len(b.Auth) > 0 {
		var auths []auth.Authenticator
		for domain, creds := range b.Auth {
			auths = append(auths, auth.StaticAuth(domain, creds.User, creds.Pass))
		}
		opts = append(opts, apko_build.WithAuthenticator(auth.MultiAuthenticator(auths...)))
		log.Infof("auth configured for: %v", maps.Keys(b.Auth))
	}

	configs, warn, err := apko_build.LockImageConfiguration(ctx, imgConfig, opts...)
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("unable to lock image configuration: %w", err)
	}

	for k, v := range warn {
		log.Warnf("Unable to lock package %s: %s", k, v)
	}

	locked, ok := configs["index"]
	if !ok {
		cleanup()
		return nil, nil, nil, errors.New("missing locked config")
	}

	// Preserve the layering configuration in the locked config
	locked.Layering = imgConfig.Layering
	b.Configuration.Environment = *locked
	opts = append(opts, apko_build.WithImageConfiguration(*locked))

	guestFS := tarfs.New()
	bc, err := apko_build.New(ctx, guestFS, opts...)
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("unable to create build context: %w", err)
	}

	// Get the APK associated with our build, and then get a Resolver
	namedIndexes, err := bc.APK().GetRepositoryIndexes(ctx, false)
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("unable to obtain repository indexes: %w", err)
	}
	b.PkgResolver = apk.NewPkgResolver(ctx, namedIndexes)

	bc.Summarize(ctx)

	// Try per-layer cache if registry is configured
	var layerCache *buildkit.LayerCache
	var predictedGroups []apko_build.LayerGroup
	if b.ApkoRegistry != "" {
		layerCache = buildkit.NewLayerCache(b.ApkoRegistry, b.Arch.ToAPK(), b.ApkoRegistryInsecure)

		// Predict layer groups without building
		predictedGroups, err = bc.PredictLayerGroups(ctx)
		if err != nil {
			log.Warnf("failed to predict layer groups, falling back to full build: %v", err)
		} else {
			log.Infof("predicted %d layer groups", len(predictedGroups))

			// Check which layers are cached
			cachedRefs, allCached, err := layerCache.CheckLayers(ctx, predictedGroups)
			switch {
			case err != nil:
				log.Warnf("failed to check layer cache: %v", err)
			case allCached:
				// All layers cached - pull and return without building
				log.Infof("all %d layers cached, skipping apko build", len(predictedGroups))
				cachedLayers, err := layerCache.PullLayers(ctx, cachedRefs)
				if err != nil {
					log.Warnf("failed to pull cached layers, falling back to full build: %v", err)
				} else {
					// Get release data (limited info when using cache)
					releaseData := &apko_build.ReleaseData{
						ID:        "cached",
						Name:      "melange-cached package",
						VersionID: "cached",
					}
					return cachedLayers, releaseData, cleanup, nil
				}
			default:
				log.Infof("partial cache hit: %d/%d layers cached, building all", len(cachedRefs), len(predictedGroups))
			}
		}
	}

	// Use BuildLayers which internally calls buildImage and handles layering
	// We don't call BuildImage separately as BuildLayers does it internally
	layers, err := bc.BuildLayers(ctx)
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("building layers: %w", err)
	}
	log.Infof("apko generated %d layer(s)", len(layers))

	// Push layers to cache for future builds
	if layerCache != nil && predictedGroups != nil && len(layers) == len(predictedGroups) {
		if err := layerCache.PushLayers(ctx, layers, predictedGroups); err != nil {
			log.Warnf("failed to push layers to cache: %v", err)
		}
	}

	// Get release data
	releaseData := &apko_build.ReleaseData{
		ID:        "unknown",
		Name:      "melange-generated package",
		VersionID: "unknown",
	}
	// Note: In BuildKit mode, we can't easily extract release data from the container
	// This is a limitation that can be addressed in a future update

	return layers, releaseData, cleanup, nil
}
