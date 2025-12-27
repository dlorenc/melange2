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

	"chainguard.dev/apko/pkg/apk/apk"
	apkofs "chainguard.dev/apko/pkg/apk/fs"
	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/tarfs"
	"github.com/chainguard-dev/clog"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"go.opentelemetry.io/otel"
	"sigs.k8s.io/release-utils/version"

	"github.com/dlorenc/melange2/pkg/build/sbom"
	"github.com/dlorenc/melange2/pkg/buildkit"
	"github.com/dlorenc/melange2/pkg/config"
	"github.com/dlorenc/melange2/pkg/index"
	"github.com/dlorenc/melange2/pkg/license"
	"github.com/dlorenc/melange2/pkg/linter"
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

	pkg := &b.Configuration.Package

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
	b.SBOMGroup = NewSBOMGroup(pkgNames...)

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

	// Build the guest environment with apko and get the layer
	log.Info("building guest environment with apko")
	layer, releaseData, layerCleanup, err := b.buildGuestLayer(ctx)
	if err != nil {
		return fmt.Errorf("building guest layer: %w", err)
	}
	defer layerCleanup()

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
	baseEnv := map[string]string{
		"SOURCE_DATE_EPOCH": fmt.Sprintf("%d", b.SourceDateEpoch.Unix()),
	}
	maps.Copy(baseEnv, b.Configuration.Environment.Environment)

	// Run the build
	cfg := &buildkit.BuildConfig{
		PackageName:  b.Configuration.Package.Name,
		Arch:         b.Arch,
		Pipelines:    b.Configuration.Pipeline,
		Subpackages:  b.Configuration.Subpackages,
		BaseEnv:      baseEnv,
		SourceDir:    b.SourceDir,
		WorkspaceDir: b.WorkspaceDir,
		CacheDir:     b.CacheDir,
		Debug:        b.Debug,
	}

	log.Info("running build with BuildKit")
	if err := builder.Build(ctx, layer, cfg); err != nil {
		return fmt.Errorf("buildkit build failed: %w", err)
	}

	// Load the workspace output into memory for further processing
	log.Infof("loading workspace from: %s", b.WorkspaceDir)
	b.WorkspaceDirFS = apkofs.DirFS(ctx, b.WorkspaceDir)

	// Perform package linting
	linterQueue := []linterTarget{
		{
			pkgName:  b.Configuration.Package.Name,
			disabled: b.Configuration.Package.Checks.Disabled,
		},
	}
	for _, sp := range b.Configuration.Subpackages {
		linterQueue = append(linterQueue, linterTarget{
			pkgName:  sp.Name,
			disabled: sp.Checks.Disabled,
		})
	}

	for _, lt := range linterQueue {
		log.Infof("running package linters for %s", lt.pkgName)

		fsys, err := apkofs.Sub(b.WorkspaceDirFS, filepath.Join(melangeOutputDirName, lt.pkgName))
		if err != nil {
			return fmt.Errorf("failed to return filesystem for workspace subtree: %w", err)
		}

		require := slices.DeleteFunc(b.LintRequire, func(s string) bool {
			return slices.Contains(lt.disabled, s)
		})
		warn := slices.CompactFunc(append(b.LintWarn, lt.disabled...), func(a, b string) bool {
			return a == b
		})

		outDir := ""
		if b.PersistLintResults {
			outDir = b.OutDir
		}

		if err := linter.LintBuild(ctx, b.Configuration, lt.pkgName, require, warn, fsys, outDir, b.Arch.ToAPK()); err != nil {
			return fmt.Errorf("unable to lint package %s: %w", lt.pkgName, err)
		}
	}

	// Perform license checks
	if _, _, err := license.LicenseCheck(ctx, b.Configuration, b.WorkspaceDirFS); err != nil {
		return fmt.Errorf("license check: %w", err)
	}

	// Get build config PURL for SBOM generation
	buildConfigPURL, err := b.getBuildConfigPURL()
	if err != nil {
		return fmt.Errorf("getting PURL for build config: %w", err)
	}

	// Create a filesystem rooted at the melange-out directory for SBOM generation
	outfs, err := apkofs.Sub(b.WorkspaceDirFS, melangeOutputDirName)
	if err != nil {
		return fmt.Errorf("creating SBOM filesystem: %w", err)
	}

	// Generate SBOMs
	genCtx := &sbom.GeneratorContext{
		Configuration:   b.Configuration,
		WorkspaceDir:    b.WorkspaceDir,
		OutputFS:        outfs,
		SourceDateEpoch: b.SourceDateEpoch,
		Namespace:       namespace,
		Arch:            b.Arch.ToAPK(),
		ConfigFile: &sbom.ConfigFile{
			Path:          b.ConfigFile,
			RepositoryURL: b.ConfigFileRepositoryURL,
			Commit:        b.ConfigFileRepositoryCommit,
			License:       b.ConfigFileLicense,
			PURL:          buildConfigPURL,
		},
		ReleaseData: releaseData,
	}

	if err := b.SBOMGenerator.GenerateSBOM(ctx, genCtx); err != nil {
		return fmt.Errorf("generating SBOMs: %w", err)
	}

	// Emit main package
	if err := b.Emit(ctx, pkg); err != nil {
		return fmt.Errorf("unable to emit package: %w", err)
	}

	// Emit subpackages
	for _, sp := range b.Configuration.Subpackages {
		if err := b.Emit(ctx, pkgFromSub(&sp)); err != nil {
			return fmt.Errorf("unable to emit package: %w", err)
		}
	}

	// Clean up workspace
	log.Debugf("cleaning workspace")
	if err := os.RemoveAll(b.WorkspaceDir); err != nil {
		log.Warnf("unable to clean workspace: %s", err)
	}

	// Generate APKINDEX if requested
	if b.GenerateIndex {
		packageDir := filepath.Join(b.OutDir, b.Arch.ToAPK())
		log.Infof("generating apk index from packages in %s", packageDir)

		var apkFiles []string
		pkgFileName := fmt.Sprintf("%s-%s-r%d.apk", b.Configuration.Package.Name, b.Configuration.Package.Version, b.Configuration.Package.Epoch)
		apkFiles = append(apkFiles, filepath.Join(packageDir, pkgFileName))

		for _, subpkg := range b.Configuration.Subpackages {
			subpkgFileName := fmt.Sprintf("%s-%s-r%d.apk", subpkg.Name, b.Configuration.Package.Version, b.Configuration.Package.Epoch)
			apkFiles = append(apkFiles, filepath.Join(packageDir, subpkgFileName))
		}

		opts := []index.Option{
			index.WithPackageFiles(apkFiles),
			index.WithSigningKey(b.SigningKey),
			index.WithMergeIndexFileFlag(true),
			index.WithIndexFile(filepath.Join(packageDir, "APKINDEX.tar.gz")),
		}

		idx, err := index.New(opts...)
		if err != nil {
			return fmt.Errorf("unable to create index: %w", err)
		}

		if err := idx.GenerateIndex(ctx); err != nil {
			return fmt.Errorf("unable to generate index: %w", err)
		}
	}

	return nil
}

// buildGuestLayer builds the apko image and returns the layer for BuildKit.
// The returned cleanup function should be called after the layer has been loaded.
func (b *Build) buildGuestLayer(ctx context.Context) (v1.Layer, *apko_build.ReleaseData, func(), error) {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("melange").Start(ctx, "buildGuestLayer")
	defer span.End()

	tmp, err := os.MkdirTemp(os.TempDir(), "apko-temp-*")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating apko tempdir: %w", err)
	}
	cleanup := func() { os.RemoveAll(tmp) }

	imgConfig := b.Configuration.Environment
	imgConfig.Archs = []apko_types.Architecture{b.Arch}

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
	log.Infof("auth configured for: %v", maps.Keys(b.Auth))

	// Build the image
	if err := bc.BuildImage(ctx); err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("unable to generate image: %w", err)
	}

	// Get the layer
	// Note: The cleanup function should be called by the caller after the layer
	// has been loaded into BuildKit (via ImageLoader.LoadLayer).
	_, layer, err := bc.ImageLayoutToLayer(ctx)
	if err != nil {
		cleanup()
		return nil, nil, nil, err
	}

	// Get release data
	releaseData := &apko_build.ReleaseData{
		ID:        "unknown",
		Name:      "melange-generated package",
		VersionID: "unknown",
	}
	// Note: In BuildKit mode, we can't easily extract release data from the container
	// This is a limitation that can be addressed in a future update

	return layer, releaseData, cleanup, nil
}
