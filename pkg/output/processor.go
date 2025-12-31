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

// Package output provides post-build processing for melange packages.
// It handles linting, license checking, SBOM generation, package emission,
// and index generation as a unified processing pipeline.
package output

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	apkofs "chainguard.dev/apko/pkg/apk/fs"
	apko_build "chainguard.dev/apko/pkg/build"
	"github.com/chainguard-dev/clog"

	"github.com/dlorenc/melange2/pkg/build/sbom"
	"github.com/dlorenc/melange2/pkg/config"
	"github.com/dlorenc/melange2/pkg/index"
	"github.com/dlorenc/melange2/pkg/license"
	"github.com/dlorenc/melange2/pkg/linter"
)

// ProcessOptions controls which post-processing steps to run.
type ProcessOptions struct {
	// SkipLint disables package linting.
	SkipLint bool
	// SkipLicenseCheck disables license checking.
	SkipLicenseCheck bool
	// SkipSBOM disables SBOM generation.
	SkipSBOM bool
	// SkipEmit disables package emission.
	SkipEmit bool
	// SkipIndex disables APKINDEX generation.
	SkipIndex bool
}

// LintConfig contains configuration for package linting.
type LintConfig struct {
	// Require is the list of linters that must pass.
	Require []string
	// Warn is the list of linters that produce warnings only.
	Warn []string
	// PersistResults writes lint results to the output directory.
	PersistResults bool
	// OutDir is the directory to write lint results to.
	OutDir string
}

// SBOMConfig contains configuration for SBOM generation.
type SBOMConfig struct {
	// Generator is the SBOM generator to use.
	Generator sbom.Generator
	// Namespace is the package namespace.
	Namespace string
	// ConfigFile contains build config file metadata.
	ConfigFile *sbom.ConfigFile
	// ReleaseData contains release metadata from the build environment.
	ReleaseData *apko_build.ReleaseData
}

// EmitConfig contains configuration for package emission.
type EmitConfig struct {
	// Emitter is the function that emits a package.
	Emitter func(ctx context.Context, pkg *config.Package) error
}

// IndexConfig contains configuration for APKINDEX generation.
type IndexConfig struct {
	// SigningKey is the path to the signing key.
	SigningKey string
}

// ProcessInput contains all the inputs needed for post-build processing.
type ProcessInput struct {
	// Configuration is the melange build configuration.
	Configuration *config.Configuration
	// WorkspaceDir is the path to the workspace directory.
	WorkspaceDir string
	// WorkspaceDirFS is the filesystem interface to the workspace.
	WorkspaceDirFS apkofs.FullFS
	// OutDir is the output directory for packages.
	OutDir string
	// Arch is the target architecture.
	Arch string
	// SourceDateEpoch is the timestamp for reproducible builds.
	SourceDateEpoch time.Time
}

// Processor handles post-build processing steps.
type Processor struct {
	Options ProcessOptions
	Lint    LintConfig
	SBOM    SBOMConfig
	Emit    EmitConfig
	Index   IndexConfig
}

// NewProcessor creates a new Processor with default options.
func NewProcessor() *Processor {
	return &Processor{}
}

// linterTarget holds information for linting a package.
type linterTarget struct {
	pkgName  string
	disabled []string
}

// Process runs all enabled post-processing steps on the build output.
func (p *Processor) Process(ctx context.Context, input *ProcessInput) error {
	log := clog.FromContext(ctx)

	// Perform package linting
	if !p.Options.SkipLint {
		if err := p.runLinting(ctx, input); err != nil {
			return err
		}
	}

	// Perform license checks
	if !p.Options.SkipLicenseCheck {
		if err := p.runLicenseCheck(ctx, input); err != nil {
			return err
		}
	}

	// Generate SBOMs
	if !p.Options.SkipSBOM {
		if err := p.runSBOMGeneration(ctx, input); err != nil {
			return err
		}
	}

	// Emit packages
	if !p.Options.SkipEmit {
		if err := p.runEmit(ctx, input); err != nil {
			return err
		}
	}

	// Generate APKINDEX
	if !p.Options.SkipIndex {
		if err := p.runIndexGeneration(ctx, input); err != nil {
			return err
		}
	}

	log.Debug("post-build processing completed")
	return nil
}

// runLinting performs package linting on all packages.
func (p *Processor) runLinting(ctx context.Context, input *ProcessInput) error {
	log := clog.FromContext(ctx)

	// Build list of packages to lint
	targets := []linterTarget{
		{
			pkgName:  input.Configuration.Package.Name,
			disabled: input.Configuration.Package.Checks.Disabled,
		},
	}
	for _, sp := range input.Configuration.Subpackages {
		targets = append(targets, linterTarget{
			pkgName:  sp.Name,
			disabled: sp.Checks.Disabled,
		})
	}

	for _, lt := range targets {
		log.Infof("running package linters for %s", lt.pkgName)

		fsys, err := apkofs.Sub(input.WorkspaceDirFS, filepath.Join(melangeOutputDirName, lt.pkgName))
		if err != nil {
			return fmt.Errorf("failed to return filesystem for workspace subtree: %w", err)
		}

		require := slices.DeleteFunc(slices.Clone(p.Lint.Require), func(s string) bool {
			return slices.Contains(lt.disabled, s)
		})
		warn := slices.CompactFunc(append(slices.Clone(p.Lint.Warn), lt.disabled...), func(a, b string) bool {
			return a == b
		})

		outDir := ""
		if p.Lint.PersistResults {
			outDir = p.Lint.OutDir
		}

		if err := linter.LintBuild(ctx, input.Configuration, lt.pkgName, require, warn, fsys, outDir, input.Arch); err != nil {
			return fmt.Errorf("unable to lint package %s: %w", lt.pkgName, err)
		}
	}

	return nil
}

// runLicenseCheck performs license checking on the build output.
func (p *Processor) runLicenseCheck(ctx context.Context, input *ProcessInput) error {
	if _, _, err := license.LicenseCheck(ctx, input.Configuration, input.WorkspaceDirFS); err != nil {
		return fmt.Errorf("license check: %w", err)
	}
	return nil
}

// runSBOMGeneration generates SBOMs for all packages.
func (p *Processor) runSBOMGeneration(ctx context.Context, input *ProcessInput) error {
	if p.SBOM.Generator == nil {
		return nil
	}

	// Create a filesystem rooted at the melange-out directory for SBOM generation
	outfs, err := apkofs.Sub(input.WorkspaceDirFS, melangeOutputDirName)
	if err != nil {
		return fmt.Errorf("creating SBOM filesystem: %w", err)
	}

	genCtx := &sbom.GeneratorContext{
		Configuration:   input.Configuration,
		WorkspaceDir:    input.WorkspaceDir,
		OutputFS:        outfs,
		SourceDateEpoch: input.SourceDateEpoch,
		Namespace:       p.SBOM.Namespace,
		Arch:            input.Arch,
		ConfigFile:      p.SBOM.ConfigFile,
		ReleaseData:     p.SBOM.ReleaseData,
	}

	if err := p.SBOM.Generator.GenerateSBOM(ctx, genCtx); err != nil {
		return fmt.Errorf("generating SBOMs: %w", err)
	}

	return nil
}

// runEmit emits all packages.
func (p *Processor) runEmit(ctx context.Context, input *ProcessInput) error {
	if p.Emit.Emitter == nil {
		return nil
	}

	// Emit main package
	if err := p.Emit.Emitter(ctx, &input.Configuration.Package); err != nil {
		return fmt.Errorf("unable to emit package: %w", err)
	}

	// Emit subpackages
	for _, sp := range input.Configuration.Subpackages {
		pkg := pkgFromSub(&sp)
		if err := p.Emit.Emitter(ctx, pkg); err != nil {
			return fmt.Errorf("unable to emit package: %w", err)
		}
	}

	return nil
}

// runIndexGeneration generates the APKINDEX.
func (p *Processor) runIndexGeneration(ctx context.Context, input *ProcessInput) error {
	log := clog.FromContext(ctx)

	packageDir := filepath.Join(input.OutDir, input.Arch)
	log.Infof("generating apk index from packages in %s", packageDir)

	// Pre-allocate slice for main package + subpackages
	apkFiles := make([]string, 0, 1+len(input.Configuration.Subpackages))
	pkgFileName := fmt.Sprintf("%s-%s-r%d.apk",
		input.Configuration.Package.Name,
		input.Configuration.Package.Version,
		input.Configuration.Package.Epoch)
	apkFiles = append(apkFiles, filepath.Join(packageDir, pkgFileName))

	for _, subpkg := range input.Configuration.Subpackages {
		subpkgFileName := fmt.Sprintf("%s-%s-r%d.apk",
			subpkg.Name,
			input.Configuration.Package.Version,
			input.Configuration.Package.Epoch)
		apkFiles = append(apkFiles, filepath.Join(packageDir, subpkgFileName))
	}

	opts := []index.Option{
		index.WithPackageFiles(apkFiles),
		index.WithSigningKey(p.Index.SigningKey),
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

	return nil
}

// pkgFromSub creates a Package from a Subpackage.
func pkgFromSub(sub *config.Subpackage) *config.Package {
	return &config.Package{
		Name:         sub.Name,
		Dependencies: sub.Dependencies,
		Options:      sub.Options,
		Scriptlets:   sub.Scriptlets,
		Description:  sub.Description,
		URL:          sub.URL,
		Commit:       sub.Commit,
	}
}

// melangeOutputDirName is the name of the output directory within the workspace.
const melangeOutputDirName = "melange-out"
