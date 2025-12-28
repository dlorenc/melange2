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

package build

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

	"chainguard.dev/apko/pkg/apk/apk"
	apkofs "chainguard.dev/apko/pkg/apk/fs"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
	"github.com/chainguard-dev/clog"
	purl "github.com/package-url/packageurl-go"
	"github.com/zealic/xignore"
	"go.opentelemetry.io/otel"

	"github.com/dlorenc/melange2/pkg/build/sbom"
	"github.com/dlorenc/melange2/pkg/build/sbom/spdx"
	"github.com/dlorenc/melange2/pkg/config"
)

const melangeOutputDirName = "melange-out"

var gccLinkTemplate = `*link:
+ --package-metadata={"type":"apk","os":"{{.Namespace}}","name":"{{.Configuration.Package.Name}}","version":"{{.Configuration.Package.FullVersion}}","architecture":"{{.Arch.ToAPK}}"{{if .Configuration.Package.CPE.Vendor}},"appCpe":"{{.Configuration.Package.CPEString}}"{{end}}}
`

var ErrSkipThisArch = errors.New("error: skip this arch")

type Build struct {
	Configuration *config.Configuration

	// The name of the build configuration file, e.g. "crane.yaml".
	ConfigFile string

	// The URL of the git repository where the build configuration file is stored,
	// e.g. "https://github.com/wolfi-dev/os".
	ConfigFileRepositoryURL string

	// The commit hash of the git repository corresponding to the current state of
	// the build configuration file.
	ConfigFileRepositoryCommit string

	// The SPDX license string to use for the build configuration file.
	ConfigFileLicense string

	SourceDateEpoch time.Time
	WorkspaceDir    string
	WorkspaceDirFS  apkofs.FullFS
	WorkspaceIgnore string
	// Ordered directories where to find 'uses' pipelines.
	PipelineDirs          []string
	SourceDir             string
	SigningKey            string
	SigningPassphrase     string
	Namespace             string
	GenerateIndex         bool
	EmptyWorkspace        bool
	OutDir                string
	Arch                  apko_types.Architecture
	Libc                  string
	ExtraKeys             []string
	ExtraRepos            []string
	ExtraPackages         []string
	DependencyLog  string
	CreateBuildLog bool
	PersistLintResults    bool
	CacheDir        string
	ApkCacheDir     string
	StripOriginName bool
	EnvFile               string
	VarsFile              string
	BuildKitAddr          string // BuildKit daemon address
	Debug                 bool
	Remove                bool
	LintRequire, LintWarn []string
	Auth                  map[string]options.Auth
	IgnoreSignatures      bool

	EnabledBuildOptions []string

	// MaxLayers controls the maximum number of layers for the build environment.
	// When set to 1, a single layer is used (original behavior).
	// When set to a higher value (default 50), apko's multi-layer mode is used
	// for better BuildKit cache efficiency, splitting the environment into
	// multiple layers (base OS, compilers, package-specific deps) which
	// can be cached independently.
	MaxLayers int

	// ExportOnFailure specifies how to export the build environment on failure.
	// Valid values: "" (disabled), "tarball", "docker", "registry"
	ExportOnFailure string

	// ExportRef is the path or image reference for debug image export.
	// For tarball: file path (e.g., "/tmp/debug.tar")
	// For docker/registry: image reference (e.g., "debug:failed")
	ExportRef string

	// SBOMGenerator is the generator used to create SBOMs for this build.
	// If not set, defaults to DefaultSBOMGenerator.
	SBOMGenerator sbom.Generator

	// SBOMGroup stores SBOMs for the main package and all subpackages.
	SBOMGroup *SBOMGroup

	Start time.Time
	End   time.Time

	// Opt-in SLSA provenance generation for initial rollout/testing
	GenerateProvenance bool

	// The package resolver associated with this build.
	// Populated during buildGuestLayers when the apko environment is created.
	PkgResolver *apk.PkgResolver
}

func New(ctx context.Context, opts ...Option) (*Build, error) {
	b := Build{
		WorkspaceIgnore: ".melangeignore",
		SourceDir:       "", // Empty by default - use --source-dir to specify
		OutDir:          ".",
		CacheDir:        "./melange-cache/",
		Arch:            apko_types.ParseArchitecture(runtime.GOARCH),
		Start:           time.Now(),
		SBOMGenerator:   &spdx.Generator{},
	}

	for _, opt := range opts {
		if err := opt(&b); err != nil {
			return nil, err
		}
	}

	log := clog.FromContext(ctx).With("arch", b.Arch.ToAPK())
	ctx = clog.WithLogger(ctx, log)

	// If no workspace directory is explicitly requested, create a
	// temporary directory for it.  Otherwise, ensure we are in a
	// subdir for this specific build context.
	if b.WorkspaceDir != "" {
		b.WorkspaceDir = filepath.Join(b.WorkspaceDir, b.Arch.ToAPK())

		// Get the absolute path to the workspace dir, which is needed for bind
		// mounts.
		absdir, err := filepath.Abs(b.WorkspaceDir)
		if err != nil {
			return nil, fmt.Errorf("unable to resolve path %s: %w", b.WorkspaceDir, err)
		}

		b.WorkspaceDir = absdir
	} else {
		// Create a temporary workspace directory
		tmpdir, err := os.MkdirTemp("", "melange-workspace-*")
		if err != nil {
			return nil, fmt.Errorf("unable to create workspace dir: %w", err)
		}
		b.WorkspaceDir = tmpdir
	}

	// If no config file is explicitly requested for the build context
	// we check if .melange.yaml or melange.yaml exist.
	checks := []string{".melange.yaml", ".melange.yml", "melange.yaml", "melange.yml"}
	if b.ConfigFile == "" {
		for _, chk := range checks {
			if _, err := os.Stat(chk); err == nil {
				log.Infof("no configuration file provided -- using %s", chk)
				b.ConfigFile = chk
				break
			}
		}
	}

	// If no config file could be automatically detected, error.
	if b.ConfigFile == "" {
		return nil, fmt.Errorf("melange.yaml is missing")
	}
	if b.ConfigFileRepositoryURL == "" {
		return nil, fmt.Errorf("config file repository URL was not set")
	}
	if b.ConfigFileRepositoryCommit == "" {
		return nil, fmt.Errorf("config file repository commit was not set")
	}

	if b.Configuration == nil {
		parsedCfg, err := config.ParseConfiguration(ctx,
			b.ConfigFile,
			config.WithEnvFileForParsing(b.EnvFile),
			config.WithVarsFileForParsing(b.VarsFile),
			config.WithCommit(b.ConfigFileRepositoryCommit),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to load configuration: %w", err)
		}
		b.Configuration = parsedCfg
	}

	if len(b.Configuration.Package.TargetArchitecture) == 1 &&
		b.Configuration.Package.TargetArchitecture[0] == "all" {
		log.Warnf("target-architecture: ['all'] is deprecated and will become an error; remove this field to build for all available archs")
	} else if len(b.Configuration.Package.TargetArchitecture) != 0 &&
		!slices.Contains(b.Configuration.Package.TargetArchitecture, b.Arch.ToAPK()) {
		return nil, ErrSkipThisArch
	}

	// SOURCE_DATE_EPOCH will always overwrite the build flag
	if _, ok := os.LookupEnv("SOURCE_DATE_EPOCH"); ok {
		t, err := sourceDateEpoch(b.SourceDateEpoch)
		if err != nil {
			return nil, err
		}
		b.SourceDateEpoch = t
	}

	// Apply build options to the context.
	for _, optName := range b.EnabledBuildOptions {
		log.Infof("applying configuration patches for build option %s", optName)

		if opt, ok := b.Configuration.Options[optName]; ok {
			b.applyBuildOption(opt)
		}
	}

	return &b, nil
}

func (b *Build) Close(ctx context.Context) error {
	log := clog.FromContext(ctx)
	errs := []error{}
	if b.Remove {
		log.Debugf("deleting workspace dir %s", b.WorkspaceDir)
		errs = append(errs, os.RemoveAll(b.WorkspaceDir))
	}

	return errors.Join(errs...)
}

func copyFile(base, src, dest string, perm fs.FileMode) error {
	basePath := filepath.Join(base, src)
	destPath := filepath.Join(dest, src)
	destDir := filepath.Dir(destPath)

	inF, err := os.Open(basePath) // #nosec G304 - Internal build workspace file operation
	if err != nil {
		return err
	}
	defer inF.Close()

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("mkdir -p %s: %w", destDir, err)
	}

	outF, err := os.Create(destPath) // #nosec G304 - Internal build workspace file operation
	if err != nil {
		return fmt.Errorf("create %s: %w", destPath, err)
	}
	defer outF.Close()

	if _, err := io.Copy(outF, inF); err != nil {
		return err
	}

	if err := os.Chmod(destPath, perm); err != nil {
		return err
	}

	return nil
}

// applyBuildOption applies a patch described by a BuildOption to a package build.
func (b *Build) applyBuildOption(bo config.BuildOption) {
	// Patch the variables block.
	if b.Configuration.Vars == nil {
		b.Configuration.Vars = make(map[string]string)
	}

	maps.Copy(b.Configuration.Vars, bo.Vars)

	// Patch the build environment configuration.
	lo := bo.Environment.Contents.Packages
	b.Configuration.Environment.Contents.Packages = append(b.Configuration.Environment.Contents.Packages, lo.Add...)

	for _, pkg := range lo.Remove {
		pkgList := b.Configuration.Environment.Contents.Packages

		for pos, ppkg := range pkgList {
			if pkg == ppkg {
				pkgList[pos] = pkgList[len(pkgList)-1]
				pkgList = pkgList[:len(pkgList)-1]
			}
		}

		b.Configuration.Environment.Contents.Packages = pkgList
	}
}

func (b *Build) loadIgnoreRules(ctx context.Context) ([]*xignore.Pattern, error) {
	log := clog.FromContext(ctx)
	ignorePath := filepath.Join(b.SourceDir, b.WorkspaceIgnore)

	ignorePatterns := []*xignore.Pattern{}

	if _, err := os.Stat(ignorePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ignorePatterns, nil
		}

		return nil, err
	}

	log.Infof("loading ignore rules from %s", ignorePath)

	inF, err := os.Open(ignorePath) // #nosec G304 - Reading workspace ignore file from build configuration
	if err != nil {
		return nil, err
	}
	defer inF.Close()

	ignF := xignore.Ignorefile{}
	if err := ignF.FromReader(inF); err != nil {
		return nil, err
	}

	for _, rule := range ignF.Patterns {
		pattern := xignore.NewPattern(rule)

		if err := pattern.Prepare(); err != nil {
			return nil, err
		}

		ignorePatterns = append(ignorePatterns, pattern)
	}

	return ignorePatterns, nil
}

// getBuildConfigPURL determines the package URL for the melange config file
// itself.
func (b Build) getBuildConfigPURL() (*purl.PackageURL, error) {
	namespace, name, found := strings.Cut(strings.TrimPrefix(b.ConfigFileRepositoryURL, "https://github.com/"), "/")
	if !found {
		return nil, fmt.Errorf("extracting namespace and name from %s", b.ConfigFileRepositoryURL)
	}

	u := &purl.PackageURL{
		Type:      purl.TypeGithub,
		Namespace: namespace,
		Name:      name,
		Version:   b.ConfigFileRepositoryCommit,
		Subpath:   b.ConfigFile,
	}
	if err := u.Normalize(); err != nil {
		return nil, fmt.Errorf("normalizing PURL: %w", err)
	}
	return u, nil
}

func (b *Build) populateWorkspace(ctx context.Context, src fs.FS) error {
	log := clog.FromContext(ctx)
	_, span := otel.Tracer("melange").Start(ctx, "populateWorkspace")
	defer span.End()

	ignorePatterns, err := b.loadIgnoreRules(ctx)
	if err != nil {
		return err
	}

	// Write out build settings into workspacedir
	// For now, just the gcc spec file and just link settings.
	// In the future can control debug symbol generation, march/mtune, etc.
	specFile, err := os.Create(filepath.Join(b.WorkspaceDir, ".melange.gcc.spec"))
	if err != nil {
		return err
	}
	specTemplate := template.New("gccSpecFile")
	if err := template.Must(specTemplate.Parse(gccLinkTemplate)).Execute(specFile, b); err != nil {
		return err
	}
	if err := specFile.Close(); err != nil {
		return err
	}
	return fs.WalkDir(src, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		fi, err := d.Info()
		if err != nil {
			return err
		}

		mode := fi.Mode()
		if !mode.IsRegular() {
			return nil
		}

		for _, pat := range ignorePatterns {
			if pat.Match(path) {
				return nil
			}
		}

		log.Debugf("  -> %s", path)

		if err := copyFile(b.SourceDir, path, b.WorkspaceDir, mode.Perm()); err != nil {
			return err
		}

		return nil
	})
}

type linterTarget struct {
	pkgName  string
	disabled []string // checks that are downgraded from required -> warn
}

func (b *Build) BuildPackage(ctx context.Context) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "BuildPackage")
	defer span.End()

	// All builds use BuildKit
	return b.buildPackageBuildKit(ctx)
}

func (b *Build) SummarizePaths(ctx context.Context) {
	log := clog.FromContext(ctx)
	log.Debugf("  workspace dir: %s", b.WorkspaceDir)
}

// buildFlavor determines if a build context uses glibc or musl, it returns
// "gnu" for GNU systems, and "musl" for musl systems.
func (b *Build) buildFlavor() string {
	if b.Libc == "" {
		return "gnu"
	}
	return b.Libc
}

// sourceDateEpoch parses the SOURCE_DATE_EPOCH environment variable.
// If it is not set, it returns the defaultTime.
// If it is set, it MUST be an ASCII representation of an integer.
// If it is malformed, it returns an error.
func sourceDateEpoch(defaultTime time.Time) (time.Time, error) {
	v := strings.TrimSpace(os.Getenv("SOURCE_DATE_EPOCH"))
	if v == "" {
		clog.DefaultLogger().Warnf("SOURCE_DATE_EPOCH is specified but empty, setting it to %v", defaultTime)
		return defaultTime, nil
	}

	// The value MUST be an ASCII representation of an integer
	// with no fractional component, identical to the output
	// format of date +%s.
	sec, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		// If the value is malformed, the build process
		// SHOULD exit with a non-zero error code.
		return defaultTime, fmt.Errorf("failed to parse SOURCE_DATE_EPOCH: %w", err)
	}

	return time.Unix(sec, 0).UTC(), nil
}
