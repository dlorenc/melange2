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

package config

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	apko_types "chainguard.dev/apko/pkg/build/types"
	purl "github.com/package-url/packageurl-go"

	"github.com/dlorenc/melange2/pkg/sbom"

	"github.com/chainguard-dev/clog"
	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

const (
	buildUser   = "build"
	purlTypeAPK = "apk"
)

type Trigger struct {
	// Optional: The script to run
	Script string `json:"script,omitempty"`
	// Optional: The list of paths to monitor to trigger the script
	Paths []string `json:"paths,omitempty"`
}

type Scriptlets struct {
	// Optional: A script to run on a custom trigger
	Trigger Trigger `json:"trigger" yaml:"trigger,omitempty"`
	// Optional: The script to run pre install. The script should contain the
	// shebang interpreter.
	PreInstall string `json:"pre-install,omitempty" yaml:"pre-install,omitempty"`
	// Optional: The script to run post install. The script should contain the
	// shebang interpreter.
	PostInstall string `json:"post-install,omitempty" yaml:"post-install,omitempty"`
	// Optional: The script to run before uninstalling. The script should contain
	// the shebang interpreter.
	PreDeinstall string `json:"pre-deinstall,omitempty" yaml:"pre-deinstall,omitempty"`
	// Optional: The script to run after uninstalling. The script should contain
	// the shebang interpreter.
	PostDeinstall string `json:"post-deinstall,omitempty" yaml:"post-deinstall,omitempty"`
	// Optional: The script to run before upgrading. The script should contain
	// the shebang interpreter.
	PreUpgrade string `json:"pre-upgrade,omitempty" yaml:"pre-upgrade,omitempty"`
	// Optional: The script to run after upgrading. The script should contain the
	// shebang interpreter.
	PostUpgrade string `json:"post-upgrade,omitempty" yaml:"post-upgrade,omitempty"`
}

type PackageOption struct {
	// Optional: Signify this package as a virtual package which does not provide
	// any files, executables, libraries, etc... and is otherwise empty
	NoProvides bool `json:"no-provides,omitempty" yaml:"no-provides,omitempty"`
	// Optional: Mark this package as a self contained package that does not
	// depend on any other package
	NoDepends bool `json:"no-depends,omitempty" yaml:"no-depends,omitempty"`
	// Optional: Mark this package as not providing any executables
	NoCommands bool `json:"no-commands,omitempty" yaml:"no-commands,omitempty"`
	// Optional: Don't generate versioned depends for shared libraries
	NoVersionedShlibDeps bool `json:"no-versioned-shlib-deps,omitempty" yaml:"no-versioned-shlib-deps,omitempty"`
}

type Checks struct {
	// Optional: disable these linters that are not enabled by default.
	Disabled []string `json:"disabled,omitempty" yaml:"disabled,omitempty"`
}

type Package struct {
	// The name of the package
	Name string `json:"name" yaml:"name"`
	// The version of the package
	Version string `json:"version" yaml:"version"`
	// The monotone increasing epoch of the package
	Epoch uint64 `json:"epoch" yaml:"epoch"`
	// A human-readable description of the package
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Annotations for this package
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	// The URL to the package's homepage
	URL string `json:"url,omitempty" yaml:"url,omitempty"`
	// Optional: The git commit of the package build configuration
	Commit string `json:"commit,omitempty" yaml:"commit,omitempty"`
	// List of target architectures for which this package should be build for
	TargetArchitecture []string `json:"target-architecture,omitempty" yaml:"target-architecture,omitempty"`
	// The list of copyrights for this package
	Copyright []Copyright `json:"copyright,omitempty" yaml:"copyright,omitempty"`
	// List of packages to depends on
	Dependencies Dependencies `json:"dependencies" yaml:"dependencies,omitempty"`
	// Optional: Options that alter the packages behavior
	Options *PackageOption `json:"options,omitempty" yaml:"options,omitempty"`
	// Optional: Executable scripts that run at various stages of the package
	// lifecycle, triggered by configurable events
	Scriptlets *Scriptlets `json:"scriptlets,omitempty" yaml:"scriptlets,omitempty"`
	// Optional: enabling, disabling, and configuration of build checks
	Checks Checks `json:"checks" yaml:"checks,omitempty"`
	// The CPE field values to be used for matching against NVD vulnerability
	// records, if known.
	CPE CPE `json:"cpe" yaml:"cpe,omitempty"`
	// Capabilities to set after the pipeline completes.
	SetCap []Capability `json:"setcap,omitempty" yaml:"setcap,omitempty"`

	// Optional: The amount of time to allow this build to take before timing out.
	Timeout time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	// Optional: Resources to allocate to the build.
	Resources *Resources `json:"resources,omitempty" yaml:"resources,omitempty"`
	// Optional: Resources to allocate for test execution.
	// Used by external schedulers (like elastic build) to provision
	// appropriately-sized test pods/VMs. If not specified, falls back
	// to Resources.
	TestResources *Resources `json:"test-resources,omitempty" yaml:"test-resources,omitempty"`
}

// CPE stores values used to produce a CPE to describe the package, suitable for
// matching against NVD records.
//
// Based on the spec found at
// https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf.
//
// For Melange, the "part" attribute should always be interpreted as "a" (for
// "application") unless otherwise specified.
//
// The "Version" and "Update" fields have been intentionally left out of the CPE
// struct to avoid confusion with the version information of the package itself.
type CPE struct {
	Part      string `json:"part,omitempty" yaml:"part,omitempty"`
	Vendor    string `json:"vendor,omitempty" yaml:"vendor,omitempty"`
	Product   string `json:"product,omitempty" yaml:"product,omitempty"`
	Edition   string `json:"edition,omitempty" yaml:"edition,omitempty"`
	Language  string `json:"language,omitempty" yaml:"language,omitempty"`
	SWEdition string `json:"sw_edition,omitempty" yaml:"sw_edition,omitempty"`
	TargetSW  string `json:"target_sw,omitempty" yaml:"target_sw,omitempty"`
	TargetHW  string `json:"target_hw,omitempty" yaml:"target_hw,omitempty"`
	Other     string `json:"other,omitempty" yaml:"other,omitempty"`
}

func (cpe CPE) IsZero() bool {
	return cpe == CPE{}
}

type Resources struct {
	CPU      string `json:"cpu,omitempty" yaml:"cpu,omitempty"`
	CPUModel string `json:"cpumodel,omitempty" yaml:"cpumodel,omitempty"`
	Memory   string `json:"memory,omitempty" yaml:"memory,omitempty"`
	Disk     string `json:"disk,omitempty" yaml:"disk,omitempty"`
}

// CPEString returns the CPE string for the package, suitable for matching
// against NVD records.
func (p Package) CPEString() (string, error) {
	const anyValue = "*"
	const partApplication = "a"

	part := partApplication
	if p.CPE.Part != "" {
		part = p.CPE.Part
	}
	vendor := anyValue
	if p.CPE.Vendor != "" {
		vendor = p.CPE.Vendor
	}
	product := anyValue
	if p.CPE.Product != "" {
		product = p.CPE.Product
	}
	edition := anyValue
	if p.CPE.Edition != "" {
		edition = p.CPE.Edition
	}
	language := anyValue
	if p.CPE.Language != "" {
		language = p.CPE.Language
	}
	swEdition := anyValue
	if p.CPE.SWEdition != "" {
		swEdition = p.CPE.SWEdition
	}
	targetSW := anyValue
	if p.CPE.TargetSW != "" {
		targetSW = p.CPE.TargetSW
	}
	targetHW := anyValue
	if p.CPE.TargetHW != "" {
		targetHW = p.CPE.TargetHW
	}
	other := anyValue
	if p.CPE.Other != "" {
		other = p.CPE.Other
	}

	// Last-mile validation to avoid headaches downstream of this.
	if !slices.Contains([]string{"a", "h", "o"}, part) {
		return "", fmt.Errorf("part value must be a, h or o")
	}
	if vendor == anyValue {
		return "", fmt.Errorf("vendor value must be exactly specified")
	}
	if product == anyValue {
		return "", fmt.Errorf("product value must be exactly specified")
	}

	return fmt.Sprintf(
		"cpe:2.3:%s:%s:%s:%s:*:%s:%s:%s:%s:%s:%s",
		part,
		vendor,
		product,
		p.Version,
		edition,
		language,
		swEdition,
		targetSW,
		targetHW,
		other,
	), nil
}

// PackageURL returns the package URL ("purl") for the APK (origin) package.
func (p Package) PackageURL(distro, arch string) *purl.PackageURL {
	return newAPKPackageURL(distro, p.Name, p.FullVersion(), arch)
}

// PackageURLForSubpackage returns the package URL ("purl") for the APK
// subpackage.
func (p Package) PackageURLForSubpackage(distro, arch, subpackage string) *purl.PackageURL {
	return newAPKPackageURL(distro, subpackage, p.FullVersion(), arch)
}

func newAPKPackageURL(distro, name, version, arch string) *purl.PackageURL {
	u := &purl.PackageURL{
		Type:      purlTypeAPK,
		Namespace: distro,
		Name:      name,
		Version:   version,
	}

	if distro != "unknown" {
		u.Qualifiers = append(u.Qualifiers, purl.Qualifier{
			Key:   "distro",
			Value: distro,
		})
	}

	if arch != "" {
		u.Qualifiers = append(u.Qualifiers, purl.Qualifier{
			Key:   "arch",
			Value: arch,
		})
	}

	return u
}

// FullVersion returns the full version of the APK package produced by the
// build, including the epoch.
func (p Package) FullVersion() string {
	return fmt.Sprintf("%s-r%d", p.Version, p.Epoch)
}

type Copyright struct {
	// Optional: The license paths, typically '*'
	Paths []string `json:"paths,omitempty" yaml:"paths,omitempty"`
	// Optional: Attestations of the license
	Attestation string `json:"attestation,omitempty" yaml:"attestation,omitempty"`
	// Required: The license for this package
	License string `json:"license" yaml:"license"`
	// Optional: Path to text of the custom License Ref
	LicensePath string `json:"license-path,omitempty" yaml:"license-path,omitempty"`
	// Optional: License override
	DetectionOverride string `json:"detection-override,omitempty" yaml:"detection-override,omitempty"`
}

// LicenseExpression returns an SPDX license expression formed from the data in
// the copyright structs found in the conf. It's a simple OR for now.
func (p Package) LicenseExpression() string {
	licenseExpression := ""
	if p.Copyright == nil {
		return licenseExpression
	}
	for _, cp := range p.Copyright {
		if licenseExpression != "" {
			licenseExpression += " AND "
		}
		licenseExpression += cp.License
	}
	return licenseExpression
}

// LicensingInfos looks at the `Package.Copyright[].LicensePath` fields of the
// parsed build configuration for the package. If this value has been set,
// LicensingInfos opens the file at this path from the build's workspace
// directory, and reads in the license content. LicensingInfos then returns a
// map of the `Copyright.License` field to the string content of the file from
// `.LicensePath`.
func (p Package) LicensingInfos(workspaceDir string) (map[string]string, error) {
	licenseInfos := make(map[string]string)
	for _, cp := range p.Copyright {
		if cp.LicensePath != "" {
			content, err := os.ReadFile(filepath.Join(workspaceDir, cp.LicensePath)) // #nosec G304 - Reading license file from build workspace
			if err != nil {
				return nil, fmt.Errorf("failed to read licensepath %q: %w", cp.LicensePath, err)
			}
			licenseInfos[cp.License] = string(content)
		}
	}
	return licenseInfos, nil
}

// FullCopyright returns the concatenated copyright expressions defined
// in the configuration file.
func (p Package) FullCopyright() string {
	copyright := ""
	for _, cp := range p.Copyright {
		if cp.Attestation != "" {
			copyright += cp.Attestation + "\n"
		}
	}
	// No copyright found, instead of omitting the field declare
	// that no determination was attempted, which is better than a
	// whitespace (which should also be interpreted as
	// NOASSERTION)
	if copyright == "" {
		copyright = "NOASSERTION"
	}
	return copyright
}

type Needs struct {
	// A list of packages needed by this pipeline
	Packages []string
}

type PipelineAssertions struct {
	// The number (an int) of required steps that must complete successfully
	// within the asserted pipeline.
	RequiredSteps int `json:"required-steps,omitempty" yaml:"required-steps,omitempty"`
}

type Pipeline struct {
	// Optional: A condition to evaluate before running the pipeline
	If string `json:"if,omitempty" yaml:"if,omitempty"`
	// Optional: A user defined name for the pipeline
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Optional: A named reusable pipeline to run
	//
	// This can be either a pipeline builtin to melange, or a user defined named pipeline.
	// For example, to use a builtin melange pipeline:
	// 		uses: autoconf/make
	Uses string `json:"uses,omitempty" yaml:"uses,omitempty"`
	// Optional: Arguments passed to the reusable pipelines defined in `uses`
	With map[string]string `json:"with,omitempty" yaml:"with,omitempty"`
	// Optional: The command to run using the builder's shell (/bin/sh)
	Runs string `json:"runs,omitempty" yaml:"runs,omitempty"`
	// Optional: The list of pipelines to run.
	//
	// Each pipeline runs in its own context that is not shared between other
	// pipelines. To share context between pipelines, nest a pipeline within an
	// existing pipeline. This can be useful when you wish to share common
	// configuration, such as an alternative `working-directory`.
	Pipeline []Pipeline `json:"pipeline,omitempty" yaml:"pipeline,omitempty"`
	// Optional: A map of inputs to the pipeline
	Inputs map[string]Input `json:"inputs,omitempty" yaml:"inputs,omitempty"`
	// Optional: Configuration to determine any explicit dependencies this pipeline may have
	Needs *Needs `json:"needs,omitempty" yaml:"needs,omitempty"`
	// Optional: Labels to apply to the pipeline
	Label string `json:"label,omitempty" yaml:"label,omitempty"`
	// Optional: Assertions to evaluate whether the pipeline was successful
	Assertions *PipelineAssertions `json:"assertions,omitempty" yaml:"assertions,omitempty"`
	// Optional: The working directory of the pipeline
	//
	// This defaults to the guests' build workspace (/home/build)
	WorkDir string `json:"working-directory,omitempty" yaml:"working-directory,omitempty"`
	// Optional: environment variables to override apko
	Environment map[string]string `json:"environment,omitempty" yaml:"environment,omitempty"`
}

// SHA256 generates a digest based on the text provided
// Returns a hex encoded string
func SHA256(text string) string {
	algorithm := sha256.New()
	algorithm.Write([]byte(text))
	return hex.EncodeToString(algorithm.Sum(nil))
}

// getGitSBOMPackage creates an SBOM package for Git based repositories.
// Returns nil package and nil error if the repository is not from a supported platform or
// if neither a tag of expectedCommit is not provided
func getGitSBOMPackage(repo, tag, expectedCommit string, idComponents []string, licenseDeclared, hint, supplier string) (*sbom.Package, error) {
	var repoType, namespace, name, ref string
	var downloadLocation string

	repoURL, err := url.Parse(repo)
	if err != nil {
		return nil, err
	}

	switch {
	case expectedCommit != "":
		ref = expectedCommit
	case tag != "":
		ref = tag
	default:
		return nil, nil
	}

	trimmedPath := strings.TrimPrefix(repoURL.Path, "/")
	namespace, name, _ = strings.Cut(trimmedPath, "/")
	name = strings.TrimSuffix(name, ".git")

	switch {
	case repoURL.Host == "github.com":
		repoType = purl.TypeGithub
		downloadLocation = fmt.Sprintf("%s://github.com/%s/%s/archive/%s.tar.gz", repoURL.Scheme, namespace, name, ref)

	case repoURL.Host == "gitlab.com":
		repoType = purl.TypeGitlab
		downloadLocation = fmt.Sprintf("%s://gitlab.com/%s/%s/-/archive/%s/%s.tar.gz", repoURL.Scheme, namespace, name, ref, ref)

	case strings.HasPrefix(repoURL.Host, "gitlab") || hint == "gitlab":
		repoType = purl.TypeGeneric
		downloadLocation = fmt.Sprintf("%s://%s/%s/%s/-/archive/%s/%s.tar.gz", repoURL.Scheme, repoURL.Host, namespace, name, ref, ref)

	default:
		repoType = purl.TypeGeneric
		// We can't determine the namespace so use the supplier passed instead.
		namespace = supplier
		name = strings.TrimSuffix(trimmedPath, ".git")
		// Use first letter of name as a directory to avoid a single huge bucket of tarballs
		downloadLocation = fmt.Sprintf("https://tarballs.cgr.dev/%s/%s-%s.tar.gz", name[:1], SHA256(name), ref)
	}

	// Prefer tag to commit, but use only ONE of these.
	versions := []string{
		tag,
		expectedCommit,
	}

	// Encode vcs_url with git+ prefix and @commit suffix
	var vcsUrl string
	if !strings.HasPrefix(repo, "git") {
		vcsUrl = "git+" + repo
	} else {
		vcsUrl = repo
	}

	if expectedCommit != "" {
		vcsUrl += "@" + expectedCommit
	}

	for _, v := range versions {
		if v == "" {
			continue
		}

		var pu *purl.PackageURL

		switch repoType {
		case purl.TypeGithub, purl.TypeGitlab:
			pu = &purl.PackageURL{
				Type:      repoType,
				Namespace: namespace,
				Name:      name,
				Version:   v,
			}
		case purl.TypeGeneric:
			pu = &purl.PackageURL{
				Type:       "generic",
				Name:       name,
				Version:    v,
				Qualifiers: purl.QualifiersFromMap(map[string]string{"vcs_url": vcsUrl}),
			}
		}

		if err := pu.Normalize(); err != nil {
			return nil, err
		}

		return &sbom.Package{
			IDComponents:     idComponents,
			Name:             name,
			Version:          v,
			LicenseDeclared:  licenseDeclared,
			Namespace:        namespace,
			PURL:             pu,
			DownloadLocation: downloadLocation,
		}, nil
	}

	// If we get here, we have a repo but no tag or commit. Without version
	// information, we can't create a sensible SBOM package.
	return nil, nil
}

// SBOMPackageForUpstreamSource returns an SBOM package for the upstream source
// of the package, if this Pipeline step was used to bring source code from an
// upstream project into the build. This function helps with generating SBOMs
// for the package being built. If the pipeline step is not a fetch or
// git-checkout step, this function returns nil and no error.
func (p Pipeline) SBOMPackageForUpstreamSource(licenseDeclared, supplier string, uniqueID string) (*sbom.Package, error) {
	// TODO: It'd be great to detect the license from the source code itself. Such a
	//  feature could even eliminate the need for the package's license field in the
	//  build configuration.

	uses, with := p.Uses, p.With

	switch uses {
	case "fetch":
		args := make(map[string]string)
		args["download_url"] = with["uri"]
		checksums := make(map[string]string)

		expectedSHA256 := with["expected-sha256"]
		if len(expectedSHA256) > 0 {
			args["checksum"] = "sha256:" + expectedSHA256
			checksums["SHA256"] = expectedSHA256
		}
		expectedSHA512 := with["expected-sha512"]
		if len(expectedSHA512) > 0 {
			args["checksum"] = "sha512:" + expectedSHA512
			checksums["SHA512"] = expectedSHA512
		}

		// These get defaulted correctly from within the fetch pipeline definition
		// (YAML) itself.
		pkgName := with["purl-name"]
		pkgVersion := with["purl-version"]

		pu := &purl.PackageURL{
			Type:       "generic",
			Name:       pkgName,
			Version:    pkgVersion,
			Qualifiers: purl.QualifiersFromMap(args),
		}
		if err := pu.Normalize(); err != nil {
			return nil, err
		}

		idComponents := []string{pkgName, pkgVersion}
		if uniqueID != "" {
			idComponents = append(idComponents, uniqueID)
		}

		return &sbom.Package{
			IDComponents:     idComponents,
			Name:             pkgName,
			Version:          pkgVersion,
			Namespace:        supplier,
			Checksums:        checksums,
			PURL:             pu,
			DownloadLocation: args["download_url"],
		}, nil

	case "git-checkout":
		repo := with["repository"]
		branch := with["branch"]
		tag := with["tag"]
		expectedCommit := with["expected-commit"]
		hint := with["type-hint"]

		// We'll use all available data to ensure our SBOM's package ID is unique, even
		// when the same repo is git-checked out multiple times.
		var idComponents []string
		repoCleaned := func() string {
			s := strings.TrimPrefix(repo, "https://")
			s = strings.TrimPrefix(s, "http://")
			return s
		}()
		for _, component := range []string{repoCleaned, branch, tag, expectedCommit} {
			if component != "" {
				idComponents = append(idComponents, component)
			}
		}
		if uniqueID != "" {
			idComponents = append(idComponents, uniqueID)
		}

		gitPackage, err := getGitSBOMPackage(repo, tag, expectedCommit, idComponents, licenseDeclared, hint, supplier)
		if err != nil {
			return nil, err
		} else if gitPackage != nil {
			return gitPackage, nil
		}
	}

	// This is not a fetch or git-checkout step.

	return nil, nil
}

type Subpackage struct {
	// Optional: A conditional statement to evaluate for the subpackage
	If string `json:"if,omitempty" yaml:"if,omitempty"`
	// Optional: The iterable used to generate multiple subpackages
	Range string `json:"range,omitempty" yaml:"range,omitempty"`
	// Required: Name of the subpackage
	Name string `json:"name" yaml:"name"`
	// Optional: The list of pipelines that produce subpackage.
	Pipeline []Pipeline `json:"pipeline,omitempty" yaml:"pipeline,omitempty"`
	// Optional: List of packages to depend on
	Dependencies Dependencies `json:"dependencies" yaml:"dependencies,omitempty"`
	// Optional: Options that alter the packages behavior
	Options    *PackageOption `json:"options,omitempty" yaml:"options,omitempty"`
	Scriptlets *Scriptlets    `json:"scriptlets,omitempty" yaml:"scriptlets,omitempty"`
	// Optional: The human readable description of the subpackage
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	// Optional: The URL to the package's homepage
	URL string `json:"url,omitempty" yaml:"url,omitempty"`
	// Optional: The git commit of the subpackage build configuration
	Commit string `json:"commit,omitempty" yaml:"commit,omitempty"`
	// Optional: enabling, disabling, and configuration of build checks
	Checks Checks `json:"checks" yaml:"checks,omitempty"`
	// Test section for the subpackage.
	Test *Test `json:"test,omitempty" yaml:"test,omitempty"`
	// Capabilities to set after the pipeline completes.
	SetCap []Capability `json:"setcap,omitempty" yaml:"setcap,omitempty"`
}

type Input struct {
	// Optional: The human-readable description of the input
	Description string `json:"description,omitempty"`
	// Optional: The default value of the input. Required when the input is.
	Default string `json:"default,omitempty"`
	// Optional: A toggle denoting whether the input is required or not
	Required bool `json:"required,omitempty"`
}

// Capabilities is the configuration for Linux capabilities for the runner.
type Capabilities struct {
	// Linux process capabilities to add to the pipeline container.
	Add []string `json:"add,omitempty" yaml:"add,omitempty"`
	// Linux process capabilities to drop from the pipeline container.
	Drop []string `json:"drop,omitempty" yaml:"drop,omitempty"`
}

// Configuration is the root melange configuration.
type Configuration struct {
	// Package metadata
	Package Package `json:"package" yaml:"package"`
	// The specification for the packages build environment
	// Optional: environment variables to override apko
	Environment apko_types.ImageConfiguration `json:"environment" yaml:"environment,omitempty"`
	// Optional: Linux capabilities configuration to apply to the melange runner.
	Capabilities Capabilities `json:"capabilities" yaml:"capabilities,omitempty"`

	// Required: The list of pipelines that produce the package.
	Pipeline []Pipeline `json:"pipeline,omitempty" yaml:"pipeline,omitempty"`
	// Optional: The list of subpackages that this package also produces.
	Subpackages []Subpackage `json:"subpackages,omitempty" yaml:"subpackages,omitempty"`
	// Optional: An arbitrary list of data that can be used via templating in the
	// pipeline
	Data []RangeData `json:"data,omitempty" yaml:"data,omitempty"`
	// Optional: The update block determining how this package is auto updated
	Update Update `json:"update" yaml:"update,omitempty"`
	// Optional: A map of arbitrary variables that can be used via templating in
	// the pipeline
	Vars map[string]string `json:"vars,omitempty" yaml:"vars,omitempty"`
	// Optional: A list of transformations to create for the builtin template
	// variables
	VarTransforms []VarTransforms `json:"var-transforms,omitempty" yaml:"var-transforms,omitempty"`
	// Optional: Deviations to the build
	Options map[string]BuildOption `json:"options,omitempty" yaml:"options,omitempty"`

	// Test section for the main package.
	Test *Test `json:"test,omitempty" yaml:"test,omitempty"`

	// Parsed AST for this configuration
	root *yaml.Node
}

// AllPackageNames returns a sequence of all package names in the configuration,
// i.e. the origin package name and the names of all subpackages.
func (cfg Configuration) AllPackageNames() iter.Seq[string] {
	return func(yield func(string) bool) {
		if !yield(cfg.Package.Name) {
			return
		}

		for _, sp := range cfg.Subpackages {
			if !yield(sp.Name) {
				return
			}
		}
	}
}

type Test struct {
	// Additional Environment necessary for test.
	// Environment.Contents.Packages automatically get
	// package.dependencies.runtime added to it. So, if your test needs
	// no additional packages, you can leave it blank.
	// Optional: Additional Environment the test needs to run
	Environment apko_types.ImageConfiguration `json:"environment" yaml:"environment,omitempty"`

	// Required: The list of pipelines that test the produced package.
	Pipeline []Pipeline `json:"pipeline" yaml:"pipeline"`
}

// Name returns a name for the configuration, using the package name. This
// implements the configs.Configuration interface in wolfictl and is important
// to keep as long as that package is in use.
func (cfg Configuration) Name() string {
	return cfg.Package.Name
}

type VarTransforms struct {
	// Required: The original template variable.
	//
	// Example: ${{package.version}}
	From string `json:"from" yaml:"from"`
	// Required: The regular expression to match against the `from` variable
	Match string `json:"match" yaml:"match"`
	// Required: The repl to replace on all `match` matches
	Replace string `json:"replace" yaml:"replace"`
	// Required: The name of the new variable to create
	//
	// Example: mangeled-package-version
	To string `json:"to" yaml:"to"`
}

// Update provides information used to describe how to keep the package up to date
type Update struct {
	// Toggle if updates should occur
	Enabled bool `json:"enabled" yaml:"enabled"`
	// Indicates that this package should be manually updated, usually taking
	// care over special version numbers
	Manual bool `json:"manual,omitempty" yaml:"manual"`
	// Indicates that automated pull requests should be merged in order rather than superseding and closing previous unmerged PRs
	RequireSequential bool `json:"require-sequential,omitempty" yaml:"require-sequential"`
	// Indicate that an update to this package requires an epoch bump of
	// downstream dependencies, e.g. golang, java
	Shared bool `json:"shared,omitempty" yaml:"shared,omitempty"`
	// Override the version separator if it is nonstandard
	VersionSeparator string `json:"version-separator,omitempty" yaml:"version-separator,omitempty"`
	// A slice of regex patterns to match an upstream version and ignore
	IgnoreRegexPatterns []string `json:"ignore-regex-patterns,omitempty" yaml:"ignore-regex-patterns,omitempty"`
	// The configuration block for updates tracked via release-monitoring.org
	ReleaseMonitor *ReleaseMonitor `json:"release-monitor,omitempty" yaml:"release-monitor,omitempty"`
	// The configuration block for updates tracked via the Github API
	GitHubMonitor *GitHubMonitor `json:"github,omitempty" yaml:"github,omitempty"`
	// The configuration block for updates tracked via Git
	GitMonitor *GitMonitor `json:"git,omitempty" yaml:"git,omitempty"`
	// The configuration block for transforming the `package.version` into an APK version
	VersionTransform []VersionTransform `json:"version-transform,omitempty" yaml:"version-transform,omitempty"`
	// ExcludeReason is required if enabled=false, to explain why updates are disabled.
	ExcludeReason string `json:"exclude-reason,omitempty" yaml:"exclude-reason,omitempty"`
	// Schedule defines the schedule for the update check to run
	Schedule *Schedule `json:"schedule,omitempty" yaml:"schedule,omitempty"`
	// Optional: Disables filtering of common pre-release tags
	EnablePreReleaseTags bool `json:"enable-prerelease-tags,omitempty" yaml:"enable-prerelease-tags,omitempty"`
}

// ReleaseMonitor indicates using the API for https://release-monitoring.org/
type ReleaseMonitor struct {
	// Required: ID number for release monitor
	Identifier int `json:"identifier" yaml:"identifier"`
	// If the version in release monitor contains a prefix which should be ignored
	StripPrefix string `json:"strip-prefix,omitempty" yaml:"strip-prefix,omitempty"`
	// If the version in release monitor contains a suffix which should be ignored
	StripSuffix string `json:"strip-suffix,omitempty" yaml:"strip-suffix,omitempty"`
	// Filter to apply when searching version on a Release Monitoring
	VersionFilterContains string `json:"version-filter-contains,omitempty" yaml:"version-filter-contains,omitempty"`
	// Filter to apply when searching version Release Monitoring
	VersionFilterPrefix string `json:"version-filter-prefix,omitempty" yaml:"version-filter-prefix,omitempty"`
}

// VersionHandler is an interface that defines methods for retrieving version filtering and stripping parameters.
// It is used to provide a common interface for handling version-related operations for different types of version monitors.
type VersionHandler interface {
	GetStripPrefix() string
	GetStripSuffix() string
	GetFilterPrefix() string
	GetFilterContains() string
}

// GitHubMonitor indicates using the GitHub API
type GitHubMonitor struct {
	// Org/repo for GitHub
	Identifier string `json:"identifier" yaml:"identifier"`
	// If the version in GitHub contains a prefix which should be ignored
	StripPrefix string `json:"strip-prefix,omitempty" yaml:"strip-prefix,omitempty"`
	// If the version in GitHub contains a suffix which should be ignored
	StripSuffix string `json:"strip-suffix,omitempty" yaml:"strip-suffix,omitempty"`
	// Filter to apply when searching tags on a GitHub repository
	//
	// Deprecated: Use TagFilterPrefix instead
	TagFilter string `json:"tag-filter,omitempty" yaml:"tag-filter,omitempty"`
	// Prefix filter to apply when searching tags on a GitHub repository
	TagFilterPrefix string `json:"tag-filter-prefix,omitempty" yaml:"tag-filter-prefix,omitempty"`
	// Filter to apply when searching tags on a GitHub repository
	TagFilterContains string `json:"tag-filter-contains,omitempty" yaml:"tag-filter-contains,omitempty"`
	// Override the default of using a GitHub release to identify related tag to
	// fetch.  Not all projects use GitHub releases but just use tags
	UseTags bool `json:"use-tag,omitempty" yaml:"use-tag,omitempty"`
}

// GitMonitor indicates using Git
type GitMonitor struct {
	// StripPrefix is the prefix to strip from the version
	StripPrefix string `json:"strip-prefix,omitempty" yaml:"strip-prefix,omitempty"`
	// If the version in GitHub contains a suffix which should be ignored
	StripSuffix string `json:"strip-suffix,omitempty" yaml:"strip-suffix,omitempty"`
	// Prefix filter to apply when searching tags on a GitHub repository
	TagFilterPrefix string `json:"tag-filter-prefix,omitempty" yaml:"tag-filter-prefix,omitempty"`
	// Filter to apply when searching tags on a GitHub repository
	TagFilterContains string `json:"tag-filter-contains,omitempty" yaml:"tag-filter-contains,omitempty"`
}

// GetStripPrefix returns the prefix that should be stripped from the GitMonitor version.
func (gm *GitMonitor) GetStripPrefix() string {
	return gm.StripPrefix
}

// GetStripSuffix returns the suffix that should be stripped from the GitMonitor version.
func (gm *GitMonitor) GetStripSuffix() string {
	return gm.StripSuffix
}

// GetFilterPrefix returns the prefix filter to apply when searching tags in GitMonitor.
func (gm *GitMonitor) GetFilterPrefix() string {
	return gm.TagFilterPrefix
}

// GetFilterContains returns the substring filter to apply when searching tags in GitMonitor.
func (gm *GitMonitor) GetFilterContains() string {
	return gm.TagFilterContains
}

// GetStripPrefix returns the prefix that should be stripped from the GitHubMonitor version.
func (ghm *GitHubMonitor) GetStripPrefix() string {
	return ghm.StripPrefix
}

// GetStripSuffix returns the suffix that should be stripped from the GitHubMonitor version.
func (ghm *GitHubMonitor) GetStripSuffix() string {
	return ghm.StripSuffix
}

// GetFilterPrefix returns the prefix filter to apply when searching tags in GitHubMonitor.
func (ghm *GitHubMonitor) GetFilterPrefix() string {
	return ghm.TagFilterPrefix
}

// GetFilterContains returns the substring filter to apply when searching tags in GitHubMonitor.
func (ghm *GitHubMonitor) GetFilterContains() string {
	return ghm.TagFilterContains
}

// GetStripPrefix returns the prefix that should be stripped from the ReleaseMonitor version.
func (rm *ReleaseMonitor) GetStripPrefix() string {
	return rm.StripPrefix
}

// GetStripSuffix returns the suffix that should be stripped from the ReleaseMonitor version.
func (rm *ReleaseMonitor) GetStripSuffix() string {
	return rm.StripSuffix
}

// GetFilterPrefix returns the prefix filter to apply when searching versions in ReleaseMonitor.
func (rm *ReleaseMonitor) GetFilterPrefix() string {
	return rm.VersionFilterPrefix
}

// GetFilterContains returns the substring filter to apply when searching versions in ReleaseMonitor.
func (rm *ReleaseMonitor) GetFilterContains() string {
	return rm.VersionFilterContains
}

// VersionTransform allows mapping the package version to an APK version
type VersionTransform struct {
	// Required: The regular expression to match against the `package.version` variable
	Match string `json:"match" yaml:"match"`
	// Required: The repl to replace on all `match` matches
	Replace string `json:"replace" yaml:"replace"`
}

// Period represents the update check period
type Period string

const (
	Daily   Period = "daily"
	Weekly  Period = "weekly"
	Monthly Period = "monthly"
)

// Schedule defines the schedule for the update check to run
type Schedule struct {
	// The reason scheduling is being used
	Reason string `json:"reason,omitempty" yaml:"reason,omitempty"`
	Period Period `json:"period,omitempty" yaml:"period,omitempty"`
}

func (schedule Schedule) GetScheduleMessage() (string, error) {
	switch schedule.Period {
	case Daily:
		return "Scheduled daily update check", nil
	case Weekly:
		return "Scheduled weekly update check", nil
	case Monthly:
		return "Scheduled monthly update check", nil
	default:
		return "", fmt.Errorf("unsupported period: %s", schedule.Period)
	}
}

type RangeData struct {
	Name  string    `json:"name" yaml:"name"`
	Items DataItems `json:"items" yaml:"items"`
}

type DataItems map[string]string

type Dependencies struct {
	// Optional: List of runtime dependencies
	Runtime []string `json:"runtime,omitempty" yaml:"runtime,omitempty"`
	// Optional: List of packages provided
	Provides []string `json:"provides,omitempty" yaml:"provides,omitempty"`
	// Optional: List of replace objectives
	Replaces []string `json:"replaces,omitempty" yaml:"replaces,omitempty"`
	// Optional: An integer string compared against other equal package provides used to
	// determine priority of provides
	ProviderPriority string `json:"provider-priority,omitempty" yaml:"provider-priority,omitempty"`
	// Optional: An integer string compared against other equal package provides used to
	// determine priority of file replacements
	ReplacesPriority string `json:"replaces-priority,omitempty" yaml:"replaces-priority,omitempty"`

	// List of self-provided dependencies found outside of lib directories
	// ("lib", "usr/lib", "lib64", or "usr/lib64").
	Vendored []string `json:"-" yaml:"-"`
}

type ConfigurationParsingOption func(*configOptions)

type configOptions struct {
	filesystem   fs.FS
	envFilePath  string
	varsFilePath string
	commit       string
}

// include reconciles all given opts into the receiver variable, such that it is
// ready to use for config parsing.
func (options *configOptions) include(opts ...ConfigurationParsingOption) {
	for _, fn := range opts {
		fn(options)
	}
}

// WithFS sets the fs.FS implementation to use. So far this FS is used only for
// reading the configuration file. If not provided, the default FS will be an
// os.DirFS created from the configuration file's containing directory.
func WithFS(filesystem fs.FS) ConfigurationParsingOption {
	return func(options *configOptions) {
		options.filesystem = filesystem
	}
}

func WithCommit(hash string) ConfigurationParsingOption {
	return func(options *configOptions) {
		options.commit = hash
	}
}

// WithEnvFileForParsing set the paths from which to read an environment file.
func WithEnvFileForParsing(path string) ConfigurationParsingOption {
	return func(options *configOptions) {
		options.envFilePath = path
	}
}

// WithVarsFileForParsing sets the path to the vars file to use if the user wishes to
// populate the variables block from an external file.
func WithVarsFileForParsing(path string) ConfigurationParsingOption {
	return func(options *configOptions) {
		options.varsFilePath = path
	}
}

// propagateChildPipelines performs downward propagation of configuration values.
func (p *Pipeline) propagateChildPipelines() {
	for idx := range p.Pipeline {
		if p.Pipeline[idx].WorkDir == "" {
			p.Pipeline[idx].WorkDir = p.WorkDir
		}

		m := maps.Clone(p.Environment)
		maps.Copy(m, p.Pipeline[idx].Environment)
		p.Pipeline[idx].Environment = m

		p.Pipeline[idx].propagateChildPipelines()
	}
}

// propagatePipelines performs downward propagation of all pipelines in the config.
func (cfg *Configuration) propagatePipelines() {
	for _, sp := range cfg.Pipeline {
		sp.propagateChildPipelines()
	}

	// Also propagate subpackages
	for _, sp := range cfg.Subpackages {
		for _, spp := range sp.Pipeline {
			spp.propagateChildPipelines()
		}
	}
}

// ParseConfiguration returns a decoded build Configuration using the parsing options provided.
func ParseConfiguration(ctx context.Context, configurationFilePath string, opts ...ConfigurationParsingOption) (*Configuration, error) {
	options := &configOptions{}
	configurationDirPath := filepath.Dir(configurationFilePath)
	options.include(opts...)

	if options.filesystem == nil {
		// TODO: this is an abstraction leak, and we can remove this `if statement` once
		//  ParseConfiguration relies solely on an abstract fs.FS.

		options.filesystem = os.DirFS(configurationDirPath)
		configurationFilePath = filepath.Base(configurationFilePath)
	}

	if configurationFilePath == "" {
		return nil, errors.New("no configuration file path provided")
	}

	f, err := options.filesystem.Open(configurationFilePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	root := yaml.Node{}

	cfg := Configuration{root: &root}

	// Unmarshal into a node first
	decoderNode := yaml.NewDecoder(f)
	err = decoderNode.Decode(&root)
	if err != nil {
		return nil, fmt.Errorf("unable to decode configuration file %q: %w", configurationFilePath, err)
	}

	// XXX(Elizafox) - Node.Decode doesn't allow setting of KnownFields, so we do this cheesy hack below
	data, err := yaml.Marshal(&root)
	if err != nil {
		return nil, fmt.Errorf("unable to decode configuration file %q: %w", configurationFilePath, err)
	}

	// Now unmarshal it into the struct, part of said cheesy hack
	reader := bytes.NewReader(data)
	decoder := yaml.NewDecoder(reader)
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("unable to decode configuration file %q: %w", configurationFilePath, err)
	}

	// If a variables file was defined, merge it into the variables block.
	if varsFile := options.varsFilePath; varsFile != "" {
		f, err := os.Open(varsFile) // #nosec G304 - User-specified variables file from configuration
		if err != nil {
			return nil, fmt.Errorf("loading variables file: %w", err)
		}
		defer f.Close()

		vars := map[string]string{}
		err = yaml.NewDecoder(f).Decode(&vars)
		if err != nil {
			return nil, fmt.Errorf("loading variables file: %w", err)
		}

		maps.Copy(cfg.Vars, vars)
	}

	// Mutate config properties with substitutions.
	configMap := buildConfigMap(&cfg)
	if err := cfg.PerformVarSubstitutions(configMap); err != nil {
		return nil, fmt.Errorf("applying variable substitutions: %w", err)
	}

	replacer := replacerFromMap(configMap)

	cfg.Package = replacePackage(replacer, options.commit, cfg.Package)

	cfg.Pipeline = replacePipelines(replacer, cfg.Pipeline)

	datas := make(map[string]DataItems, len(cfg.Data))
	for _, d := range cfg.Data {
		datas[d.Name] = d.Items
	}

	cfg.Subpackages, err = replaceSubpackages(replacer, datas, cfg, cfg.Subpackages)
	if err != nil {
		return nil, fmt.Errorf("unable to decode configuration file %q: %w", configurationFilePath, err)
	}

	cfg.Environment = replaceImageConfig(replacer, cfg.Environment)

	cfg.Test = replaceTest(replacer, cfg.Test)

	// Clear Data after expansion - range data is consumed by replaceSubpackages
	cfg.Data = nil

	grpName := buildUser
	grp := apko_types.Group{
		GroupName: grpName,
		GID:       1000,
		Members:   []string{buildUser},
	}

	usr := apko_types.User{
		UserName: buildUser,
		UID:      1000,
		GID:      apko_types.GID(&grp.GID),
	}

	sameGroup := func(g apko_types.Group) bool { return g.GroupName == grpName }
	if !slices.ContainsFunc(cfg.Environment.Accounts.Groups, sameGroup) {
		cfg.Environment.Accounts.Groups = append(cfg.Environment.Accounts.Groups, grp)
	}
	if cfg.Test != nil && !slices.ContainsFunc(cfg.Test.Environment.Accounts.Groups, sameGroup) {
		cfg.Test.Environment.Accounts.Groups = append(cfg.Test.Environment.Accounts.Groups, grp)
	}
	for _, sub := range cfg.Subpackages {
		if sub.Test == nil || len(sub.Test.Pipeline) == 0 {
			continue
		}
		if !slices.ContainsFunc(sub.Test.Environment.Accounts.Groups, sameGroup) {
			sub.Test.Environment.Accounts.Groups = append(sub.Test.Environment.Accounts.Groups, grp)
		}
	}

	sameUser := func(u apko_types.User) bool { return u.UserName == buildUser }
	if !slices.ContainsFunc(cfg.Environment.Accounts.Users, sameUser) {
		cfg.Environment.Accounts.Users = append(cfg.Environment.Accounts.Users, usr)
	}
	if cfg.Test != nil && !slices.ContainsFunc(cfg.Test.Environment.Accounts.Users, sameUser) {
		cfg.Test.Environment.Accounts.Users = append(cfg.Test.Environment.Accounts.Users, usr)
	}
	for _, sub := range cfg.Subpackages {
		if sub.Test == nil || len(sub.Test.Pipeline) == 0 {
			continue
		}
		if !slices.ContainsFunc(sub.Test.Environment.Accounts.Users, sameUser) {
			sub.Test.Environment.Accounts.Users = append(sub.Test.Environment.Accounts.Users, usr)
		}
	}

	// Merge environment file if needed.
	if envFile := options.envFilePath; envFile != "" {
		envMap, err := godotenv.Read(envFile)
		if err != nil {
			return nil, fmt.Errorf("loading environment file: %w", err)
		}

		curEnv := cfg.Environment.Environment
		cfg.Environment.Environment = envMap

		// Overlay the environment in the YAML on top as override.
		maps.Copy(cfg.Environment.Environment, curEnv)
	}

	// Set up some useful environment variables.
	if cfg.Environment.Environment == nil {
		cfg.Environment.Environment = make(map[string]string)
	}

	const (
		defaultEnvVarHOME       = "/home/build"
		defaultEnvVarGOPATH     = "/home/build/.cache/go"
		defaultEnvVarGOMODCACHE = "/var/cache/melange/gomodcache"
	)

	setIfEmpty := func(key, value string) {
		if cfg.Environment.Environment[key] == "" {
			cfg.Environment.Environment[key] = value
		}
	}

	setIfEmpty("HOME", defaultEnvVarHOME)
	setIfEmpty("GOPATH", defaultEnvVarGOPATH)
	setIfEmpty("GOMODCACHE", defaultEnvVarGOMODCACHE)

	if err := cfg.ApplyDependencySubstitutions(); err != nil {
		return nil, err
	}
	if err := cfg.ApplyPackageSubstitutions(); err != nil {
		return nil, err
	}

	// Propagate all child pipelines
	cfg.propagatePipelines()

	// Ensure Resources is always non-nil for convenient field access
	if cfg.Package.Resources == nil {
		cfg.Package.Resources = &Resources{}
	}

	// Finally, validate the configuration we ended up with before returning it for use downstream.
	if err = cfg.validate(ctx); err != nil {
		return nil, fmt.Errorf("validating configuration %q: %w", cfg.Package.Name, err)
	}

	return &cfg, nil
}

func (cfg Configuration) Root() *yaml.Node {
	return cfg.root
}

// Summarize lists the dependencies that are configured in a dependency set.
func (dep *Dependencies) Summarize(ctx context.Context) {
	log := clog.FromContext(ctx)
	if len(dep.Runtime) > 0 {
		log.Info("  runtime:")

		for _, dep := range dep.Runtime {
			log.Info("    " + dep)
		}
	}

	if len(dep.Provides) > 0 {
		log.Info("  provides:")

		for _, dep := range dep.Provides {
			log.Info("    " + dep)
		}
	}
}
