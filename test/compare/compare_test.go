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

//go:build compare

// Package compare provides a test harness for comparing builds between
// upstream melange and melange2 (BuildKit-based).
//
// Run with:
//
//	go test -tags=compare ./test/compare/... \
//	  -wolfi-repo=/path/to/wolfi-dev/os \
//	  -baseline-melange=/path/to/upstream/melange \
//	  -packages=jq,tzdata,scdoc
//
// Or via make:
//
//	make compare WOLFI_REPO=/path/to/os BASELINE_MELANGE=/path/to/melange PACKAGES="jq tzdata"
package compare

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var (
	// Required flags
	wolfiRepo       = flag.String("wolfi-repo", "", "Path to wolfi-dev/os repository clone (required)")
	baselineMelange = flag.String("baseline-melange", "", "Path to baseline melange binary to compare against (required)")

	// Optional flags
	buildkitAddr    = flag.String("buildkit-addr", "tcp://localhost:8372", "BuildKit daemon address")
	keepOutputs     = flag.Bool("keep-outputs", false, "Keep output directories after test")
	packages        = flag.String("packages", "", "Comma-separated list of packages to test")
	packagesFile    = flag.String("packages-file", "", "File containing list of packages to test (one per line)")
	baselineArgs    = flag.String("baseline-args", "", "Additional args to pass to baseline melange (space-separated)")
	melange2Args    = flag.String("melange2-args", "", "Additional args to pass to melange2 (space-separated)")
	arch            = flag.String("arch", "x86_64", "Architecture to build for")
)

func TestCompareBuilds(t *testing.T) {
	// Validate required flags
	if *wolfiRepo == "" {
		t.Fatal("--wolfi-repo is required")
	}
	if *baselineMelange == "" {
		t.Fatal("--baseline-melange is required")
	}

	// Verify paths exist
	if _, err := os.Stat(*wolfiRepo); err != nil {
		t.Fatalf("wolfi-repo path does not exist: %s", *wolfiRepo)
	}
	if _, err := os.Stat(*baselineMelange); err != nil {
		t.Fatalf("baseline-melange binary does not exist: %s", *baselineMelange)
	}

	// Build melange2 from current source
	melange2Binary := buildMelange2(t)

	// Determine packages to test
	pkgList := getPackageList(t)
	if len(pkgList) == 0 {
		t.Fatal("no packages specified; use --packages or --packages-file")
	}

	// Filter to only packages that exist in the repo
	var validPackages []string
	for _, pkg := range pkgList {
		yamlPath := filepath.Join(*wolfiRepo, pkg+".yaml")
		if _, err := os.Stat(yamlPath); err == nil {
			validPackages = append(validPackages, pkg)
		} else {
			t.Logf("Skipping %s: %s.yaml not found", pkg, pkg)
		}
	}

	if len(validPackages) == 0 {
		t.Fatal("no valid packages found in wolfi-repo")
	}

	t.Logf("Testing %d packages: %v", len(validPackages), validPackages)
	t.Logf("Baseline melange: %s", *baselineMelange)
	t.Logf("Melange2 binary: %s", melange2Binary)
	t.Logf("BuildKit address: %s", *buildkitAddr)

	// Create output directories
	baseDir, err := os.MkdirTemp("", "melange-compare-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	if !*keepOutputs {
		defer os.RemoveAll(baseDir)
	} else {
		t.Logf("Output directory: %s", baseDir)
	}

	results := make(map[string]*CompareResult)

	for _, pkg := range validPackages {
		t.Run(pkg, func(t *testing.T) {
			result := comparePackage(t, pkg, baseDir, melange2Binary)
			results[pkg] = result
		})
	}

	// Print summary
	printSummary(t, results)
}

// buildMelange2 builds the melange2 binary from the current source.
func buildMelange2(t *testing.T) string {
	t.Helper()

	// Get the module root (where go.mod is)
	moduleRoot, err := findModuleRoot()
	if err != nil {
		t.Fatalf("failed to find module root: %v", err)
	}

	// Build to a temp directory
	tmpDir, err := os.MkdirTemp("", "melange2-build-*")
	if err != nil {
		t.Fatalf("failed to create temp dir for build: %v", err)
	}

	binaryPath := filepath.Join(tmpDir, "melange2")
	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	cmd.Dir = moduleRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build melange2: %v\n%s", err, string(output))
	}

	t.Logf("Built melange2 to %s", binaryPath)
	return binaryPath
}

// findModuleRoot finds the root of the Go module.
func findModuleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find go.mod")
		}
		dir = parent
	}
}

// getPackageList returns the list of packages to test.
func getPackageList(t *testing.T) []string {
	t.Helper()

	// First check --packages flag
	if *packages != "" {
		return strings.Split(*packages, ",")
	}

	// Then check --packages-file flag
	if *packagesFile != "" {
		pkgs, err := loadPackagesFromFile(*packagesFile)
		if err != nil {
			t.Fatalf("failed to load packages from file: %v", err)
		}
		return pkgs
	}

	return nil
}

type CompareResult struct {
	Package            string
	BaselineBuildError error
	Melange2BuildError error
	Identical          bool
	Differences        []string
	BaselineAPKPath    string
	Melange2APKPath    string
}

func comparePackage(t *testing.T, pkg string, baseDir string, melange2Binary string) *CompareResult {
	result := &CompareResult{Package: pkg}

	yamlPath := filepath.Join(*wolfiRepo, pkg+".yaml")
	baselineOutDir := filepath.Join(baseDir, "baseline", pkg)
	melange2OutDir := filepath.Join(baseDir, "melange2", pkg)

	if err := os.MkdirAll(baselineOutDir, 0755); err != nil {
		t.Fatalf("failed to create baseline output dir: %v", err)
	}
	if err := os.MkdirAll(melange2OutDir, 0755); err != nil {
		t.Fatalf("failed to create melange2 output dir: %v", err)
	}

	pipelineDir := filepath.Join(*wolfiRepo, "pipelines")
	sourceDir := filepath.Join(*wolfiRepo, pkg)

	// Build with baseline melange
	t.Logf("Building %s with baseline melange...", pkg)
	baselineCmd := buildBaselineCommand(yamlPath, baselineOutDir, pipelineDir, sourceDir)
	baselineCmd.Dir = *wolfiRepo
	baselineOutput, err := baselineCmd.CombinedOutput()
	if err != nil {
		result.BaselineBuildError = fmt.Errorf("baseline build failed: %w\n%s", err, string(baselineOutput))
		t.Logf("Baseline build failed for %s: %v", pkg, err)
	}

	// Build with melange2
	t.Logf("Building %s with melange2...", pkg)
	cacheDir := filepath.Join(melange2OutDir, "cache")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		t.Fatalf("failed to create cache dir: %v", err)
	}
	melange2Cmd := buildMelange2Command(melange2Binary, yamlPath, melange2OutDir, pipelineDir, sourceDir, cacheDir)
	melange2Cmd.Dir = *wolfiRepo
	melange2Output, err := melange2Cmd.CombinedOutput()
	if err != nil {
		result.Melange2BuildError = fmt.Errorf("melange2 build failed: %w\n%s", err, string(melange2Output))
		t.Logf("Melange2 build failed for %s: %v", pkg, err)
	}

	// If either build failed, we can't compare
	if result.BaselineBuildError != nil || result.Melange2BuildError != nil {
		return result
	}

	// Find APK files
	baselineAPKs, err := filepath.Glob(filepath.Join(baselineOutDir, *arch, "*.apk"))
	if err != nil || len(baselineAPKs) == 0 {
		result.BaselineBuildError = fmt.Errorf("no APK found in baseline output")
		return result
	}

	melange2APKs, err := filepath.Glob(filepath.Join(melange2OutDir, *arch, "*.apk"))
	if err != nil || len(melange2APKs) == 0 {
		result.Melange2BuildError = fmt.Errorf("no APK found in melange2 output")
		return result
	}

	// Compare APKs
	result.BaselineAPKPath = baselineAPKs[0]
	result.Melange2APKPath = melange2APKs[0]

	diffs, err := compareAPKs(result.BaselineAPKPath, result.Melange2APKPath)
	if err != nil {
		t.Errorf("failed to compare APKs: %v", err)
		result.Differences = []string{fmt.Sprintf("comparison error: %v", err)}
		return result
	}

	result.Differences = diffs
	result.Identical = len(diffs) == 0

	if !result.Identical {
		t.Logf("Differences found in %s:", pkg)
		for _, diff := range diffs {
			t.Logf("  %s", diff)
		}
	} else {
		t.Logf("%s: identical", pkg)
	}

	return result
}

func buildBaselineCommand(yamlPath, outDir, pipelineDir, sourceDir string) *exec.Cmd {
	args := []string{"build", yamlPath,
		"--arch", *arch,
		"--signing-key=",
		"--out-dir", outDir,
		"--repository-append", "https://packages.wolfi.dev/os",
		"--keyring-append", "https://packages.wolfi.dev/os/wolfi-signing.rsa.pub",
		"--pipeline-dir", pipelineDir,
		"--source-dir", sourceDir,
	}

	// Add any additional baseline args
	if *baselineArgs != "" {
		args = append(args, strings.Fields(*baselineArgs)...)
	}

	return exec.Command(*baselineMelange, args...)
}

func buildMelange2Command(binary, yamlPath, outDir, pipelineDir, sourceDir, cacheDir string) *exec.Cmd {
	args := []string{"build", yamlPath,
		"--arch", *arch,
		"--signing-key=",
		"--out-dir", outDir,
		"--repository-append", "https://packages.wolfi.dev/os",
		"--keyring-append", "https://packages.wolfi.dev/os/wolfi-signing.rsa.pub",
		"--buildkit-addr", *buildkitAddr,
		"--cache-dir", cacheDir,
		"--pipeline-dir", pipelineDir,
		"--source-dir", sourceDir,
	}

	// Add any additional melange2 args
	if *melange2Args != "" {
		args = append(args, strings.Fields(*melange2Args)...)
	}

	return exec.Command(binary, args...)
}

// compareAPKs compares two APK files and returns a list of differences.
// APK files are tar.gz archives, so we extract and compare contents.
func compareAPKs(baselinePath, melange2Path string) ([]string, error) {
	var diffs []string

	baselineFiles, err := extractAPKContents(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("extracting baseline APK: %w", err)
	}

	melange2Files, err := extractAPKContents(melange2Path)
	if err != nil {
		return nil, fmt.Errorf("extracting melange2 APK: %w", err)
	}

	// Get all file names
	allFiles := make(map[string]bool)
	for name := range baselineFiles {
		allFiles[name] = true
	}
	for name := range melange2Files {
		allFiles[name] = true
	}

	sortedFiles := make([]string, 0, len(allFiles))
	for name := range allFiles {
		sortedFiles = append(sortedFiles, name)
	}
	sort.Strings(sortedFiles)

	for _, name := range sortedFiles {
		baselineInfo, baselineExists := baselineFiles[name]
		melange2Info, melange2Exists := melange2Files[name]

		if !baselineExists {
			diffs = append(diffs, fmt.Sprintf("+ %s (only in melange2)", name))
			continue
		}
		if !melange2Exists {
			diffs = append(diffs, fmt.Sprintf("- %s (only in baseline)", name))
			continue
		}

		// Compare file contents
		if baselineInfo.Hash != melange2Info.Hash {
			// Skip known non-deterministic files
			if isNonDeterministicFile(name) {
				continue
			}
			diffs = append(diffs, fmt.Sprintf("~ %s (hash differs: baseline=%s melange2=%s)",
				name, baselineInfo.Hash[:16], melange2Info.Hash[:16]))
		}

		// Compare modes
		if baselineInfo.Mode != melange2Info.Mode {
			diffs = append(diffs, fmt.Sprintf("~ %s (mode differs: baseline=%o melange2=%o)",
				name, baselineInfo.Mode, melange2Info.Mode))
		}
	}

	return diffs, nil
}

type FileInfo struct {
	Hash string
	Mode int64
	Size int64
}

func extractAPKContents(apkPath string) (map[string]FileInfo, error) {
	f, err := os.Open(apkPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gzr.Close()

	files := make(map[string]FileInfo)
	tr := tar.NewReader(gzr)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// Calculate hash for regular files
		var hash string
		if hdr.Typeflag == tar.TypeReg {
			h := sha256.New()
			if _, err := io.Copy(h, tr); err != nil {
				return nil, err
			}
			hash = hex.EncodeToString(h.Sum(nil))
		}

		files[hdr.Name] = FileInfo{
			Hash: hash,
			Mode: hdr.Mode,
			Size: hdr.Size,
		}
	}

	return files, nil
}

// isNonDeterministicFile returns true for files that are expected to differ
// between builds due to timestamps or other non-deterministic content.
func isNonDeterministicFile(name string) bool {
	nonDeterministic := []string{
		".PKGINFO",   // Contains build timestamp
		".SIGN.",     // Signature files
		"APKINDEX",   // Index with timestamps
		".spdx.json", // SBOM with timestamps
		".cdx.json",  // CycloneDX SBOM
		"buildinfo",  // Build info with timestamps
	}

	for _, pattern := range nonDeterministic {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

func loadPackagesFromFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var packages []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			packages = append(packages, line)
		}
	}
	return packages, nil
}

func printSummary(t *testing.T, results map[string]*CompareResult) {
	var identical, different, baselineFailed, melange2Failed int

	t.Log("\n=== COMPARISON SUMMARY ===")

	packages := make([]string, 0, len(results))
	for pkg := range results {
		packages = append(packages, pkg)
	}
	sort.Strings(packages)

	for _, pkg := range packages {
		result := results[pkg]
		var status string

		switch {
		case result.BaselineBuildError != nil:
			baselineFailed++
			status = "BASELINE_FAILED"
		case result.Melange2BuildError != nil:
			melange2Failed++
			status = "MELANGE2_FAILED"
		case result.Identical:
			identical++
			status = "IDENTICAL"
		default:
			different++
			status = "DIFFERENT"
		}

		t.Logf("  %-30s %s", pkg, status)
	}

	t.Log("\n=== TOTALS ===")
	t.Logf("  Identical:        %d", identical)
	t.Logf("  Different:        %d", different)
	t.Logf("  Baseline Failed:  %d", baselineFailed)
	t.Logf("  Melange2 Failed:  %d", melange2Failed)
	t.Logf("  Total:            %d", len(results))
}
