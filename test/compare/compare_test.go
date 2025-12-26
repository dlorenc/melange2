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

// Package compare provides a test harness for comparing builds between
// the old (runner-based) and new (BuildKit-based) melange implementations.
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
	wolfiRepo     = flag.String("wolfi-repo", "", "Path to wolfi-dev/os repository clone")
	oldMelange    = flag.String("old-melange", "", "Path to old melange binary (runner-based)")
	newMelange    = flag.String("new-melange", "", "Path to new melange binary (BuildKit-based)")
	buildkitAddr  = flag.String("buildkit-addr", "tcp://localhost:8372", "BuildKit daemon address")
	keepOutputs   = flag.Bool("keep-outputs", false, "Keep output directories after test")
	packagesFile  = flag.String("packages-file", "", "File containing list of packages to test (one per line)")
)

// Default packages to test - a mix of simple and complex packages
var defaultPackages = []string{
	"age",
	"apko",
	"bat",
	"buf",
	"cosign",
	"crane",
	"curl",
	"git",
	"go-1.23",
	"grpcurl",
	"helm",
	"jq",
	"ko",
	"kubectl",
	"melange",
	"protoc",
	"runc",
	"skopeo",
	"terraform",
	"yq",
}

func TestCompareBuilds(t *testing.T) {
	if *wolfiRepo == "" {
		t.Skip("--wolfi-repo not specified")
	}
	if *oldMelange == "" {
		t.Skip("--old-melange not specified")
	}
	if *newMelange == "" {
		t.Skip("--new-melange not specified")
	}

	packages := defaultPackages
	if *packagesFile != "" {
		var err error
		packages, err = loadPackagesFromFile(*packagesFile)
		if err != nil {
			t.Fatalf("failed to load packages from file: %v", err)
		}
	}

	// Filter to only packages that exist in the repo
	var validPackages []string
	for _, pkg := range packages {
		yamlPath := filepath.Join(*wolfiRepo, pkg+".yaml")
		if _, err := os.Stat(yamlPath); err == nil {
			validPackages = append(validPackages, pkg)
		} else {
			t.Logf("Skipping %s: %s.yaml not found", pkg, pkg)
		}
	}

	if len(validPackages) == 0 {
		t.Fatal("no valid packages found")
	}

	t.Logf("Testing %d packages: %v", len(validPackages), validPackages)

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
			result := comparePackage(t, pkg, baseDir)
			results[pkg] = result
		})
	}

	// Print summary
	printSummary(t, results)
}

type CompareResult struct {
	Package       string
	OldBuildError error
	NewBuildError error
	Identical     bool
	Differences   []string
	OldAPKPath    string
	NewAPKPath    string
}

func comparePackage(t *testing.T, pkg string, baseDir string) *CompareResult {
	result := &CompareResult{Package: pkg}

	yamlPath := filepath.Join(*wolfiRepo, pkg+".yaml")
	oldOutDir := filepath.Join(baseDir, "old", pkg)
	newOutDir := filepath.Join(baseDir, "new", pkg)

	if err := os.MkdirAll(oldOutDir, 0755); err != nil {
		t.Fatalf("failed to create old output dir: %v", err)
	}
	if err := os.MkdirAll(newOutDir, 0755); err != nil {
		t.Fatalf("failed to create new output dir: %v", err)
	}

	// Build with old melange (runner-based)
	t.Logf("Building %s with old melange...", pkg)
	oldCmd := exec.Command(*oldMelange, "build", yamlPath,
		"--arch", "x86_64",
		"--signing-key=",
		"--out-dir", oldOutDir,
		"--repository-append", "https://packages.wolfi.dev/os",
		"--keyring-append", "https://packages.wolfi.dev/os/wolfi-signing.rsa.pub",
	)
	oldCmd.Dir = *wolfiRepo
	oldOutput, err := oldCmd.CombinedOutput()
	if err != nil {
		result.OldBuildError = fmt.Errorf("old build failed: %w\n%s", err, string(oldOutput))
		t.Logf("Old build failed for %s: %v", pkg, err)
	}

	// Build with new melange (BuildKit-based)
	t.Logf("Building %s with new melange...", pkg)
	newCmd := exec.Command(*newMelange, "build", yamlPath,
		"--arch", "x86_64",
		"--signing-key=",
		"--out-dir", newOutDir,
		"--repository-append", "https://packages.wolfi.dev/os",
		"--keyring-append", "https://packages.wolfi.dev/os/wolfi-signing.rsa.pub",
		"--buildkit-addr", *buildkitAddr,
	)
	newCmd.Dir = *wolfiRepo
	newOutput, err := newCmd.CombinedOutput()
	if err != nil {
		result.NewBuildError = fmt.Errorf("new build failed: %w\n%s", err, string(newOutput))
		t.Logf("New build failed for %s: %v", pkg, err)
	}

	// If either build failed, we can't compare
	if result.OldBuildError != nil || result.NewBuildError != nil {
		return result
	}

	// Find APK files
	oldAPKs, err := filepath.Glob(filepath.Join(oldOutDir, "x86_64", "*.apk"))
	if err != nil || len(oldAPKs) == 0 {
		result.OldBuildError = fmt.Errorf("no APK found in old output")
		return result
	}

	newAPKs, err := filepath.Glob(filepath.Join(newOutDir, "x86_64", "*.apk"))
	if err != nil || len(newAPKs) == 0 {
		result.NewBuildError = fmt.Errorf("no APK found in new output")
		return result
	}

	// Compare APKs
	result.OldAPKPath = oldAPKs[0]
	result.NewAPKPath = newAPKs[0]

	diffs, err := compareAPKs(result.OldAPKPath, result.NewAPKPath)
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

// compareAPKs compares two APK files and returns a list of differences.
// APK files are tar.gz archives, so we extract and compare contents.
func compareAPKs(oldPath, newPath string) ([]string, error) {
	var diffs []string

	oldFiles, err := extractAPKContents(oldPath)
	if err != nil {
		return nil, fmt.Errorf("extracting old APK: %w", err)
	}

	newFiles, err := extractAPKContents(newPath)
	if err != nil {
		return nil, fmt.Errorf("extracting new APK: %w", err)
	}

	// Get all file names
	allFiles := make(map[string]bool)
	for name := range oldFiles {
		allFiles[name] = true
	}
	for name := range newFiles {
		allFiles[name] = true
	}

	sortedFiles := make([]string, 0, len(allFiles))
	for name := range allFiles {
		sortedFiles = append(sortedFiles, name)
	}
	sort.Strings(sortedFiles)

	for _, name := range sortedFiles {
		oldInfo, oldExists := oldFiles[name]
		newInfo, newExists := newFiles[name]

		if !oldExists {
			diffs = append(diffs, fmt.Sprintf("+ %s (only in new)", name))
			continue
		}
		if !newExists {
			diffs = append(diffs, fmt.Sprintf("- %s (only in old)", name))
			continue
		}

		// Compare file contents
		if oldInfo.Hash != newInfo.Hash {
			// Skip known non-deterministic files
			if isNonDeterministicFile(name) {
				continue
			}
			diffs = append(diffs, fmt.Sprintf("~ %s (hash differs: old=%s new=%s)",
				name, oldInfo.Hash[:16], newInfo.Hash[:16]))
		}

		// Compare modes
		if oldInfo.Mode != newInfo.Mode {
			diffs = append(diffs, fmt.Sprintf("~ %s (mode differs: old=%o new=%o)",
				name, oldInfo.Mode, newInfo.Mode))
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
		".PKGINFO",           // Contains build timestamp
		".SIGN.",             // Signature files
		"APKINDEX",           // Index with timestamps
		".spdx.json",         // SBOM with timestamps
		".cdx.json",          // CycloneDX SBOM
		"buildinfo",          // Build info with timestamps
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
	var identical, different, oldFailed, newFailed int

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
		case result.OldBuildError != nil:
			oldFailed++
			status = "OLD_FAILED"
		case result.NewBuildError != nil:
			newFailed++
			status = "NEW_FAILED"
		case result.Identical:
			identical++
			status = "IDENTICAL"
		default:
			different++
			status = "DIFFERENT"
		}

		t.Logf("  %-20s %s", pkg, status)
	}

	t.Log("\n=== TOTALS ===")
	t.Logf("  Identical:   %d", identical)
	t.Logf("  Different:   %d", different)
	t.Logf("  Old Failed:  %d", oldFailed)
	t.Logf("  New Failed:  %d", newFailed)
	t.Logf("  Total:       %d", len(results))
}
