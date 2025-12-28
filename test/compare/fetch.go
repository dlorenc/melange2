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

package compare

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// WolfiRepo represents a Wolfi APK repository.
type WolfiRepo struct {
	BaseURL string
	Arch    string
	Index   *APKIndex
}

// DefaultWolfiRepoURL is the default URL for the Wolfi APK repository.
const DefaultWolfiRepoURL = "https://packages.wolfi.dev/os"

// NewWolfiRepo creates a new WolfiRepo and fetches its APKINDEX.
func NewWolfiRepo(baseURL, arch string) (*WolfiRepo, error) {
	if baseURL == "" {
		baseURL = DefaultWolfiRepoURL
	}

	index, err := FetchAPKIndex(baseURL, arch)
	if err != nil {
		return nil, fmt.Errorf("fetching APKINDEX: %w", err)
	}

	return &WolfiRepo{
		BaseURL: baseURL,
		Arch:    arch,
		Index:   index,
	}, nil
}

// GetPackage returns the package metadata for the given name.
func (r *WolfiRepo) GetPackage(name string) *APKPackage {
	return r.Index.GetPackage(name)
}

// HasPackage returns true if the repository contains a package with the given name.
func (r *WolfiRepo) HasPackage(name string) bool {
	return r.Index.HasPackage(name)
}

// DownloadPackage downloads an APK package to the specified directory.
// Returns the path to the downloaded file.
func (r *WolfiRepo) DownloadPackage(pkg *APKPackage, destDir string) (string, error) {
	if pkg == nil {
		return "", fmt.Errorf("package is nil")
	}

	filename := pkg.Filename()
	pkgURL := fmt.Sprintf("%s/%s/%s", strings.TrimSuffix(r.BaseURL, "/"), r.Arch, filename)
	destPath := filepath.Join(destDir, filename)

	// Create destination directory if needed
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return "", fmt.Errorf("creating destination directory: %w", err)
	}

	// Download the file
	resp, err := http.Get(pkgURL)
	if err != nil {
		return "", fmt.Errorf("downloading %s: %w", filename, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("downloading %s: HTTP %d", filename, resp.StatusCode)
	}

	// Create the destination file
	f, err := os.Create(destPath)
	if err != nil {
		return "", fmt.Errorf("creating %s: %w", destPath, err)
	}
	defer f.Close()

	// Copy the content
	if _, err := io.Copy(f, resp.Body); err != nil {
		os.Remove(destPath) // Clean up partial file
		return "", fmt.Errorf("writing %s: %w", destPath, err)
	}

	return destPath, nil
}

// DownloadPackageByName downloads an APK package by name to the specified directory.
// Returns the path to the downloaded file and the package metadata.
func (r *WolfiRepo) DownloadPackageByName(name, destDir string) (string, *APKPackage, error) {
	pkg := r.GetPackage(name)
	if pkg == nil {
		return "", nil, fmt.Errorf("package %q not found in repository", name)
	}

	path, err := r.DownloadPackage(pkg, destDir)
	if err != nil {
		return "", nil, err
	}

	return path, pkg, nil
}

// ListPackages returns a list of all package names in the repository.
func (r *WolfiRepo) ListPackages() []string {
	names := make([]string, 0, len(r.Index.Packages))
	for name := range r.Index.Packages {
		names = append(names, name)
	}
	return names
}
