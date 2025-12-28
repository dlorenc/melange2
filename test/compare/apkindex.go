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
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// APKPackage represents a package entry from APKINDEX.
type APKPackage struct {
	Name         string
	Version      string
	Architecture string
	Size         int64
	InstalledSize int64
	Description  string
	URL          string
	License      string
	Origin       string
	Maintainer   string
	Commit       string
	Checksum     string
	Dependencies []string
	Provides     []string
}

// Filename returns the APK filename for this package.
func (p *APKPackage) Filename() string {
	return fmt.Sprintf("%s-%s.apk", p.Name, p.Version)
}

// APKIndex holds the parsed APKINDEX data.
type APKIndex struct {
	Packages map[string]*APKPackage // keyed by package name
}

// FetchAPKIndex downloads and parses the APKINDEX from the given repository URL.
func FetchAPKIndex(repoURL, arch string) (*APKIndex, error) {
	indexURL := fmt.Sprintf("%s/%s/APKINDEX.tar.gz", strings.TrimSuffix(repoURL, "/"), arch)

	resp, err := http.Get(indexURL)
	if err != nil {
		return nil, fmt.Errorf("fetching APKINDEX: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching APKINDEX: HTTP %d", resp.StatusCode)
	}

	return ParseAPKIndex(resp.Body)
}

// ParseAPKIndex parses an APKINDEX.tar.gz from the given reader.
func ParseAPKIndex(r io.Reader) (*APKIndex, error) {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("creating gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar: %w", err)
		}

		if hdr.Name == "APKINDEX" {
			return parseAPKIndexFile(tr)
		}
	}

	return nil, fmt.Errorf("APKINDEX file not found in archive")
}

// parseAPKIndexFile parses the APKINDEX file content.
func parseAPKIndexFile(r io.Reader) (*APKIndex, error) {
	index := &APKIndex{
		Packages: make(map[string]*APKPackage),
	}

	scanner := bufio.NewScanner(r)
	var current *APKPackage

	for scanner.Scan() {
		line := scanner.Text()

		// Empty line marks end of package entry
		if line == "" {
			if current != nil && current.Name != "" {
				index.Packages[current.Name] = current
			}
			current = nil
			continue
		}

		// Start new package if needed
		if current == nil {
			current = &APKPackage{}
		}

		// Parse field:value format
		if len(line) < 2 || line[1] != ':' {
			continue
		}

		field := line[0]
		value := line[2:]

		switch field {
		case 'P': // Package name
			current.Name = value
		case 'V': // Version
			current.Version = value
		case 'A': // Architecture
			current.Architecture = value
		case 'S': // Size (compressed)
			fmt.Sscanf(value, "%d", &current.Size)
		case 'I': // Installed size
			fmt.Sscanf(value, "%d", &current.InstalledSize)
		case 'T': // Description
			current.Description = value
		case 'U': // URL
			current.URL = value
		case 'L': // License
			current.License = value
		case 'o': // Origin
			current.Origin = value
		case 'm': // Maintainer
			current.Maintainer = value
		case 'c': // Commit
			current.Commit = value
		case 'C': // Checksum
			current.Checksum = value
		case 'D': // Dependencies
			if value != "" {
				current.Dependencies = strings.Fields(value)
			}
		case 'p': // Provides
			if value != "" {
				current.Provides = strings.Fields(value)
			}
		}
	}

	// Don't forget the last package if file doesn't end with empty line
	if current != nil && current.Name != "" {
		index.Packages[current.Name] = current
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning APKINDEX: %w", err)
	}

	return index, nil
}

// GetPackage returns the package with the given name, or nil if not found.
func (idx *APKIndex) GetPackage(name string) *APKPackage {
	return idx.Packages[name]
}

// HasPackage returns true if the index contains a package with the given name.
func (idx *APKIndex) HasPackage(name string) bool {
	_, ok := idx.Packages[name]
	return ok
}
