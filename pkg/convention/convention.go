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

// Package convention provides convention-based detection for melange builds.
// It implements the "convention over configuration" approach where common
// directories and files are automatically detected based on standard locations.
//
// Conventions:
//   - Pipeline directory: ./pipelines/
//   - Signing keys: melange.rsa, local-signing.rsa
//   - Source directory: ./$pkgname/ (directory named after package)
package convention

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultPipelineDir is the conventional directory for custom pipelines.
	DefaultPipelineDir = "pipelines"

	// BuiltinPipelineDir is the system directory for built-in pipelines.
	BuiltinPipelineDir = "/usr/share/melange/pipelines"

	// maxFileSize is the maximum size of a file to include (10MB).
	maxFileSize = 10 * 1024 * 1024
)

// ConventionalSigningKeys are the signing keys checked in order.
var ConventionalSigningKeys = []string{
	"melange.rsa",
	"local-signing.rsa",
}

// DetectPipelineDir checks if the conventional ./pipelines/ directory exists.
// Returns the directory path if it exists, empty string otherwise.
func DetectPipelineDir() string {
	if info, err := os.Stat(DefaultPipelineDir); err == nil && info.IsDir() {
		return DefaultPipelineDir
	}
	return ""
}

// DetectSigningKey checks for signing keys in conventional locations.
// It looks for keys in order: melange.rsa, local-signing.rsa
// Returns the first key found, or empty string if none exist.
func DetectSigningKey() string {
	for _, key := range ConventionalSigningKeys {
		if _, err := os.Stat(key); err == nil {
			return key
		}
	}
	return ""
}

// DetectSourceDir checks if a directory named after the package exists.
// It parses the config file to extract the package name and checks if $pkgname/ exists.
// Returns the directory path if it exists, empty string otherwise.
func DetectSourceDir(configPath string) string {
	if configPath == "" {
		return ""
	}

	pkgName, err := ExtractPackageName(configPath)
	if err != nil || pkgName == "" {
		return ""
	}

	if info, err := os.Stat(pkgName); err == nil && info.IsDir() {
		return pkgName
	}
	return ""
}

// ExtractPackageName extracts the package name from a melange config file.
// It uses YAML parsing to reliably extract the package.name field.
func ExtractPackageName(configPath string) (string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}

	return ExtractPackageNameFromData(data)
}

// ExtractPackageNameFromData extracts the package name from YAML data.
func ExtractPackageNameFromData(data []byte) (string, error) {
	var cfg struct {
		Package struct {
			Name string `yaml:"name"`
		} `yaml:"package"`
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return "", err
	}

	if cfg.Package.Name == "" {
		return "", fmt.Errorf("package name not found")
	}

	return cfg.Package.Name, nil
}

// LoadPipelines loads pipelines from the conventional ./pipelines/ directory if it exists.
// Returns a map of relative paths to their YAML content, or nil if no pipelines found.
func LoadPipelines() (map[string]string, error) {
	info, err := os.Stat(DefaultPipelineDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("checking pipelines directory: %w", err)
	}
	if !info.IsDir() {
		return nil, nil
	}

	return LoadPipelinesFromDir(DefaultPipelineDir)
}

// LoadPipelinesFromDir reads all YAML files from a directory and returns
// a map of relative paths to their content.
func LoadPipelinesFromDir(dir string) (map[string]string, error) {
	pipelines := make(map[string]string)
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".yaml" {
			return nil
		}

		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("getting relative path: %w", err)
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}

		pipelines[relPath] = string(content)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", dir, err)
	}

	return pipelines, nil
}

// LoadSourceFiles loads source files for packages using the convention
// that source files are located in a directory named after the package.
// For example, if the package name is "curl", it will look for source files
// in ./curl/ directory.
// Returns a map of package name -> (relative path -> content), or nil if no sources found.
func LoadSourceFiles(configPaths []string) (map[string]map[string]string, error) {
	sourceFiles := make(map[string]map[string]string)

	for _, configPath := range configPaths {
		pkgName, err := ExtractPackageName(configPath)
		if err != nil {
			continue
		}

		info, err := os.Stat(pkgName)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("checking source directory %s: %w", pkgName, err)
		}
		if !info.IsDir() {
			continue
		}

		files, err := LoadFilesFromDir(pkgName)
		if err != nil {
			return nil, fmt.Errorf("loading source files from %s: %w", pkgName, err)
		}

		if len(files) > 0 {
			sourceFiles[pkgName] = files
		}
	}

	if len(sourceFiles) == 0 {
		return nil, nil
	}
	return sourceFiles, nil
}

// LoadFilesFromDir reads all files from a directory and returns a map of
// relative paths to their content. Skips binary files and files larger than 10MB.
func LoadFilesFromDir(dir string) (map[string]string, error) {
	files := make(map[string]string)
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		if info.Size() > maxFileSize {
			return nil
		}

		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("getting relative path: %w", err)
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}

		// Skip binary files (check for null bytes in first 512 bytes)
		if isBinaryContent(content) {
			return nil
		}

		files[relPath] = string(content)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", dir, err)
	}

	return files, nil
}

// isBinaryContent checks if content appears to be binary by looking for null bytes.
func isBinaryContent(content []byte) bool {
	checkLen := 512
	if len(content) < checkLen {
		checkLen = len(content)
	}
	for i := 0; i < checkLen; i++ {
		if content[i] == 0 {
			return true
		}
	}
	return false
}

// ParseYAMLPackageName extracts just the package.name from YAML data
// using simple string parsing. This is useful when you want to avoid
// importing the full YAML package.
// Deprecated: Use ExtractPackageNameFromData instead for more reliable parsing.
func ParseYAMLPackageName(data []byte) string {
	lines := strings.Split(string(data), "\n")
	inPackage := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "package:" {
			inPackage = true
			continue
		}
		if inPackage && strings.HasPrefix(trimmed, "name:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[1])
				name = strings.Trim(name, "\"'")
				return name
			}
		}
		if inPackage && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			if !strings.HasPrefix(trimmed, "name:") {
				break
			}
		}
	}
	return ""
}
