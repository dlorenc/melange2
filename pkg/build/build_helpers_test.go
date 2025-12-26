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
	"os"
	"path/filepath"
	"testing"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/pkg/config"
)

func TestCopyFile(t *testing.T) {
	t.Run("copies file successfully", func(t *testing.T) {
		tmpDir := t.TempDir()
		srcDir := filepath.Join(tmpDir, "src")
		destDir := filepath.Join(tmpDir, "dest")
		require.NoError(t, os.MkdirAll(srcDir, 0o755))

		// Create source file
		srcContent := []byte("test content")
		require.NoError(t, os.WriteFile(filepath.Join(srcDir, "test.txt"), srcContent, 0o644))

		// Copy file
		err := copyFile(srcDir, "test.txt", destDir, 0o644)
		require.NoError(t, err)

		// Verify copy
		content, err := os.ReadFile(filepath.Join(destDir, "test.txt"))
		require.NoError(t, err)
		require.Equal(t, srcContent, content)
	})

	t.Run("copies file with subdirectory", func(t *testing.T) {
		tmpDir := t.TempDir()
		srcDir := filepath.Join(tmpDir, "src")
		destDir := filepath.Join(tmpDir, "dest")
		require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "subdir"), 0o755))

		// Create source file in subdirectory
		srcContent := []byte("nested content")
		require.NoError(t, os.WriteFile(filepath.Join(srcDir, "subdir", "nested.txt"), srcContent, 0o644))

		// Copy file
		err := copyFile(srcDir, "subdir/nested.txt", destDir, 0o644)
		require.NoError(t, err)

		// Verify copy
		content, err := os.ReadFile(filepath.Join(destDir, "subdir", "nested.txt"))
		require.NoError(t, err)
		require.Equal(t, srcContent, content)
	})

	t.Run("preserves permissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		srcDir := filepath.Join(tmpDir, "src")
		destDir := filepath.Join(tmpDir, "dest")
		require.NoError(t, os.MkdirAll(srcDir, 0o755))

		// Create source file
		require.NoError(t, os.WriteFile(filepath.Join(srcDir, "exec.sh"), []byte("#!/bin/sh"), 0o755))

		// Copy file with executable permissions
		err := copyFile(srcDir, "exec.sh", destDir, 0o755)
		require.NoError(t, err)

		// Verify permissions
		fi, err := os.Stat(filepath.Join(destDir, "exec.sh"))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o755), fi.Mode().Perm())
	})

	t.Run("returns error for nonexistent file", func(t *testing.T) {
		tmpDir := t.TempDir()
		err := copyFile(tmpDir, "nonexistent.txt", filepath.Join(tmpDir, "dest"), 0o644)
		require.Error(t, err)
	})
}

func TestLoadIgnoreRules(t *testing.T) {
	t.Run("returns empty when no ignore file exists", func(t *testing.T) {
		ctx := slogtest.Context(t)
		tmpDir := t.TempDir()
		b := &Build{
			SourceDir:       tmpDir,
			WorkspaceIgnore: ".melangeignore",
		}

		patterns, err := b.loadIgnoreRules(ctx)
		require.NoError(t, err)
		require.Empty(t, patterns)
	})

	t.Run("loads ignore patterns from file", func(t *testing.T) {
		ctx := slogtest.Context(t)
		tmpDir := t.TempDir()

		// Create ignore file
		ignoreContent := "*.tmp\n.git/\nnode_modules/"
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".melangeignore"), []byte(ignoreContent), 0o644))

		b := &Build{
			SourceDir:       tmpDir,
			WorkspaceIgnore: ".melangeignore",
		}

		patterns, err := b.loadIgnoreRules(ctx)
		require.NoError(t, err)
		require.Len(t, patterns, 3)
	})

	t.Run("handles custom ignore file name", func(t *testing.T) {
		ctx := slogtest.Context(t)
		tmpDir := t.TempDir()

		// Create custom ignore file
		ignoreContent := "*.log"
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".customignore"), []byte(ignoreContent), 0o644))

		b := &Build{
			SourceDir:       tmpDir,
			WorkspaceIgnore: ".customignore",
		}

		patterns, err := b.loadIgnoreRules(ctx)
		require.NoError(t, err)
		require.Len(t, patterns, 1)
	})
}

func TestGetBuildConfigPURL(t *testing.T) {
	tests := []struct {
		name       string
		build      Build
		wantPURL   string
		wantErr    bool
	}{
		{
			name: "valid github URL",
			build: Build{
				ConfigFileRepositoryURL:    "https://github.com/wolfi-dev/os",
				ConfigFileRepositoryCommit: "abc123def456",
				ConfigFile:                 "crane.yaml",
			},
			wantPURL: "pkg:github/wolfi-dev/os@abc123def456#crane.yaml",
			wantErr:  false,
		},
		{
			name: "github URL with nested config path",
			build: Build{
				ConfigFileRepositoryURL:    "https://github.com/chainguard-dev/packages",
				ConfigFileRepositoryCommit: "deadbeef1234",
				ConfigFile:                 "packages/go.yaml",
			},
			wantPURL: "pkg:github/chainguard-dev/packages@deadbeef1234#packages/go.yaml",
			wantErr:  false,
		},
		{
			name: "invalid URL format",
			build: Build{
				ConfigFileRepositoryURL:    "not-a-valid-url",
				ConfigFileRepositoryCommit: "abc123",
				ConfigFile:                 "test.yaml",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			purl, err := tt.build.getBuildConfigPURL()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantPURL, purl.String())
		})
	}
}

func TestBuildFlavor(t *testing.T) {
	tests := []struct {
		name   string
		libc   string
		expect string
	}{
		{
			name:   "empty returns gnu",
			libc:   "",
			expect: "gnu",
		},
		{
			name:   "musl returns musl",
			libc:   "musl",
			expect: "musl",
		},
		{
			name:   "glibc returns glibc",
			libc:   "glibc",
			expect: "glibc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Build{Libc: tt.libc}
			require.Equal(t, tt.expect, b.buildFlavor())
		})
	}
}

func TestApplyBuildOption(t *testing.T) {
	t.Run("patches variables", func(t *testing.T) {
		b := &Build{
			Configuration: &config.Configuration{
				Vars: map[string]string{"existing": "value"},
			},
		}

		opt := config.BuildOption{
			Vars: map[string]string{"new_var": "new_value"},
		}

		b.applyBuildOption(opt)
		require.Equal(t, "value", b.Configuration.Vars["existing"])
		require.Equal(t, "new_value", b.Configuration.Vars["new_var"])
	})

	t.Run("creates vars map if nil", func(t *testing.T) {
		b := &Build{
			Configuration: &config.Configuration{
				Vars: nil,
			},
		}

		opt := config.BuildOption{
			Vars: map[string]string{"new_var": "new_value"},
		}

		b.applyBuildOption(opt)
		require.NotNil(t, b.Configuration.Vars)
		require.Equal(t, "new_value", b.Configuration.Vars["new_var"])
	})

	t.Run("adds packages", func(t *testing.T) {
		b := &Build{
			Configuration: &config.Configuration{
				Environment: apko_types.ImageConfiguration{
					Contents: apko_types.ImageContents{
						Packages: []string{"pkg1"},
					},
				},
			},
		}

		opt := config.BuildOption{
			Environment: config.EnvironmentOption{
				Contents: config.ContentsOption{
					Packages: config.ListOption{
						Add: []string{"pkg2", "pkg3"},
					},
				},
			},
		}

		b.applyBuildOption(opt)
		require.Contains(t, b.Configuration.Environment.Contents.Packages, "pkg1")
		require.Contains(t, b.Configuration.Environment.Contents.Packages, "pkg2")
		require.Contains(t, b.Configuration.Environment.Contents.Packages, "pkg3")
	})

	t.Run("removes packages", func(t *testing.T) {
		b := &Build{
			Configuration: &config.Configuration{
				Environment: apko_types.ImageConfiguration{
					Contents: apko_types.ImageContents{
						Packages: []string{"pkg1", "pkg2", "pkg3"},
					},
				},
			},
		}

		opt := config.BuildOption{
			Environment: config.EnvironmentOption{
				Contents: config.ContentsOption{
					Packages: config.ListOption{
						Remove: []string{"pkg2"},
					},
				},
			},
		}

		b.applyBuildOption(opt)
		require.Contains(t, b.Configuration.Environment.Contents.Packages, "pkg1")
		require.NotContains(t, b.Configuration.Environment.Contents.Packages, "pkg2")
		require.Contains(t, b.Configuration.Environment.Contents.Packages, "pkg3")
	})
}

func TestPkgFromSub(t *testing.T) {
	sub := &config.Subpackage{
		Name:        "test-subpkg",
		Description: "A test subpackage",
		URL:         "https://example.com",
		Commit:      "abc123",
		Dependencies: config.Dependencies{
			Runtime:  []string{"dep1"},
			Provides: []string{"prov1"},
		},
		Options: &config.PackageOption{
			NoProvides: true,
		},
		Scriptlets: &config.Scriptlets{
			PreInstall: "echo pre",
		},
	}

	pkg := pkgFromSub(sub)

	require.Equal(t, "test-subpkg", pkg.Name)
	require.Equal(t, "A test subpackage", pkg.Description)
	require.Equal(t, "https://example.com", pkg.URL)
	require.Equal(t, "abc123", pkg.Commit)
	require.Equal(t, []string{"dep1"}, pkg.Dependencies.Runtime)
	require.Equal(t, []string{"prov1"}, pkg.Dependencies.Provides)
	require.True(t, pkg.Options.NoProvides)
	require.Equal(t, "echo pre", pkg.Scriptlets.PreInstall)
}
