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

package linters

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/pkg/config"
)

func TestIsIgnoredPath(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"var/lib/db/sbom/package.spdx.json", true},
		{"var/lib/db/sbom/", true},
		{"var/lib/other/file", false},
		{"usr/bin/myapp", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := IsIgnoredPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRegexPatterns(t *testing.T) {
	t.Run("InfoRegex", func(t *testing.T) {
		matches := []string{
			"usr/share/info/dir",
			"usr/share/info/emacs.info",
			"usr/share/info/emacs.info-1",
			"usr/share/info/emacs.info.gz",
			"usr/local/share/info/test.info.bz2",
		}
		nonMatches := []string{
			"usr/share/info/",
			"usr/bin/info",
			"var/info/test",
		}

		for _, m := range matches {
			assert.True(t, InfoRegex.MatchString(m), "should match: %s", m)
		}
		for _, m := range nonMatches {
			assert.False(t, InfoRegex.MatchString(m), "should not match: %s", m)
		}
	})

	t.Run("IsTempDirRegex", func(t *testing.T) {
		matches := []string{
			"tmp/somefile",
			"var/tmp/somefile",
		}
		nonMatches := []string{
			"usr/tmp/file",
			"home/tmp/file",
		}

		for _, m := range matches {
			assert.True(t, IsTempDirRegex.MatchString(m), "should match: %s", m)
		}
		for _, m := range nonMatches {
			assert.False(t, IsTempDirRegex.MatchString(m), "should not match: %s", m)
		}
	})

	t.Run("IsSharedObjectFileRegex", func(t *testing.T) {
		matches := []string{
			"libfoo.so",
			"libfoo.so.1",
			"libfoo.so.1.2.3",
		}
		nonMatches := []string{
			"libfoo.a",
			"libfoo.dylib",
			"program",
		}

		for _, m := range matches {
			assert.True(t, IsSharedObjectFileRegex.MatchString(m), "should match: %s", m)
		}
		for _, m := range nonMatches {
			assert.False(t, IsSharedObjectFileRegex.MatchString(m), "should not match: %s", m)
		}
	})

	t.Run("IsDocumentationFileRegex", func(t *testing.T) {
		matches := []string{
			"README",
			"README.md",
			"TODO",
			"CREDITS",
			"file.md",
			"file.rst",
			"file.doc",
			"file.docx",
		}
		nonMatches := []string{
			"main.go",
			"program.exe",
			"libfoo.so",
		}

		for _, m := range matches {
			assert.True(t, IsDocumentationFileRegex.MatchString(m), "should match: %s", m)
		}
		for _, m := range nonMatches {
			assert.False(t, IsDocumentationFileRegex.MatchString(m), "should not match: %s", m)
		}
	})

	t.Run("PkgconfDirRegex", func(t *testing.T) {
		matches := []string{
			"usr/lib/pkgconfig/foo.pc",
			"usr/share/pkgconfig/bar.pc",
		}
		nonMatches := []string{
			"usr/bin/pkgconfig",
			"lib/pkgconfig/foo.pc",
		}

		for _, m := range matches {
			assert.True(t, PkgconfDirRegex.MatchString(m), "should match: %s", m)
		}
		for _, m := range nonMatches {
			assert.False(t, PkgconfDirRegex.MatchString(m), "should not match: %s", m)
		}
	})
}

func TestAllPaths(t *testing.T) {
	ctx := context.Background()

	t.Run("returns nil when no paths match", func(t *testing.T) {
		fsys := fstest.MapFS{
			"usr/bin/myapp": &fstest.MapFile{Data: []byte("binary")},
			"usr/lib/libfoo.so": &fstest.MapFile{Data: []byte("lib")},
		}

		err := AllPaths(ctx, "test-pkg", fsys,
			func(path string, d os.DirEntry) bool { return false },
			func(pkgname string, paths []string) string { return "error" },
		)

		assert.NoError(t, err)
	})

	t.Run("returns error when paths match", func(t *testing.T) {
		fsys := fstest.MapFS{
			"dev/null": &fstest.MapFile{Data: []byte{}},
			"dev/zero": &fstest.MapFile{Data: []byte{}},
		}

		err := AllPaths(ctx, "test-pkg", fsys,
			func(path string, d os.DirEntry) bool {
				return path == "dev/null" || path == "dev/zero"
			},
			func(pkgname string, paths []string) string {
				return pkgname + " writes to /dev"
			},
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "test-pkg writes to /dev")
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		fsys := fstest.MapFS{
			"file1": &fstest.MapFile{Data: []byte("data")},
		}

		err := AllPaths(ctx, "test-pkg", fsys,
			func(path string, d os.DirEntry) bool { return false },
			func(pkgname string, paths []string) string { return "error" },
		)

		assert.Error(t, err)
		assert.Equal(t, context.Canceled, err)
	})
}

func TestEmptyLinter(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Configuration{}

	t.Run("returns nil for non-empty package", func(t *testing.T) {
		fsys := fstest.MapFS{
			"usr/bin/myapp": &fstest.MapFile{Data: []byte("binary")},
		}

		err := EmptyLinter(ctx, cfg, "test-pkg", fsys)
		assert.NoError(t, err)
	})

	t.Run("returns error for empty package", func(t *testing.T) {
		fsys := fstest.MapFS{
			"usr": &fstest.MapFile{Mode: os.ModeDir},
		}

		err := EmptyLinter(ctx, cfg, "test-pkg", fsys)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "package is empty")
	})

	t.Run("ignores sbom paths", func(t *testing.T) {
		fsys := fstest.MapFS{
			"var/lib/db/sbom/package.spdx.json": &fstest.MapFile{Data: []byte("sbom")},
		}

		err := EmptyLinter(ctx, cfg, "test-pkg", fsys)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "package is empty")
	})
}

func TestDevLinter(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Configuration{}

	t.Run("returns nil for package without /dev files", func(t *testing.T) {
		fsys := fstest.MapFS{
			"usr/bin/myapp": &fstest.MapFile{Data: []byte("binary")},
		}

		err := DevLinter(ctx, cfg, "test-pkg", fsys)
		assert.NoError(t, err)
	})

	t.Run("returns error for package with /dev files", func(t *testing.T) {
		fsys := fstest.MapFS{
			"dev/null": &fstest.MapFile{Data: []byte{}},
		}

		err := DevLinter(ctx, cfg, "test-pkg", fsys)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "test-pkg writes to /dev")
	})

	t.Run("ignores /dev directories", func(t *testing.T) {
		fsys := fstest.MapFS{
			"dev/subdir/file": &fstest.MapFile{Data: []byte("data")},
		}

		err := DevLinter(ctx, cfg, "test-pkg", fsys)
		require.Error(t, err)
	})
}

func TestOptLinter(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Configuration{}

	t.Run("returns nil for package without /opt files", func(t *testing.T) {
		fsys := fstest.MapFS{
			"usr/bin/myapp": &fstest.MapFile{Data: []byte("binary")},
		}

		err := OptLinter(ctx, cfg, "test-pkg", fsys)
		assert.NoError(t, err)
	})

	t.Run("returns error for package with /opt files", func(t *testing.T) {
		fsys := fstest.MapFS{
			"opt/myapp/bin/app": &fstest.MapFile{Data: []byte("binary")},
		}

		err := OptLinter(ctx, cfg, "test-pkg", fsys)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "test-pkg writes to /opt")
	})

	t.Run("allows /opt for compat packages", func(t *testing.T) {
		fsys := fstest.MapFS{
			"opt/myapp/bin/app": &fstest.MapFile{Data: []byte("binary")},
		}

		err := OptLinter(ctx, cfg, "test-pkg-compat", fsys)
		assert.NoError(t, err)
	})
}

func TestUsrLocalLinter(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Configuration{}

	t.Run("returns nil for package without /usr/local files", func(t *testing.T) {
		fsys := fstest.MapFS{
			"usr/bin/myapp": &fstest.MapFile{Data: []byte("binary")},
		}

		err := UsrLocalLinter(ctx, cfg, "test-pkg", fsys)
		assert.NoError(t, err)
	})

	t.Run("returns error for package with /usr/local files", func(t *testing.T) {
		fsys := fstest.MapFS{
			"usr/local/bin/myapp": &fstest.MapFile{Data: []byte("binary")},
		}

		err := UsrLocalLinter(ctx, cfg, "test-pkg", fsys)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "/usr/local")
	})

	t.Run("allows /usr/local for compat packages", func(t *testing.T) {
		fsys := fstest.MapFS{
			"usr/local/bin/myapp": &fstest.MapFile{Data: []byte("binary")},
		}

		err := UsrLocalLinter(ctx, cfg, "test-pkg-compat", fsys)
		assert.NoError(t, err)
	})
}

func TestTempDirLinter(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Configuration{}

	t.Run("returns nil for package without temp files", func(t *testing.T) {
		fsys := fstest.MapFS{
			"usr/bin/myapp": &fstest.MapFile{Data: []byte("binary")},
		}

		err := TempDirLinter(ctx, cfg, "test-pkg", fsys)
		assert.NoError(t, err)
	})

	t.Run("returns error for package with /tmp files", func(t *testing.T) {
		fsys := fstest.MapFS{
			"tmp/somefile": &fstest.MapFile{Data: []byte("data")},
		}

		err := TempDirLinter(ctx, cfg, "test-pkg", fsys)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "temp dir")
	})

	t.Run("returns error for package with /var/tmp files", func(t *testing.T) {
		fsys := fstest.MapFS{
			"var/tmp/somefile": &fstest.MapFile{Data: []byte("data")},
		}

		err := TempDirLinter(ctx, cfg, "test-pkg", fsys)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "temp dir")
	})

	t.Run("returns error for package with /var/run files", func(t *testing.T) {
		fsys := fstest.MapFS{
			"var/run/daemon.pid": &fstest.MapFile{Data: []byte("123")},
		}

		err := TempDirLinter(ctx, cfg, "test-pkg", fsys)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "temp dir")
	})

	t.Run("allows /run directory with tmpfiles.d", func(t *testing.T) {
		fsys := fstest.MapFS{
			"usr/lib/tmpfiles.d/myapp.conf": &fstest.MapFile{Data: []byte("config")},
			"run/myapp": &fstest.MapFile{Mode: os.ModeDir},
		}

		err := TempDirLinter(ctx, cfg, "test-pkg", fsys)
		assert.NoError(t, err)
	})

	t.Run("returns error for /run directory without tmpfiles.d", func(t *testing.T) {
		fsys := fstest.MapFS{
			"run/myapp": &fstest.MapFile{Mode: os.ModeDir},
		}

		err := TempDirLinter(ctx, cfg, "test-pkg", fsys)
		require.Error(t, err)
	})
}

func TestElfMagic(t *testing.T) {
	assert.Equal(t, []byte{'\x7f', 'E', 'L', 'F'}, ElfMagic)
}

func TestRealFilesystem(t *testing.T) {
	// Test with a real temporary directory
	tmpDir := t.TempDir()
	ctx := context.Background()
	cfg := &config.Configuration{}

	t.Run("DevLinter with real filesystem", func(t *testing.T) {
		// Create a dev directory with a file
		devDir := filepath.Join(tmpDir, "dev")
		require.NoError(t, os.MkdirAll(devDir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(devDir, "testfile"), []byte("test"), 0644))

		fsys := os.DirFS(tmpDir)
		err := DevLinter(ctx, cfg, "test-pkg", fsys)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "test-pkg writes to /dev")
	})
}
