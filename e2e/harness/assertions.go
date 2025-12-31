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

package harness

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// FileExists asserts that a file exists at the given path within the output directory.
func FileExists(t *testing.T, outDir, path string) {
	t.Helper()
	fullPath := filepath.Join(outDir, path)
	_, err := os.Stat(fullPath)
	require.NoError(t, err, "file should exist: %s", path)
}

// FileNotExists asserts that a file does NOT exist at the given path.
func FileNotExists(t *testing.T, outDir, path string) {
	t.Helper()
	fullPath := filepath.Join(outDir, path)
	_, err := os.Stat(fullPath)
	require.True(t, os.IsNotExist(err), "file should not exist: %s", path)
}

// FileContains asserts that a file contains the expected string.
func FileContains(t *testing.T, outDir, path, expected string) {
	t.Helper()
	fullPath := filepath.Join(outDir, path)
	content, err := os.ReadFile(fullPath)
	require.NoError(t, err, "should read file: %s", path)
	require.Contains(t, string(content), expected, "file %s should contain %q", path, expected)
}

// FileNotContains asserts that a file does NOT contain the specified string.
func FileNotContains(t *testing.T, outDir, path, notExpected string) {
	t.Helper()
	fullPath := filepath.Join(outDir, path)
	content, err := os.ReadFile(fullPath)
	require.NoError(t, err, "should read file: %s", path)
	require.NotContains(t, string(content), notExpected, "file %s should not contain %q", path, notExpected)
}

// FileEquals asserts that a file's content exactly equals the expected string.
func FileEquals(t *testing.T, outDir, path, expected string) {
	t.Helper()
	fullPath := filepath.Join(outDir, path)
	content, err := os.ReadFile(fullPath)
	require.NoError(t, err, "should read file: %s", path)
	require.Equal(t, expected, string(content), "file %s should equal expected content", path)
}

// FileHasSize asserts that a file has the expected size in bytes.
func FileHasSize(t *testing.T, outDir, path string, expectedSize int64) {
	t.Helper()
	fullPath := filepath.Join(outDir, path)
	info, err := os.Stat(fullPath)
	require.NoError(t, err, "should stat file: %s", path)
	require.Equal(t, expectedSize, info.Size(), "file %s should have size %d", path, expectedSize)
}

// FileIsExecutable asserts that a file has executable permissions.
func FileIsExecutable(t *testing.T, outDir, path string) {
	t.Helper()
	fullPath := filepath.Join(outDir, path)
	info, err := os.Stat(fullPath)
	require.NoError(t, err, "should stat file: %s", path)
	mode := info.Mode()
	require.True(t, mode&0111 != 0, "file %s should be executable (mode: %o)", path, mode)
}

// DirExists asserts that a directory exists at the given path.
func DirExists(t *testing.T, outDir, path string) {
	t.Helper()
	fullPath := filepath.Join(outDir, path)
	info, err := os.Stat(fullPath)
	require.NoError(t, err, "directory should exist: %s", path)
	require.True(t, info.IsDir(), "%s should be a directory", path)
}

// FilesExist asserts that all given files exist in the output directory.
func FilesExist(t *testing.T, outDir string, paths ...string) {
	t.Helper()
	for _, path := range paths {
		FileExists(t, outDir, path)
	}
}

// ReadFile reads a file from the output directory and returns its contents.
func ReadFile(t *testing.T, outDir, path string) string {
	t.Helper()
	fullPath := filepath.Join(outDir, path)
	content, err := os.ReadFile(fullPath)
	require.NoError(t, err, "should read file: %s", path)
	return string(content)
}
