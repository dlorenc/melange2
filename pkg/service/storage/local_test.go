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

package storage

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLocalStorage(t *testing.T) {
	t.Run("creates base directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		baseDir := filepath.Join(tmpDir, "storage", "nested")

		storage, err := NewLocalStorage(baseDir)
		require.NoError(t, err)
		require.NotNil(t, storage)

		// Verify directory was created
		info, err := os.Stat(baseDir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
	})

	t.Run("uses existing directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		storage, err := NewLocalStorage(tmpDir)
		require.NoError(t, err)
		require.NotNil(t, storage)
	})
}

func TestLocalStorage_WriteLog(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	storage, err := NewLocalStorage(tmpDir)
	require.NoError(t, err)

	t.Run("writes log file", func(t *testing.T) {
		logContent := "Build started\nStep 1: Success\nBuild finished"
		reader := strings.NewReader(logContent)

		url, err := storage.WriteLog(ctx, "job-123", "my-package", reader)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(url, "file://"))

		// Verify file contents
		filePath := strings.TrimPrefix(url, "file://")
		content, err := os.ReadFile(filePath)
		require.NoError(t, err)
		assert.Equal(t, logContent, string(content))

		// Verify directory structure
		assert.Contains(t, filePath, "job-123")
		assert.Contains(t, filePath, "logs")
		assert.True(t, strings.HasSuffix(filePath, "my-package.log"))
	})

	t.Run("creates nested directories", func(t *testing.T) {
		reader := strings.NewReader("test log")
		url, err := storage.WriteLog(ctx, "new-job", "pkg", reader)
		require.NoError(t, err)

		logDir := filepath.Join(tmpDir, "new-job", "logs")
		info, err := os.Stat(logDir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
		assert.NotEmpty(t, url)
	})

	t.Run("handles large content", func(t *testing.T) {
		largeContent := bytes.Repeat([]byte("x"), 1024*1024) // 1MB
		reader := bytes.NewReader(largeContent)

		url, err := storage.WriteLog(ctx, "large-job", "pkg", reader)
		require.NoError(t, err)

		filePath := strings.TrimPrefix(url, "file://")
		info, err := os.Stat(filePath)
		require.NoError(t, err)
		assert.Equal(t, int64(len(largeContent)), info.Size())
	})
}

func TestLocalStorage_WriteArtifact(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	storage, err := NewLocalStorage(tmpDir)
	require.NoError(t, err)

	t.Run("writes artifact file", func(t *testing.T) {
		content := []byte("artifact content")
		reader := bytes.NewReader(content)

		url, err := storage.WriteArtifact(ctx, "job-456", "output.apk", reader)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(url, "file://"))

		// Verify file contents
		filePath := strings.TrimPrefix(url, "file://")
		readContent, err := os.ReadFile(filePath)
		require.NoError(t, err)
		assert.Equal(t, content, readContent)

		// Verify directory structure
		assert.Contains(t, filePath, "job-456")
		assert.Contains(t, filePath, "artifacts")
		assert.True(t, strings.HasSuffix(filePath, "output.apk"))
	})

	t.Run("preserves artifact name", func(t *testing.T) {
		reader := strings.NewReader("test")
		url, err := storage.WriteArtifact(ctx, "job-789", "my-pkg-1.0.0-r0.apk", reader)
		require.NoError(t, err)

		filePath := strings.TrimPrefix(url, "file://")
		assert.True(t, strings.HasSuffix(filePath, "my-pkg-1.0.0-r0.apk"))
	})
}

func TestLocalStorage_GetLogURL(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	storage, err := NewLocalStorage(tmpDir)
	require.NoError(t, err)

	t.Run("returns URL for existing log", func(t *testing.T) {
		// First write a log
		reader := strings.NewReader("log content")
		_, err := storage.WriteLog(ctx, "job-get", "pkg", reader)
		require.NoError(t, err)

		// Then get its URL
		url, err := storage.GetLogURL(ctx, "job-get", "pkg")
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(url, "file://"))
		assert.Contains(t, url, "job-get")
		assert.Contains(t, url, "pkg.log")
	})

	t.Run("error for non-existent log", func(t *testing.T) {
		_, err := storage.GetLogURL(ctx, "non-existent-job", "pkg")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "log not found")
	})
}

func TestLocalStorage_ListArtifacts(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	storage, err := NewLocalStorage(tmpDir)
	require.NoError(t, err)

	t.Run("empty when no artifacts", func(t *testing.T) {
		artifacts, err := storage.ListArtifacts(ctx, "empty-job")
		require.NoError(t, err)
		assert.Empty(t, artifacts)
	})

	t.Run("lists all artifacts", func(t *testing.T) {
		// Write multiple artifacts
		storage.WriteArtifact(ctx, "list-job", "pkg-1.0.0.apk", strings.NewReader("content1"))
		storage.WriteArtifact(ctx, "list-job", "pkg-dev-1.0.0.apk", strings.NewReader("content2content2"))
		storage.WriteArtifact(ctx, "list-job", "APKINDEX.tar.gz", strings.NewReader("idx"))

		artifacts, err := storage.ListArtifacts(ctx, "list-job")
		require.NoError(t, err)
		assert.Len(t, artifacts, 3)

		// Verify artifact properties
		names := make([]string, len(artifacts))
		for i, a := range artifacts {
			names[i] = a.Name
			assert.True(t, strings.HasPrefix(a.URL, "file://"))
			assert.Greater(t, a.Size, int64(0))
		}
		assert.Contains(t, names, "pkg-1.0.0.apk")
		assert.Contains(t, names, "pkg-dev-1.0.0.apk")
		assert.Contains(t, names, "APKINDEX.tar.gz")
	})

	t.Run("excludes directories", func(t *testing.T) {
		// Create artifact directory with a subdirectory
		artifactDir := filepath.Join(tmpDir, "dir-test-job", "artifacts")
		require.NoError(t, os.MkdirAll(artifactDir, 0755))
		require.NoError(t, os.MkdirAll(filepath.Join(artifactDir, "subdir"), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(artifactDir, "file.apk"), []byte("data"), 0644))

		artifacts, err := storage.ListArtifacts(ctx, "dir-test-job")
		require.NoError(t, err)
		assert.Len(t, artifacts, 1)
		assert.Equal(t, "file.apk", artifacts[0].Name)
	})
}

func TestLocalStorage_OutputDir(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	storage, err := NewLocalStorage(tmpDir)
	require.NoError(t, err)

	t.Run("creates and returns output directory", func(t *testing.T) {
		dir, err := storage.OutputDir(ctx, "output-job")
		require.NoError(t, err)

		info, err := os.Stat(dir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
		assert.Contains(t, dir, "output-job")
	})

	t.Run("returns same path for same job", func(t *testing.T) {
		dir1, err := storage.OutputDir(ctx, "same-job")
		require.NoError(t, err)

		dir2, err := storage.OutputDir(ctx, "same-job")
		require.NoError(t, err)

		assert.Equal(t, dir1, dir2)
	})

	t.Run("different paths for different jobs", func(t *testing.T) {
		dir1, err := storage.OutputDir(ctx, "job-a")
		require.NoError(t, err)

		dir2, err := storage.OutputDir(ctx, "job-b")
		require.NoError(t, err)

		assert.NotEqual(t, dir1, dir2)
	})
}

func TestLocalStorage_SyncOutputDir(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	storage, err := NewLocalStorage(tmpDir)
	require.NoError(t, err)

	t.Run("is a no-op", func(t *testing.T) {
		// SyncOutputDir should be a no-op for local storage
		err := storage.SyncOutputDir(ctx, "any-job", "/some/path")
		require.NoError(t, err)
	})
}

// Verify LocalStorage implements Storage interface
var _ Storage = (*LocalStorage)(nil)
