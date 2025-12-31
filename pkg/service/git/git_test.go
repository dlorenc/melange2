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

package git

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/pkg/service/types"
)

func TestNewSourceFromGitSource(t *testing.T) {
	t.Run("nil input", func(t *testing.T) {
		result := NewSourceFromGitSource(nil)
		assert.Nil(t, result)
	})

	t.Run("full git source", func(t *testing.T) {
		gs := &types.GitSource{
			Repository: "https://github.com/example/repo",
			Ref:        "main",
			Pattern:    "*.yaml",
			Path:       "configs",
		}

		result := NewSourceFromGitSource(gs)

		require.NotNil(t, result)
		assert.Equal(t, "https://github.com/example/repo", result.Repository)
		assert.Equal(t, "main", result.Ref)
		assert.Equal(t, "*.yaml", result.Pattern)
		assert.Equal(t, "configs", result.Path)
	})

	t.Run("minimal git source", func(t *testing.T) {
		gs := &types.GitSource{
			Repository: "https://github.com/example/repo",
		}

		result := NewSourceFromGitSource(gs)

		require.NotNil(t, result)
		assert.Equal(t, "https://github.com/example/repo", result.Repository)
		assert.Empty(t, result.Ref)
		assert.Empty(t, result.Pattern)
		assert.Empty(t, result.Path)
	})
}

func TestValidateSource(t *testing.T) {
	t.Run("nil source", func(t *testing.T) {
		err := ValidateSource(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nil")
	})

	t.Run("empty repository", func(t *testing.T) {
		gs := &types.GitSource{}
		err := ValidateSource(gs)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "repository is required")
	})

	t.Run("valid source", func(t *testing.T) {
		gs := &types.GitSource{
			Repository: "https://github.com/example/repo",
		}
		err := ValidateSource(gs)
		assert.NoError(t, err)
	})

	t.Run("valid source with all fields", func(t *testing.T) {
		gs := &types.GitSource{
			Repository: "https://github.com/example/repo",
			Ref:        "v1.0.0",
			Pattern:    "pkg/*.yaml",
			Path:       "packages",
		}
		err := ValidateSource(gs)
		assert.NoError(t, err)
	})
}

func TestSource_FindConfigs(t *testing.T) {
	t.Run("finds yaml files with default pattern", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create some test files
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "config1.yaml"), []byte("test1"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "config2.yaml"), []byte("test2"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "readme.md"), []byte("readme"), 0644))

		s := &Source{
			Pattern: "", // Default pattern
		}

		configs, err := s.FindConfigs(context.Background(), tmpDir)
		require.NoError(t, err)
		assert.Len(t, configs, 2)
	})

	t.Run("finds files with custom pattern", func(t *testing.T) {
		tmpDir := t.TempDir()

		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "pkg1.yaml"), []byte("test1"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "pkg2.yaml"), []byte("test2"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "test.txt"), []byte("text"), 0644))

		s := &Source{
			Pattern: "pkg*.yaml",
		}

		configs, err := s.FindConfigs(context.Background(), tmpDir)
		require.NoError(t, err)
		assert.Len(t, configs, 2)
	})

	t.Run("searches in subdirectory path", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create subdirectory
		subDir := filepath.Join(tmpDir, "packages")
		require.NoError(t, os.MkdirAll(subDir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(subDir, "app.yaml"), []byte("app"), 0644))
		// File in root should not be found
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "root.yaml"), []byte("root"), 0644))

		s := &Source{
			Path:    "packages",
			Pattern: "*.yaml",
		}

		configs, err := s.FindConfigs(context.Background(), tmpDir)
		require.NoError(t, err)
		assert.Len(t, configs, 1)
		assert.Contains(t, configs[0], "app.yaml")
	})

	t.Run("returns empty for no matches", func(t *testing.T) {
		tmpDir := t.TempDir()

		s := &Source{
			Pattern: "*.yaml",
		}

		configs, err := s.FindConfigs(context.Background(), tmpDir)
		require.NoError(t, err)
		assert.Empty(t, configs)
	})

	t.Run("handles nonexistent path gracefully", func(t *testing.T) {
		tmpDir := t.TempDir()

		s := &Source{
			Path:    "nonexistent",
			Pattern: "*.yaml",
		}

		configs, err := s.FindConfigs(context.Background(), tmpDir)
		require.NoError(t, err)
		assert.Empty(t, configs)
	})
}

func TestSource_Clone_InvalidRepo(t *testing.T) {
	// Test with an invalid repository URL
	s := &Source{
		Repository: "https://invalid-host-that-does-not-exist.example.com/repo.git",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, cleanup, err := s.Clone(ctx)
	if cleanup != nil {
		cleanup()
	}

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cloning repository")
}
