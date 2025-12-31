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

package convention

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractPackageNameFromData(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    string
		wantErr bool
	}{
		{
			name: "valid config",
			data: `package:
  name: my-package
  version: 1.0.0`,
			want: "my-package",
		},
		{
			name: "with other fields",
			data: `package:
  name: test-pkg
  version: 2.0.0
  description: A test package
pipeline:
  - runs: echo hello`,
			want: "test-pkg",
		},
		{
			name:    "empty config",
			data:    "",
			wantErr: true,
		},
		{
			name: "missing package name",
			data: `package:
  version: 1.0.0`,
			wantErr: true,
		},
		{
			name:    "invalid yaml",
			data:    `{invalid: yaml: here`,
			wantErr: true,
		},
		{
			name: "empty package name",
			data: `package:
  name: ""
  version: 1.0.0`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractPackageNameFromData([]byte(tt.data))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractPackageName(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("valid config file", func(t *testing.T) {
		configPath := filepath.Join(tmpDir, "valid.yaml")
		err := os.WriteFile(configPath, []byte(`package:
  name: test-package
  version: 1.0.0`), 0644)
		require.NoError(t, err)

		name, err := ExtractPackageName(configPath)
		require.NoError(t, err)
		assert.Equal(t, "test-package", name)
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := ExtractPackageName("/nonexistent/path.yaml")
		assert.Error(t, err)
	})
}

func TestDetectPipelineDir(t *testing.T) {
	// Save current dir and restore after test
	origDir, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(origDir)

	t.Run("pipelines dir exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		require.NoError(t, os.Chdir(tmpDir))

		require.NoError(t, os.Mkdir("pipelines", 0755))

		result := DetectPipelineDir()
		assert.Equal(t, "pipelines", result)
	})

	t.Run("pipelines dir does not exist", func(t *testing.T) {
		tmpDir := t.TempDir()
		require.NoError(t, os.Chdir(tmpDir))

		result := DetectPipelineDir()
		assert.Empty(t, result)
	})

	t.Run("pipelines is a file not dir", func(t *testing.T) {
		tmpDir := t.TempDir()
		require.NoError(t, os.Chdir(tmpDir))
		require.NoError(t, os.WriteFile("pipelines", []byte("not a dir"), 0644))

		result := DetectPipelineDir()
		assert.Empty(t, result)
	})
}

func TestDetectSigningKey(t *testing.T) {
	origDir, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(origDir)

	t.Run("melange.rsa exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		require.NoError(t, os.Chdir(tmpDir))
		require.NoError(t, os.WriteFile("melange.rsa", []byte("key"), 0644))

		result := DetectSigningKey()
		assert.Equal(t, "melange.rsa", result)
	})

	t.Run("local-signing.rsa exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		require.NoError(t, os.Chdir(tmpDir))
		require.NoError(t, os.WriteFile("local-signing.rsa", []byte("key"), 0644))

		result := DetectSigningKey()
		assert.Equal(t, "local-signing.rsa", result)
	})

	t.Run("melange.rsa takes precedence", func(t *testing.T) {
		tmpDir := t.TempDir()
		require.NoError(t, os.Chdir(tmpDir))
		require.NoError(t, os.WriteFile("melange.rsa", []byte("key1"), 0644))
		require.NoError(t, os.WriteFile("local-signing.rsa", []byte("key2"), 0644))

		result := DetectSigningKey()
		assert.Equal(t, "melange.rsa", result)
	})

	t.Run("no key exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		require.NoError(t, os.Chdir(tmpDir))

		result := DetectSigningKey()
		assert.Empty(t, result)
	})
}

func TestDetectSourceDir(t *testing.T) {
	origDir, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(origDir)

	t.Run("source dir exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		require.NoError(t, os.Chdir(tmpDir))

		// Create config
		configPath := filepath.Join(tmpDir, "curl.yaml")
		err := os.WriteFile(configPath, []byte(`package:
  name: curl
  version: 1.0.0`), 0644)
		require.NoError(t, err)

		// Create source directory
		require.NoError(t, os.Mkdir("curl", 0755))

		result := DetectSourceDir(configPath)
		assert.Equal(t, "curl", result)
	})

	t.Run("source dir does not exist", func(t *testing.T) {
		tmpDir := t.TempDir()
		require.NoError(t, os.Chdir(tmpDir))

		configPath := filepath.Join(tmpDir, "curl.yaml")
		err := os.WriteFile(configPath, []byte(`package:
  name: curl
  version: 1.0.0`), 0644)
		require.NoError(t, err)

		result := DetectSourceDir(configPath)
		assert.Empty(t, result)
	})

	t.Run("empty config path", func(t *testing.T) {
		result := DetectSourceDir("")
		assert.Empty(t, result)
	})

	t.Run("invalid config", func(t *testing.T) {
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "invalid.yaml")
		err := os.WriteFile(configPath, []byte("invalid: yaml: bad"), 0644)
		require.NoError(t, err)

		result := DetectSourceDir(configPath)
		assert.Empty(t, result)
	})
}

func TestLoadPipelinesFromDir(t *testing.T) {
	t.Run("loads yaml files", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create pipeline files
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "build.yaml"), []byte("name: build"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "test.yaml"), []byte("name: test"), 0644))
		// Create non-yaml file (should be skipped)
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("readme"), 0644))

		pipelines, err := LoadPipelinesFromDir(tmpDir)
		require.NoError(t, err)
		assert.Len(t, pipelines, 2)
		assert.Contains(t, pipelines, "build.yaml")
		assert.Contains(t, pipelines, "test.yaml")
		assert.NotContains(t, pipelines, "readme.txt")
	})

	t.Run("handles nested directories", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create nested structure
		require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "category"), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "top.yaml"), []byte("top"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "category", "nested.yaml"), []byte("nested"), 0644))

		pipelines, err := LoadPipelinesFromDir(tmpDir)
		require.NoError(t, err)
		assert.Len(t, pipelines, 2)
		assert.Contains(t, pipelines, "top.yaml")
		assert.Contains(t, pipelines, filepath.Join("category", "nested.yaml"))
	})

	t.Run("returns empty map for empty dir", func(t *testing.T) {
		tmpDir := t.TempDir()

		pipelines, err := LoadPipelinesFromDir(tmpDir)
		require.NoError(t, err)
		assert.Empty(t, pipelines)
	})
}

func TestLoadFilesFromDir(t *testing.T) {
	t.Run("loads text files", func(t *testing.T) {
		tmpDir := t.TempDir()

		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "file2.patch"), []byte("content2"), 0644))

		files, err := LoadFilesFromDir(tmpDir)
		require.NoError(t, err)
		assert.Len(t, files, 2)
		assert.Equal(t, "content1", files["file1.txt"])
		assert.Equal(t, "content2", files["file2.patch"])
	})

	t.Run("skips binary files", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Text file
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "text.txt"), []byte("hello world"), 0644))
		// Binary file (contains null bytes)
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "binary.bin"), []byte("hello\x00world"), 0644))

		files, err := LoadFilesFromDir(tmpDir)
		require.NoError(t, err)
		assert.Len(t, files, 1)
		assert.Contains(t, files, "text.txt")
		assert.NotContains(t, files, "binary.bin")
	})
}

func TestIsBinaryContent(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		want    bool
	}{
		{
			name:    "text content",
			content: []byte("Hello, world!"),
			want:    false,
		},
		{
			name:    "binary with null byte",
			content: []byte("hello\x00world"),
			want:    true,
		},
		{
			name:    "empty content",
			content: []byte{},
			want:    false,
		},
		{
			name:    "null at start",
			content: []byte("\x00hello"),
			want:    true,
		},
		{
			name:    "newlines and tabs",
			content: []byte("line1\nline2\ttabbed"),
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBinaryContent(tt.content)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLoadPipelines(t *testing.T) {
	origDir, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(origDir)

	t.Run("no pipelines directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		require.NoError(t, os.Chdir(tmpDir))

		pipelines, err := LoadPipelines()
		require.NoError(t, err)
		assert.Nil(t, pipelines)
	})

	t.Run("pipelines directory exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		require.NoError(t, os.Chdir(tmpDir))

		require.NoError(t, os.Mkdir("pipelines", 0755))
		require.NoError(t, os.WriteFile(filepath.Join("pipelines", "custom.yaml"), []byte("name: custom"), 0644))

		pipelines, err := LoadPipelines()
		require.NoError(t, err)
		assert.Len(t, pipelines, 1)
		assert.Contains(t, pipelines, "custom.yaml")
	})

	t.Run("pipelines is a file not directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		require.NoError(t, os.Chdir(tmpDir))

		require.NoError(t, os.WriteFile("pipelines", []byte("not a directory"), 0644))

		pipelines, err := LoadPipelines()
		require.NoError(t, err)
		assert.Nil(t, pipelines)
	})
}

func TestLoadSourceFiles(t *testing.T) {
	origDir, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(origDir)

	t.Run("loads source files for package", func(t *testing.T) {
		tmpDir := t.TempDir()
		require.NoError(t, os.Chdir(tmpDir))

		// Create config
		configPath := filepath.Join(tmpDir, "myapp.yaml")
		err := os.WriteFile(configPath, []byte(`package:
  name: myapp
  version: 1.0.0`), 0644)
		require.NoError(t, err)

		// Create source directory with files
		require.NoError(t, os.Mkdir("myapp", 0755))
		require.NoError(t, os.WriteFile(filepath.Join("myapp", "patch1.patch"), []byte("patch content"), 0644))

		sources, err := LoadSourceFiles([]string{configPath})
		require.NoError(t, err)
		assert.Len(t, sources, 1)
		assert.Contains(t, sources, "myapp")
		assert.Contains(t, sources["myapp"], "patch1.patch")
	})

	t.Run("no source directories", func(t *testing.T) {
		tmpDir := t.TempDir()
		require.NoError(t, os.Chdir(tmpDir))

		configPath := filepath.Join(tmpDir, "pkg.yaml")
		err := os.WriteFile(configPath, []byte(`package:
  name: pkg
  version: 1.0.0`), 0644)
		require.NoError(t, err)

		sources, err := LoadSourceFiles([]string{configPath})
		require.NoError(t, err)
		assert.Nil(t, sources)
	})

	t.Run("multiple configs some with sources", func(t *testing.T) {
		tmpDir := t.TempDir()
		require.NoError(t, os.Chdir(tmpDir))

		// First config with sources
		config1 := filepath.Join(tmpDir, "pkg1.yaml")
		err := os.WriteFile(config1, []byte(`package:
  name: pkg1
  version: 1.0.0`), 0644)
		require.NoError(t, err)
		require.NoError(t, os.Mkdir("pkg1", 0755))
		require.NoError(t, os.WriteFile(filepath.Join("pkg1", "file.txt"), []byte("content"), 0644))

		// Second config without sources
		config2 := filepath.Join(tmpDir, "pkg2.yaml")
		err = os.WriteFile(config2, []byte(`package:
  name: pkg2
  version: 1.0.0`), 0644)
		require.NoError(t, err)

		sources, err := LoadSourceFiles([]string{config1, config2})
		require.NoError(t, err)
		assert.Len(t, sources, 1)
		assert.Contains(t, sources, "pkg1")
	})
}
