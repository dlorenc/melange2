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

package manifest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apkotypes "chainguard.dev/apko/pkg/build/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/pkg/config"
)

func TestGeneratedMelangeConfig_SetPackage(t *testing.T) {
	m := &GeneratedMelangeConfig{}
	pkg := config.Package{
		Name:        "test-package",
		Version:     "1.0.0",
		Description: "A test package",
	}

	m.SetPackage(pkg)

	assert.Equal(t, "test-package", m.Package.Name)
	assert.Equal(t, "1.0.0", m.Package.Version)
	assert.Equal(t, "A test package", m.Package.Description)
}

func TestGeneratedMelangeConfig_SetEnvironment(t *testing.T) {
	m := &GeneratedMelangeConfig{}
	env := apkotypes.ImageConfiguration{
		Contents: apkotypes.ImageContents{
			Packages: []string{"busybox", "ca-certificates"},
		},
	}

	m.SetEnvironment(env)

	assert.Equal(t, []string{"busybox", "ca-certificates"}, m.Environment.Contents.Packages)
}

func TestGeneratedMelangeConfig_SetPipeline(t *testing.T) {
	m := &GeneratedMelangeConfig{}
	pipeline := []config.Pipeline{
		{Name: "build", Runs: "make"},
		{Name: "install", Runs: "make install"},
	}

	m.SetPipeline(pipeline)

	assert.Len(t, m.Pipeline, 2)
	assert.Equal(t, "build", m.Pipeline[0].Name)
	assert.Equal(t, "install", m.Pipeline[1].Name)
}

func TestGeneratedMelangeConfig_SetSubpackages(t *testing.T) {
	m := &GeneratedMelangeConfig{}
	subs := []config.Subpackage{
		{Name: "test-package-dev"},
		{Name: "test-package-doc"},
	}

	m.SetSubpackages(subs)

	assert.Len(t, m.Subpackages, 2)
	assert.Equal(t, "test-package-dev", m.Subpackages[0].Name)
	assert.Equal(t, "test-package-doc", m.Subpackages[1].Name)
}

func TestGeneratedMelangeConfig_SetGeneratedFromComment(t *testing.T) {
	m := &GeneratedMelangeConfig{}

	m.SetGeneratedFromComment("https://example.com/package")

	assert.Equal(t, "https://example.com/package", m.GeneratedFromComment)
}

func TestGeneratedMelangeConfig_Write(t *testing.T) {
	t.Run("creates directory and writes file", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputDir := filepath.Join(tmpDir, "nested", "output")

		m := &GeneratedMelangeConfig{
			GeneratedFromComment: "https://example.com/source",
		}
		m.SetPackage(config.Package{
			Name:        "my-package",
			Version:     "2.0.0",
			Description: "My test package",
		})
		m.SetPipeline([]config.Pipeline{
			{Runs: "echo hello"},
		})

		err := m.Write(context.Background(), outputDir)
		require.NoError(t, err)

		// Check file was created
		expectedPath := filepath.Join(outputDir, "my-package.yaml")
		_, err = os.Stat(expectedPath)
		require.NoError(t, err)

		// Check content
		content, err := os.ReadFile(expectedPath)
		require.NoError(t, err)

		contentStr := string(content)
		assert.True(t, strings.HasPrefix(contentStr, "# Generated from https://example.com/source"))
		assert.Contains(t, contentStr, "name: my-package")
		assert.Contains(t, contentStr, "version: 2.0.0")
	})

	t.Run("uses existing directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		m := &GeneratedMelangeConfig{
			GeneratedFromComment: "test-source",
		}
		m.SetPackage(config.Package{
			Name:    "existing-dir-test",
			Version: "1.0.0",
		})

		err := m.Write(context.Background(), tmpDir)
		require.NoError(t, err)

		expectedPath := filepath.Join(tmpDir, "existing-dir-test.yaml")
		_, err = os.Stat(expectedPath)
		require.NoError(t, err)
	})

	t.Run("includes generated comment", func(t *testing.T) {
		tmpDir := t.TempDir()

		m := &GeneratedMelangeConfig{
			GeneratedFromComment: "https://github.com/example/repo",
		}
		m.SetPackage(config.Package{
			Name:    "comment-test",
			Version: "1.0.0",
		})

		err := m.Write(context.Background(), tmpDir)
		require.NoError(t, err)

		content, err := os.ReadFile(filepath.Join(tmpDir, "comment-test.yaml"))
		require.NoError(t, err)

		lines := strings.Split(string(content), "\n")
		assert.Equal(t, "# Generated from https://github.com/example/repo", lines[0])
	})

	t.Run("handles complex configuration", func(t *testing.T) {
		tmpDir := t.TempDir()

		m := &GeneratedMelangeConfig{
			GeneratedFromComment: "complex-test",
		}
		m.SetPackage(config.Package{
			Name:        "complex-pkg",
			Version:     "3.0.0",
			Description: "A complex package",
			URL:         "https://example.com",
		})
		m.SetEnvironment(apkotypes.ImageConfiguration{
			Contents: apkotypes.ImageContents{
				Packages: []string{"build-base", "cmake"},
			},
		})
		m.SetPipeline([]config.Pipeline{
			{Name: "configure", Runs: "./configure"},
			{Name: "build", Runs: "make -j$(nproc)"},
			{Name: "install", Runs: "make install DESTDIR=${{targets.destdir}}"},
		})
		m.SetSubpackages([]config.Subpackage{
			{Name: "complex-pkg-dev", Description: "Development files"},
		})

		err := m.Write(context.Background(), tmpDir)
		require.NoError(t, err)

		content, err := os.ReadFile(filepath.Join(tmpDir, "complex-pkg.yaml"))
		require.NoError(t, err)

		contentStr := string(content)
		assert.Contains(t, contentStr, "complex-pkg")
		assert.Contains(t, contentStr, "3.0.0")
	})
}
