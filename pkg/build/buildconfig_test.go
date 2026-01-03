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

	"chainguard.dev/apko/pkg/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/pkg/config"
)

func TestNewBuildConfig(t *testing.T) {
	cfg := NewBuildConfig()

	assert.Equal(t, ".melangeignore", cfg.WorkspaceIgnore)
	assert.Equal(t, ".", cfg.OutDir)
	assert.Equal(t, "./melange-cache/", cfg.CacheDir)
	assert.True(t, cfg.Remove)
	assert.Equal(t, 50, cfg.MaxLayers)
}

func TestBuildConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*BuildConfig)
		wantErr string
	}{
		{
			name:    "missing config",
			setup:   func(cfg *BuildConfig) {},
			wantErr: "either ConfigFile or Configuration must be set",
		},
		{
			name: "missing repository URL",
			setup: func(cfg *BuildConfig) {
				cfg.ConfigFile = "test.yaml"
			},
			wantErr: "ConfigFileRepositoryURL is required",
		},
		{
			name: "missing repository commit",
			setup: func(cfg *BuildConfig) {
				cfg.ConfigFile = "test.yaml"
				cfg.ConfigFileRepositoryURL = "https://example.com/repo"
			},
			wantErr: "ConfigFileRepositoryCommit is required",
		},
		{
			name: "signing key not found",
			setup: func(cfg *BuildConfig) {
				cfg.ConfigFile = "test.yaml"
				cfg.ConfigFileRepositoryURL = "https://example.com/repo"
				cfg.ConfigFileRepositoryCommit = "abc123"
				cfg.SigningKey = "/nonexistent/key.rsa"
			},
			wantErr: "signing key not found",
		},
		{
			name: "valid config without signing key",
			setup: func(cfg *BuildConfig) {
				cfg.ConfigFile = "test.yaml"
				cfg.ConfigFileRepositoryURL = "https://example.com/repo"
				cfg.ConfigFileRepositoryCommit = "abc123"
			},
			wantErr: "",
		},
		{
			name: "valid config with Configuration instead of ConfigFile",
			setup: func(cfg *BuildConfig) {
				cfg.Configuration = &config.Configuration{}
				cfg.ConfigFileRepositoryURL = "https://example.com/repo"
				cfg.ConfigFileRepositoryCommit = "abc123"
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NewBuildConfig()
			tt.setup(cfg)

			err := cfg.Validate()

			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestBuildConfig_Validate_WithRealSigningKey(t *testing.T) {
	// Create a temporary signing key file
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test.rsa")
	require.NoError(t, os.WriteFile(keyPath, []byte("fake-key"), 0600))

	cfg := NewBuildConfig()
	cfg.ConfigFile = "test.yaml"
	cfg.ConfigFileRepositoryURL = "https://example.com/repo"
	cfg.ConfigFileRepositoryCommit = "abc123"
	cfg.SigningKey = keyPath

	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestBuildConfig_Clone(t *testing.T) {
	original := &BuildConfig{
		ConfigFile:               "test.yaml",
		ConfigFileRepositoryURL:  "https://example.com/repo",
		ConfigFileRepositoryCommit: "abc123",
		OutDir:                   "/output",
		PipelineDirs:             []string{"/pipelines1", "/pipelines2"},
		ExtraKeys:                []string{"key1", "key2"},
		ExtraRepos:               []string{"repo1", "repo2"},
		ExtraPackages:            []string{"pkg1", "pkg2"},
		LintRequire:              []string{"lint1"},
		LintWarn:                 []string{"lint2"},
		EnabledBuildOptions:      []string{"opt1"},
		Auth: map[string]options.Auth{
			"registry.example.com": {User: "user", Pass: "pass"},
		},
	}

	clone := original.Clone()

	// Verify the clone is equal
	assert.Equal(t, original.ConfigFile, clone.ConfigFile)
	assert.Equal(t, original.ConfigFileRepositoryURL, clone.ConfigFileRepositoryURL)
	assert.Equal(t, original.OutDir, clone.OutDir)
	assert.Equal(t, original.PipelineDirs, clone.PipelineDirs)
	assert.Equal(t, original.ExtraKeys, clone.ExtraKeys)
	assert.Equal(t, original.ExtraRepos, clone.ExtraRepos)
	assert.Equal(t, original.ExtraPackages, clone.ExtraPackages)
	assert.Equal(t, original.LintRequire, clone.LintRequire)
	assert.Equal(t, original.LintWarn, clone.LintWarn)
	assert.Equal(t, original.EnabledBuildOptions, clone.EnabledBuildOptions)
	assert.Equal(t, original.Auth, clone.Auth)

	// Verify the clone is a deep copy (modifying clone doesn't affect original)
	clone.PipelineDirs[0] = "/modified"
	assert.NotEqual(t, original.PipelineDirs[0], clone.PipelineDirs[0])

	clone.ExtraKeys[0] = "modified-key"
	assert.NotEqual(t, original.ExtraKeys[0], clone.ExtraKeys[0])

	clone.Auth["new-registry"] = options.Auth{User: "new"}
	assert.NotContains(t, original.Auth, "new-registry")
}

func TestBuildConfig_Clone_NilSlices(t *testing.T) {
	original := &BuildConfig{
		ConfigFile: "test.yaml",
		// All slices and maps are nil
	}

	clone := original.Clone()

	assert.Equal(t, original.ConfigFile, clone.ConfigFile)
	assert.Nil(t, clone.PipelineDirs)
	assert.Nil(t, clone.ExtraKeys)
	assert.Nil(t, clone.ExtraRepos)
	assert.Nil(t, clone.ExtraPackages)
	assert.Nil(t, clone.LintRequire)
	assert.Nil(t, clone.LintWarn)
	assert.Nil(t, clone.EnabledBuildOptions)
	assert.Nil(t, clone.Auth)
}

func TestNewBuildConfigForRemote(t *testing.T) {
	params := RemoteBuildParams{
		ConfigPath:    "/configs/test.yaml",
		PipelineDir:   "/pipelines",
		SourceDir:     "/sources",
		OutputDir:     "/output",
		CacheDir:      "/cache",
		ApkCacheDir:   "/apk-cache",
		BackendAddr:   "tcp://localhost:1234",
		Debug:         true,
		JobID:         "job-123",
		CacheRegistry: "registry.example.com/cache",
		CacheMode:     "max",
		ExtraEnv: map[string]string{
			"CUSTOM_VAR": "value",
		},
	}

	cfg := NewBuildConfigForRemote(params)

	assert.Equal(t, params.ConfigPath, cfg.ConfigFile)
	assert.Equal(t, "https://melange-service/inline", cfg.ConfigFileRepositoryURL)
	assert.Equal(t, "inline-job-123", cfg.ConfigFileRepositoryCommit)
	assert.Equal(t, []string{params.PipelineDir}, cfg.PipelineDirs)
	assert.Equal(t, params.SourceDir, cfg.SourceDir)
	assert.Equal(t, params.OutputDir, cfg.OutDir)
	assert.Equal(t, params.CacheDir, cfg.CacheDir)
	assert.Equal(t, params.ApkCacheDir, cfg.ApkCacheDir)
	assert.Equal(t, params.BackendAddr, cfg.BuildKitAddr)
	assert.True(t, cfg.Debug)
	assert.True(t, cfg.GenerateIndex)
	assert.True(t, cfg.IgnoreSignatures)
	assert.Equal(t, "wolfi", cfg.Namespace)
	assert.Equal(t, params.CacheRegistry, cfg.CacheRegistry)
	assert.Equal(t, params.CacheMode, cfg.CacheMode)
}

func TestNewBuildConfigForRemote_MinimalParams(t *testing.T) {
	params := RemoteBuildParams{
		ConfigPath: "/configs/test.yaml",
		OutputDir:  "/output",
		JobID:      "job-456",
	}

	cfg := NewBuildConfigForRemote(params)

	assert.Equal(t, params.ConfigPath, cfg.ConfigFile)
	assert.Empty(t, cfg.PipelineDirs)
	assert.Empty(t, cfg.SourceDir)
	assert.Equal(t, params.OutputDir, cfg.OutDir)
}
