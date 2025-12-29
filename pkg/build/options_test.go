// Copyright 2022 Chainguard, Inc.
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
	"time"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/pkg/config"
)

func TestWithConfig(t *testing.T) {
	b := &Build{}
	opt := WithConfig("/path/to/config.yaml")
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, "/path/to/config.yaml", b.ConfigFile)
}

func TestWithConfiguration(t *testing.T) {
	b := &Build{}
	cfg := &config.Configuration{
		Package: config.Package{Name: "test-pkg"},
	}
	opt := WithConfiguration(cfg, "test.yaml")
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, "test.yaml", b.ConfigFile)
	require.Equal(t, cfg, b.Configuration)
}

func TestWithConfigFileRepositoryURL(t *testing.T) {
	b := &Build{}
	opt := WithConfigFileRepositoryURL("https://github.com/example/repo")
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, "https://github.com/example/repo", b.ConfigFileRepositoryURL)
}

func TestWithConfigFileRepositoryCommit(t *testing.T) {
	b := &Build{}
	opt := WithConfigFileRepositoryCommit("abc123def456")
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, "abc123def456", b.ConfigFileRepositoryCommit)
}

func TestWithConfigFileLicense(t *testing.T) {
	b := &Build{}
	opt := WithConfigFileLicense("Apache-2.0")
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, "Apache-2.0", b.ConfigFileLicense)
}

func TestWithLintRequire(t *testing.T) {
	b := &Build{}
	linters := []string{"linter1", "linter2"}
	opt := WithLintRequire(linters)
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, linters, b.LintRequire)
}

func TestWithLintWarn(t *testing.T) {
	b := &Build{}
	linters := []string{"warn1", "warn2"}
	opt := WithLintWarn(linters)
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, linters, b.LintWarn)
}

func TestWithBuildDate(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantTime  time.Time
		wantError bool
	}{
		{
			name:     "empty string defaults to epoch",
			input:    "",
			wantTime: time.Unix(0, 0),
		},
		{
			name:     "valid RFC3339 date",
			input:    "2023-06-15T10:30:00Z",
			wantTime: time.Date(2023, 6, 15, 10, 30, 0, 0, time.UTC),
		},
		{
			name:      "invalid date format",
			input:     "not-a-date",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Build{}
			opt := WithBuildDate(tt.input)
			err := opt(b)
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.True(t, tt.wantTime.Equal(b.SourceDateEpoch))
			}
		})
	}
}

func TestWithWorkspaceDir(t *testing.T) {
	b := &Build{}
	opt := WithWorkspaceDir("/workspace")
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, "/workspace", b.WorkspaceDir)
}

func TestWithWorkspaceIgnore(t *testing.T) {
	b := &Build{}
	opt := WithWorkspaceIgnore(".melangeignore")
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, ".melangeignore", b.WorkspaceIgnore)
}

func TestWithEmptyWorkspace(t *testing.T) {
	b := &Build{}
	opt := WithEmptyWorkspace(true)
	err := opt(b)
	require.NoError(t, err)
	require.True(t, b.EmptyWorkspace)
}

func TestWithPipelineDir(t *testing.T) {
	t.Run("non-empty dir is appended", func(t *testing.T) {
		b := &Build{}
		opt := WithPipelineDir("/custom/pipelines")
		err := opt(b)
		require.NoError(t, err)
		require.Contains(t, b.PipelineDirs, "/custom/pipelines")
	})

	t.Run("empty dir is not appended", func(t *testing.T) {
		b := &Build{}
		opt := WithPipelineDir("")
		err := opt(b)
		require.NoError(t, err)
		require.Empty(t, b.PipelineDirs)
	})

	t.Run("multiple dirs can be added", func(t *testing.T) {
		b := &Build{}
		WithPipelineDir("/dir1")(b)
		WithPipelineDir("/dir2")(b)
		require.Len(t, b.PipelineDirs, 2)
		require.Equal(t, []string{"/dir1", "/dir2"}, b.PipelineDirs)
	})
}

func TestWithSourceDir(t *testing.T) {
	b := &Build{}
	opt := WithSourceDir("/source")
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, "/source", b.SourceDir)
}

func TestWithCacheDir(t *testing.T) {
	b := &Build{}
	opt := WithCacheDir("/cache")
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, "/cache", b.CacheDir)
}

func TestWithSigningKey(t *testing.T) {
	t.Run("empty key is allowed", func(t *testing.T) {
		b := &Build{}
		opt := WithSigningKey("")
		err := opt(b)
		require.NoError(t, err)
		require.Empty(t, b.SigningKey)
	})

	t.Run("existing file is allowed", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "key.rsa")
		err := os.WriteFile(tmpFile, []byte("key"), 0o600)
		require.NoError(t, err)

		b := &Build{}
		opt := WithSigningKey(tmpFile)
		err = opt(b)
		require.NoError(t, err)
		require.Equal(t, tmpFile, b.SigningKey)
	})

	t.Run("non-existing file returns error", func(t *testing.T) {
		b := &Build{}
		opt := WithSigningKey("/nonexistent/key.rsa")
		err := opt(b)
		require.Error(t, err)
	})
}

func TestWithGenerateIndex(t *testing.T) {
	b := &Build{}
	opt := WithGenerateIndex(true)
	err := opt(b)
	require.NoError(t, err)
	require.True(t, b.GenerateIndex)
}

func TestWithOutDir(t *testing.T) {
	b := &Build{}
	opt := WithOutDir("/output")
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, "/output", b.OutDir)
}

func TestWithArch(t *testing.T) {
	b := &Build{}
	opt := WithArch(apko_types.Architecture("x86_64"))
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, apko_types.Architecture("x86_64"), b.Arch)
}

func TestWithExtraKeys(t *testing.T) {
	b := &Build{}
	keys := []string{"key1.pub", "key2.pub"}
	opt := WithExtraKeys(keys)
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, keys, b.ExtraKeys)
}

func TestWithExtraRepos(t *testing.T) {
	b := &Build{}
	repos := []string{"https://repo1.example.com", "https://repo2.example.com"}
	opt := WithExtraRepos(repos)
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, repos, b.ExtraRepos)
}

func TestWithDependencyLog(t *testing.T) {
	b := &Build{}
	opt := WithDependencyLog("/var/log/deps.log")
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, "/var/log/deps.log", b.DependencyLog)
}

func TestWithStripOriginName(t *testing.T) {
	b := &Build{}
	opt := WithStripOriginName(true)
	err := opt(b)
	require.NoError(t, err)
	require.True(t, b.StripOriginName)
}

func TestWithEnvFile(t *testing.T) {
	b := &Build{}
	opt := WithEnvFile("/etc/build.env")
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, "/etc/build.env", b.EnvFile)
}

func TestWithVarsFile(t *testing.T) {
	b := &Build{}
	opt := WithVarsFile("/etc/vars.yaml")
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, "/etc/vars.yaml", b.VarsFile)
}

func TestWithNamespace(t *testing.T) {
	b := &Build{}
	opt := WithNamespace("wolfi")
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, "wolfi", b.Namespace)
}

func TestWithEnabledBuildOptions(t *testing.T) {
	b := &Build{}
	opts := []string{"debug", "static"}
	opt := WithEnabledBuildOptions(opts)
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, opts, b.EnabledBuildOptions)
}

func TestWithCreateBuildLog(t *testing.T) {
	b := &Build{}
	opt := WithCreateBuildLog(true)
	err := opt(b)
	require.NoError(t, err)
	require.True(t, b.CreateBuildLog)
}

func TestWithPersistLintResults(t *testing.T) {
	b := &Build{}
	opt := WithPersistLintResults(true)
	err := opt(b)
	require.NoError(t, err)
	require.True(t, b.PersistLintResults)
}

func TestWithDebug(t *testing.T) {
	b := &Build{}
	opt := WithDebug(true)
	err := opt(b)
	require.NoError(t, err)
	require.True(t, b.Debug)
}

func TestWithRemove(t *testing.T) {
	b := &Build{}
	opt := WithRemove(true)
	err := opt(b)
	require.NoError(t, err)
	require.True(t, b.Remove)
}

func TestWithPackageCacheDir(t *testing.T) {
	b := &Build{}
	opt := WithPackageCacheDir("/var/cache/apk")
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, "/var/cache/apk", b.ApkCacheDir)
}

func TestWithExtraPackages(t *testing.T) {
	b := &Build{}
	pkgs := []string{"pkg1", "pkg2"}
	opt := WithExtraPackages(pkgs)
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, pkgs, b.ExtraPackages)
}

func TestWithAuth(t *testing.T) {
	t.Run("creates auth map if nil", func(t *testing.T) {
		b := &Build{}
		opt := WithAuth("example.com", "user", "pass")
		err := opt(b)
		require.NoError(t, err)
		require.NotNil(t, b.Auth)
		require.Equal(t, "user", b.Auth["example.com"].User)
		require.Equal(t, "pass", b.Auth["example.com"].Pass)
	})

	t.Run("adds to existing auth map", func(t *testing.T) {
		b := &Build{}
		WithAuth("domain1.com", "user1", "pass1")(b)
		WithAuth("domain2.com", "user2", "pass2")(b)
		require.Len(t, b.Auth, 2)
	})
}

func TestWithLibcFlavorOverride(t *testing.T) {
	b := &Build{}
	opt := WithLibcFlavorOverride("musl")
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, "musl", b.Libc)
}

func TestWithIgnoreSignatures(t *testing.T) {
	b := &Build{}
	opt := WithIgnoreSignatures(true)
	err := opt(b)
	require.NoError(t, err)
	require.True(t, b.IgnoreSignatures)
}

func TestWithGenerateProvenance(t *testing.T) {
	b := &Build{}
	opt := WithGenerateProvenance(true)
	err := opt(b)
	require.NoError(t, err)
	require.True(t, b.GenerateProvenance)
}

func TestWithBuildKitAddr(t *testing.T) {
	b := &Build{}
	opt := WithBuildKitAddr("tcp://localhost:1234")
	err := opt(b)
	require.NoError(t, err)
	require.Equal(t, "tcp://localhost:1234", b.BuildKitAddr)
}

func TestWithSBOMGenerator(t *testing.T) {
	b := &Build{}
	// Test with nil generator (should work, sets nil)
	opt := WithSBOMGenerator(nil)
	err := opt(b)
	require.NoError(t, err)
	require.Nil(t, b.SBOMGenerator)
}

// TestMultipleOptions tests that multiple options can be applied together
func TestMultipleOptions(t *testing.T) {
	b := &Build{}
	opts := []Option{
		WithConfig("config.yaml"),
		WithWorkspaceDir("/workspace"),
		WithOutDir("/output"),
		WithDebug(true),
		WithArch(apko_types.Architecture("aarch64")),
	}

	for _, opt := range opts {
		err := opt(b)
		require.NoError(t, err)
	}

	require.Equal(t, "config.yaml", b.ConfigFile)
	require.Equal(t, "/workspace", b.WorkspaceDir)
	require.Equal(t, "/output", b.OutDir)
	require.True(t, b.Debug)
	require.Equal(t, apko_types.Architecture("aarch64"), b.Arch)
}
