// Copyright 2023 Chainguard, Inc.
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
	"testing"
	"time"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/stretchr/testify/require"
)

func TestWithTestConfig(t *testing.T) {
	test := &Test{}
	opt := WithTestConfig("/path/to/test.yaml")
	err := opt(test)
	require.NoError(t, err)
	require.Equal(t, "/path/to/test.yaml", test.ConfigFile)
}

func TestWithTestWorkspaceDir(t *testing.T) {
	test := &Test{}
	opt := WithTestWorkspaceDir("/workspace")
	err := opt(test)
	require.NoError(t, err)
	require.Equal(t, "/workspace", test.WorkspaceDir)
}

func TestWithTestWorkspaceIgnore(t *testing.T) {
	test := &Test{}
	opt := WithTestWorkspaceIgnore(".testignore")
	err := opt(test)
	require.NoError(t, err)
	require.Equal(t, ".testignore", test.WorkspaceIgnore)
}

func TestWithTestPipelineDir(t *testing.T) {
	test := &Test{}
	opt := WithTestPipelineDir("/custom/pipelines")
	err := opt(test)
	require.NoError(t, err)
	require.Contains(t, test.PipelineDirs, "/custom/pipelines")
}

func TestWithTestSourceDir(t *testing.T) {
	test := &Test{}
	opt := WithTestSourceDir("/source")
	err := opt(test)
	require.NoError(t, err)
	require.Equal(t, "/source", test.SourceDir)
}

func TestWithTestCacheDir(t *testing.T) {
	test := &Test{}
	opt := WithTestCacheDir("/cache")
	err := opt(test)
	require.NoError(t, err)
	require.Equal(t, "/cache", test.CacheDir)
}

func TestWithTestCacheSource(t *testing.T) {
	test := &Test{}
	opt := WithTestCacheSource("/cache/source")
	err := opt(test)
	require.NoError(t, err)
	require.Equal(t, "/cache/source", test.CacheSource)
}

func TestWithTestArch(t *testing.T) {
	test := &Test{}
	opt := WithTestArch(apko_types.Architecture("aarch64"))
	err := opt(test)
	require.NoError(t, err)
	require.Equal(t, apko_types.Architecture("aarch64"), test.Arch)
}

func TestWithTestExtraKeys(t *testing.T) {
	test := &Test{}
	keys := []string{"key1.pub", "key2.pub"}
	opt := WithTestExtraKeys(keys)
	err := opt(test)
	require.NoError(t, err)
	require.Equal(t, keys, test.ExtraKeys)
}

func TestWithTestDebug(t *testing.T) {
	test := &Test{}
	opt := WithTestDebug(true)
	err := opt(test)
	require.NoError(t, err)
	require.True(t, test.Debug)
}

func TestWithTestDebugRunner(t *testing.T) {
	test := &Test{}
	opt := WithTestDebugRunner(true)
	err := opt(test)
	require.NoError(t, err)
	require.True(t, test.DebugRunner)
}

func TestWithTestInteractive(t *testing.T) {
	test := &Test{}
	opt := WithTestInteractive(true)
	err := opt(test)
	require.NoError(t, err)
	require.True(t, test.Interactive)
}

func TestWithTestExtraRepos(t *testing.T) {
	test := &Test{}
	repos := []string{"https://repo1.example.com", "https://repo2.example.com"}
	opt := WithTestExtraRepos(repos)
	err := opt(test)
	require.NoError(t, err)
	require.Equal(t, repos, test.ExtraRepos)
}

func TestWithTestBinShOverlay(t *testing.T) {
	test := &Test{}
	opt := WithTestBinShOverlay("/custom/sh")
	err := opt(test)
	require.NoError(t, err)
	require.Equal(t, "/custom/sh", test.BinShOverlay)
}

func TestWithTestPackage(t *testing.T) {
	test := &Test{}
	opt := WithTestPackage("mypackage")
	err := opt(test)
	require.NoError(t, err)
	require.Equal(t, "mypackage", test.Package)
}

func TestWithTestPackageCacheDir(t *testing.T) {
	test := &Test{}
	opt := WithTestPackageCacheDir("/var/cache/apk")
	err := opt(test)
	require.NoError(t, err)
	require.Equal(t, "/var/cache/apk", test.ApkCacheDir)
}

func TestWithExtraTestPackages(t *testing.T) {
	test := &Test{}
	pkgs := []string{"pkg1", "pkg2"}
	opt := WithExtraTestPackages(pkgs)
	err := opt(test)
	require.NoError(t, err)
	require.Equal(t, pkgs, test.ExtraTestPackages)
}

func TestWithTestEnvFile(t *testing.T) {
	test := &Test{}
	opt := WithTestEnvFile("/etc/test.env")
	err := opt(test)
	require.NoError(t, err)
	require.Equal(t, "/etc/test.env", test.EnvFile)
}

func TestWithTestAuth(t *testing.T) {
	t.Run("creates auth map if nil", func(t *testing.T) {
		test := &Test{}
		opt := WithTestAuth("example.com", "user", "pass")
		err := opt(test)
		require.NoError(t, err)
		require.NotNil(t, test.Auth)
		require.Equal(t, "user", test.Auth["example.com"].User)
		require.Equal(t, "pass", test.Auth["example.com"].Pass)
	})

	t.Run("adds to existing auth map", func(t *testing.T) {
		test := &Test{}
		WithTestAuth("domain1.com", "user1", "pass1")(test)
		WithTestAuth("domain2.com", "user2", "pass2")(test)
		require.Len(t, test.Auth, 2)
	})
}

func TestWithTestRemove(t *testing.T) {
	test := &Test{}
	opt := WithTestRemove(true)
	err := opt(test)
	require.NoError(t, err)
	require.True(t, test.Remove)
}

func TestWithTestIgnoreSignatures(t *testing.T) {
	test := &Test{}
	opt := WithTestIgnoreSignatures(true)
	err := opt(test)
	require.NoError(t, err)
	require.True(t, test.IgnoreSignatures)
}

func TestWithTestCPU(t *testing.T) {
	test := &Test{}
	opt := WithTestCPU("2")
	err := opt(test)
	require.NoError(t, err)
	require.Equal(t, "2", test.DefaultCPU)
}

func TestWithTestCPUModel(t *testing.T) {
	test := &Test{}
	opt := WithTestCPUModel("host")
	err := opt(test)
	require.NoError(t, err)
	require.Equal(t, "host", test.DefaultCPUModel)
}

func TestWithTestDisk(t *testing.T) {
	test := &Test{}
	opt := WithTestDisk("10G")
	err := opt(test)
	require.NoError(t, err)
	require.Equal(t, "10G", test.DefaultDisk)
}

func TestWithTestMemory(t *testing.T) {
	test := &Test{}
	opt := WithTestMemory("4G")
	err := opt(test)
	require.NoError(t, err)
	require.Equal(t, "4G", test.DefaultMemory)
}

func TestWithTestTimeout(t *testing.T) {
	test := &Test{}
	timeout := 30 * time.Minute
	opt := WithTestTimeout(timeout)
	err := opt(test)
	require.NoError(t, err)
	require.Equal(t, timeout, test.DefaultTimeout)
}

// TestMultipleTestOptions tests that multiple options can be applied together
func TestMultipleTestOptions(t *testing.T) {
	test := &Test{}
	opts := []TestOption{
		WithTestConfig("config.yaml"),
		WithTestWorkspaceDir("/workspace"),
		WithTestDebug(true),
		WithTestArch(apko_types.Architecture("x86_64")),
		WithTestTimeout(10 * time.Minute),
	}

	for _, opt := range opts {
		err := opt(test)
		require.NoError(t, err)
	}

	require.Equal(t, "config.yaml", test.ConfigFile)
	require.Equal(t, "/workspace", test.WorkspaceDir)
	require.True(t, test.Debug)
	require.Equal(t, apko_types.Architecture("x86_64"), test.Arch)
	require.Equal(t, 10*time.Minute, test.DefaultTimeout)
}
