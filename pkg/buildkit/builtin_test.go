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

package buildkit

import (
	"testing"

	"github.com/moby/buildkit/client/llb"
	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/pkg/config"
)

func TestIsBuiltinPipeline(t *testing.T) {
	tests := []struct {
		name     string
		pipeline string
		expected bool
	}{
		{"git-checkout is builtin", "git-checkout", true},
		{"fetch is builtin", "fetch", true},
		{"autoconf/configure is not builtin", "autoconf/configure", false},
		{"split/dev is not builtin", "split/dev", false},
		{"empty string is not builtin", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsBuiltinPipeline(tt.pipeline)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildBuiltinPipeline_GitCheckout(t *testing.T) {
	base := llb.Image(TestBaseImage)
	base = SetupBuildUser(base)
	base = PrepareWorkspace(base, "test-pkg")

	tests := []struct {
		name        string
		with        map[string]string
		expectError bool
		errorMsg    string
	}{
		{
			name: "basic git clone",
			with: map[string]string{
				"repository": "https://github.com/octocat/Hello-World.git",
			},
			expectError: false,
		},
		{
			name: "git clone with tag",
			with: map[string]string{
				"repository": "https://github.com/octocat/Hello-World.git",
				"tag":        "v1.0",
			},
			expectError: false,
		},
		{
			name: "git clone with branch and expected-commit",
			with: map[string]string{
				"repository":      "https://github.com/octocat/Hello-World.git",
				"branch":          "main",
				"expected-commit": "abc123def456",
			},
			expectError: false,
		},
		{
			name: "git clone with custom destination",
			with: map[string]string{
				"repository":  "https://github.com/octocat/Hello-World.git",
				"destination": "my-project",
			},
			expectError: false,
		},
		{
			name: "git clone with depth",
			with: map[string]string{
				"repository": "https://github.com/octocat/Hello-World.git",
				"depth":      "1",
			},
			expectError: false,
		},
		{
			name: "git clone with full history",
			with: map[string]string{
				"repository": "https://github.com/octocat/Hello-World.git",
				"depth":      "-1",
			},
			expectError: false,
		},
		{
			name:        "missing repository",
			with:        map[string]string{},
			expectError: true,
			errorMsg:    "repository is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &config.Pipeline{
				Uses: "git-checkout",
				With: tt.with,
			}

			state, err := BuildBuiltinPipeline(base, p)
			if tt.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
				// Verify state is valid (not empty)
				require.NotEqual(t, llb.State{}, state)
			}
		})
	}
}

func TestBuildBuiltinPipeline_Fetch(t *testing.T) {
	base := llb.Image(TestBaseImage)
	base = SetupBuildUser(base)
	base = PrepareWorkspace(base, "test-pkg")

	tests := []struct {
		name        string
		with        map[string]string
		expectError bool
		errorMsg    string
	}{
		{
			name: "basic fetch with sha256",
			with: map[string]string{
				"uri":             "https://example.com/file.tar.gz",
				"expected-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			expectError: false,
		},
		{
			name: "fetch with sha512 returns fallback error",
			with: map[string]string{
				"uri":             "https://example.com/file.tar.gz",
				"expected-sha512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
			},
			expectError: true,
			errorMsg:    "sha512 requires shell fallback",
		},
		{
			name: "fetch with expected-none returns error",
			with: map[string]string{
				"uri":           "https://example.com/file.tar.gz",
				"expected-none": "true",
			},
			expectError: true,
			errorMsg:    "expected-none is not supported",
		},
		{
			name: "fetch with custom strip-components",
			with: map[string]string{
				"uri":              "https://example.com/file.tar.gz",
				"expected-sha256":  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				"strip-components": "2",
			},
			expectError: false,
		},
		{
			name: "fetch without extraction",
			with: map[string]string{
				"uri":             "https://example.com/file.bin",
				"expected-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				"extract":         "false",
			},
			expectError: false,
		},
		{
			name: "fetch to custom directory",
			with: map[string]string{
				"uri":             "https://example.com/file.tar.gz",
				"expected-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				"directory":       "subdir",
			},
			expectError: false,
		},
		{
			name:        "missing uri",
			with:        map[string]string{},
			expectError: true,
			errorMsg:    "uri is required",
		},
		{
			name: "missing checksum",
			with: map[string]string{
				"uri": "https://example.com/file.tar.gz",
			},
			expectError: true,
			errorMsg:    "expected-sha256 is required for native LLB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &config.Pipeline{
				Uses: "fetch",
				With: tt.with,
			}

			state, err := BuildBuiltinPipeline(base, p)
			if tt.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
				// Verify state is valid (not empty)
				require.NotEqual(t, llb.State{}, state)
			}
		})
	}
}

func TestBuildBuiltinPipeline_UnknownPipeline(t *testing.T) {
	base := llb.Image(TestBaseImage)

	p := &config.Pipeline{
		Uses: "unknown-pipeline",
		With: map[string]string{},
	}

	_, err := BuildBuiltinPipeline(base, p)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown built-in pipeline")
}
