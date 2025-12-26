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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/pkg/config"
)

func TestPackageBuildIdentity(t *testing.T) {
	tests := []struct {
		name     string
		pb       *PackageBuild
		expected string
	}{
		{
			name: "simple package",
			pb: &PackageBuild{
				PackageName: "mypackage",
				Origin: &config.Package{
					Version: "1.0.0",
					Epoch:   0,
				},
			},
			expected: "mypackage-1.0.0-r0",
		},
		{
			name: "package with epoch",
			pb: &PackageBuild{
				PackageName: "test-pkg",
				Origin: &config.Package{
					Version: "2.3.4",
					Epoch:   5,
				},
			},
			expected: "test-pkg-2.3.4-r5",
		},
		{
			name: "package with complex version",
			pb: &PackageBuild{
				PackageName: "complex",
				Origin: &config.Package{
					Version: "1.2.3_alpha1",
					Epoch:   10,
				},
			},
			expected: "complex-1.2.3_alpha1-r10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, tt.pb.Identity())
		})
	}
}

func TestPackageBuildFilename(t *testing.T) {
	pb := &PackageBuild{
		PackageName: "testpkg",
		OutDir:      "/output/x86_64",
		Origin: &config.Package{
			Version: "1.0.0",
			Epoch:   0,
		},
	}

	expected := "/output/x86_64/testpkg-1.0.0-r0.apk"
	require.Equal(t, expected, pb.Filename())
}

func TestPackageBuildProvenanceFilename(t *testing.T) {
	pb := &PackageBuild{
		PackageName: "testpkg",
		OutDir:      "/output/aarch64",
		Origin: &config.Package{
			Version: "2.0.0",
			Epoch:   1,
		},
	}

	expected := "/output/aarch64/testpkg-2.0.0-r1.attest.tar.gz"
	require.Equal(t, expected, pb.ProvenanceFilename())
}

func TestPackageBuildSignatureName(t *testing.T) {
	tests := []struct {
		name       string
		signingKey string
		expected   string
	}{
		{
			name:       "simple key name",
			signingKey: "/keys/signing.rsa",
			expected:   ".SIGN.RSA.signing.rsa.pub",
		},
		{
			name:       "key with path",
			signingKey: "/var/lib/melange/keys/wolfi-signing.rsa",
			expected:   ".SIGN.RSA.wolfi-signing.rsa.pub",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pb := &PackageBuild{
				Build: &Build{
					SigningKey: tt.signingKey,
				},
			}
			require.Equal(t, tt.expected, pb.SignatureName())
		})
	}
}

func TestPackageBuildWorkspaceSubdir(t *testing.T) {
	pb := &PackageBuild{
		PackageName: "mypackage",
		Build: &Build{
			WorkspaceDir: "/workspace/build",
		},
	}

	expected := "/workspace/build/melange-out/mypackage"
	require.Equal(t, expected, pb.WorkspaceSubdir())
}

func TestPackageBuildWantSignature(t *testing.T) {
	t.Run("wants signature when key is set", func(t *testing.T) {
		pb := &PackageBuild{
			Build: &Build{
				SigningKey: "/keys/signing.rsa",
			},
		}
		require.True(t, pb.wantSignature())
	})

	t.Run("does not want signature when key is empty", func(t *testing.T) {
		pb := &PackageBuild{
			Build: &Build{
				SigningKey: "",
			},
		}
		require.False(t, pb.wantSignature())
	})
}

func TestRemoveSelfProvidedDeps_SoVerDeps(t *testing.T) {
	// Test so-ver: dependencies - the ">=" part gets stripped but so-ver: prefix remains
	// so-ver:libtest.so.1>=1.0.0 becomes so-ver:libtest.so.1
	// This will NOT match so:libtest.so.1 because the prefixes differ
	provides := []string{"so-ver:libtest.so.1=1.0.0"}
	depends := []string{"so-ver:libtest.so.1>=1.0.0", "so:libother.so.2"}

	final := removeSelfProvidedDeps(depends, provides)

	// so-ver:libtest.so.1>=1.0.0 becomes so-ver:libtest.so.1, which matches so-ver:libtest.so.1
	require.Len(t, final, 1)
	require.Equal(t, "so:libother.so.2", final[0])
}

func TestRemoveSelfProvidedDeps_MultipleProvides(t *testing.T) {
	provides := []string{"so:liba.so.1=1", "so:libb.so.2=2", "so:libc.so.3=3"}
	depends := []string{"so:liba.so.1", "so:libb.so.2", "so:libd.so.4"}

	final := removeSelfProvidedDeps(depends, provides)

	require.Len(t, final, 1)
	require.Equal(t, "so:libd.so.4", final[0])
}
