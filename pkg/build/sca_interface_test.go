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

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/pkg/config"
)

func TestSCABuildInterface_PackageName(t *testing.T) {
	scabi := &SCABuildInterface{
		PackageBuild: &PackageBuild{
			PackageName: "test-package",
		},
	}

	require.Equal(t, "test-package", scabi.PackageName())
}

func TestSCABuildInterface_RelativeNames(t *testing.T) {
	t.Run("main package only", func(t *testing.T) {
		scabi := &SCABuildInterface{
			PackageBuild: &PackageBuild{
				Origin: &config.Package{Name: "main-pkg"},
				Build: &Build{
					Configuration: &config.Configuration{
						Subpackages: []config.Subpackage{},
					},
				},
			},
		}

		names := scabi.RelativeNames()
		require.Len(t, names, 1)
		require.Contains(t, names, "main-pkg")
	})

	t.Run("main package with subpackages", func(t *testing.T) {
		scabi := &SCABuildInterface{
			PackageBuild: &PackageBuild{
				Origin: &config.Package{Name: "main-pkg"},
				Build: &Build{
					Configuration: &config.Configuration{
						Subpackages: []config.Subpackage{
							{Name: "sub1"},
							{Name: "sub2"},
							{Name: "sub3"},
						},
					},
				},
			},
		}

		names := scabi.RelativeNames()
		require.Len(t, names, 4)
		require.Contains(t, names, "main-pkg")
		require.Contains(t, names, "sub1")
		require.Contains(t, names, "sub2")
		require.Contains(t, names, "sub3")
	})
}

func TestSCABuildInterface_Version(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		epoch    uint64
		expected string
	}{
		{
			name:     "simple version",
			version:  "1.0.0",
			epoch:    0,
			expected: "1.0.0-r0",
		},
		{
			name:     "version with epoch",
			version:  "2.3.4",
			epoch:    5,
			expected: "2.3.4-r5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scabi := &SCABuildInterface{
				PackageBuild: &PackageBuild{
					Origin: &config.Package{
						Version: tt.version,
						Epoch:   tt.epoch,
					},
				},
			}
			require.Equal(t, tt.expected, scabi.Version())
		})
	}
}

func TestSCABuildInterface_Options(t *testing.T) {
	t.Run("returns empty options when nil", func(t *testing.T) {
		scabi := &SCABuildInterface{
			PackageBuild: &PackageBuild{
				Options: nil,
			},
		}

		opts := scabi.Options()
		require.False(t, opts.NoProvides)
		require.False(t, opts.NoDepends)
	})

	t.Run("returns configured options", func(t *testing.T) {
		scabi := &SCABuildInterface{
			PackageBuild: &PackageBuild{
				Options: &config.PackageOption{
					NoProvides: true,
					NoDepends:  true,
				},
			},
		}

		opts := scabi.Options()
		require.True(t, opts.NoProvides)
		require.True(t, opts.NoDepends)
	})
}

func TestSCABuildInterface_BaseDependencies(t *testing.T) {
	scabi := &SCABuildInterface{
		PackageBuild: &PackageBuild{
			Dependencies: config.Dependencies{
				Runtime:  []string{"dep1", "dep2"},
				Provides: []string{"prov1"},
			},
		},
	}

	deps := scabi.BaseDependencies()
	require.Equal(t, []string{"dep1", "dep2"}, deps.Runtime)
	require.Equal(t, []string{"prov1"}, deps.Provides)
}

func TestSCABuildInterface_InstalledPackages(t *testing.T) {
	scabi := &SCABuildInterface{
		PackageBuild: &PackageBuild{
			Origin: &config.Package{Name: "main-pkg"},
			Build: &Build{
				Configuration: &config.Configuration{
					Environment: apko_types.ImageConfiguration{
						Contents: apko_types.ImageContents{
							Packages: []string{"pkg1=1.0.0", "pkg2=2.0.0", "pkg3"},
						},
					},
					Subpackages: []config.Subpackage{
						{Name: "sub1"},
					},
				},
			},
		},
	}

	installed := scabi.InstalledPackages()

	// Check environment packages
	require.Equal(t, "1.0.0", installed["pkg1"])
	require.Equal(t, "2.0.0", installed["pkg2"])
	require.Equal(t, "", installed["pkg3"]) // No version specified

	// Check that packages being built get @CURRENT@
	require.Equal(t, "@CURRENT@", installed["main-pkg"])
	require.Equal(t, "@CURRENT@", installed["sub1"])
}

func TestSCABuildInterface_PkgResolver(t *testing.T) {
	t.Run("returns nil when not set", func(t *testing.T) {
		scabi := &SCABuildInterface{
			PackageBuild: &PackageBuild{
				Build: &Build{
					PkgResolver: nil,
				},
			},
		}

		require.Nil(t, scabi.PkgResolver())
	})
}
