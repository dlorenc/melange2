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
	"fmt"
	"path/filepath"
	"testing"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/pkg/config"
)

const (
	buildUser = "build"
)

var gid1000 = uint32(1000)

func defaultEnv(opts ...func(*apko_types.ImageConfiguration)) apko_types.ImageConfiguration {
	env := apko_types.ImageConfiguration{
		Accounts: apko_types.ImageAccounts{
			Groups: []apko_types.Group{{GroupName: "build", GID: 1000, Members: []string{buildUser}}},
			Users:  []apko_types.User{{UserName: "build", UID: 1000, GID: apko_types.GID(&gid1000)}},
		},
	}

	for _, opt := range opts {
		opt(&env)
	}

	return env
}

// TestConfigurationLoad is the main set of tests for loading a configuration
// file for tests. When in doubt, add your test here.
func TestConfigurationLoad(t *testing.T) {
	tests := []struct {
		name                string
		skipConfigCleanStep bool
		requireErr          require.ErrorAssertionFunc
		expected            *config.Configuration
	}{
		{
			name:       "range-subpackages",
			requireErr: require.NoError,
			expected: &config.Configuration{
				Package: config.Package{
					Name:      "hello",
					Version:   "world",
					Resources: &config.Resources{},
				},
				Test: &config.Test{
					Environment: defaultEnv(),
					Pipeline: []config.Pipeline{
						{
							Name: "hello",
							Runs: "world",
						},
					},
				},
				Subpackages: []config.Subpackage{{
					Name: "cats",
					Test: &config.Test{
						Environment: defaultEnv(),
						Pipeline: []config.Pipeline{{
							Runs: "cats are angry",
						}},
					},
				}, {
					Name: "dogs",
					Test: &config.Test{
						Environment: defaultEnv(),
						Pipeline: []config.Pipeline{{
							Runs: "dogs are loyal",
						}},
					},
				}, {
					Name: "turtles",
					Test: &config.Test{
						Environment: defaultEnv(),
						Pipeline: []config.Pipeline{{
							Runs: "turtles are slow",
						}},
					},
				}, {
					Name: "donatello",
					Test: &config.Test{
						Environment: defaultEnv(),
						Pipeline: []config.Pipeline{
							{
								Runs: "donatello's color is purple",
							},
							{
								Uses: "go/build",
								With: map[string]string{"packages": "purple"},
							},
						},
					},
				}, {
					Name: "leonardo",
					Test: &config.Test{
						Environment: defaultEnv(),
						Pipeline: []config.Pipeline{
							{
								Runs: "leonardo's color is blue",
							},
							{
								Uses: "go/build",
								With: map[string]string{"packages": "blue"},
							},
						},
					},
				}, {
					Name: "michelangelo",
					Test: &config.Test{
						Environment: defaultEnv(),
						Pipeline: []config.Pipeline{
							{
								Runs: "michelangelo's color is orange",
							},
							{
								Uses: "go/build",
								With: map[string]string{"packages": "orange"},
							},
						},
					},
				}, {
					Name: "raphael",
					Test: &config.Test{
						Environment: defaultEnv(),
						Pipeline: []config.Pipeline{
							{
								Runs: "raphael's color is red",
							},
							{
								Uses: "go/build",
								With: map[string]string{"packages": "red"},
							},
						},
					},
				}, {
					Name: "simple",
					Test: &config.Test{
						Environment: defaultEnv(),
						Pipeline: []config.Pipeline{
							{
								Runs: "simple-runs",
							}, {
								Uses: "simple-uses",
							},
						},
					},
				}},
			},
		}, {
			name:       "py3-pandas",
			requireErr: require.NoError,
			expected: &config.Configuration{
				Package: config.Package{
					Name:      "py3-pandas",
					Version:   "2.1.3",
					Resources: &config.Resources{},
				},
				Test: &config.Test{
					Environment: defaultEnv(func(env *apko_types.ImageConfiguration) {
						env.Contents.Packages = []string{"busybox", "python-3"}
					}),
					Pipeline: []config.Pipeline{
						{
							Runs: "python3 ./py3-pandas-test.py\n",
						}, {
							Uses: "test-uses",
							With: map[string]string{"test-with": "test-with-value"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := slogtest.Context(t)
			configFile := filepath.Join("testdata", "test_configuration_load", fmt.Sprintf("%s.melange.yaml", tt.name))

			cfg, err := config.ParseConfiguration(ctx, configFile)
			tt.requireErr(t, err)

			if !tt.skipConfigCleanStep {
				cleanTestConfig(cfg)
			}

			if tt.expected == nil {
				if cfg != nil {
					t.Fatalf("actual didn't match expected (want nil, got config)")
				}
			} else {
				if d := cmp.Diff(
					*tt.expected,
					*cfg,
					cmpopts.IgnoreUnexported(config.Pipeline{}, config.Configuration{}),
				); d != "" {
					t.Fatalf("actual didn't match expected (-want, +got): %s", d)
				}
			}
		})
	}
}
