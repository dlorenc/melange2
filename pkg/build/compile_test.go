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
	"context"
	"testing"

	"github.com/dlorenc/melange2/pkg/config"
)

func TestCompileEmpty(t *testing.T) {
	build := &Build{
		Configuration: &config.Configuration{
			Subpackages: []config.Subpackage{{}},
		},
	}

	if err := build.Compile(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInheritWorkdir(t *testing.T) {
	build := &Build{
		Configuration: &config.Configuration{
			Pipeline: []config.Pipeline{{
				WorkDir: "/work",
				Pipeline: []config.Pipeline{{}, {
					WorkDir: "/do-not-inherit",
					Runs:    "#!/bin/bash\n# hunter2\necho $SECRET",
				}},
			}},
		},
	}

	if err := build.Compile(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := build.Configuration.Pipeline[0].Pipeline[0].WorkDir, "/work"; want != got {
		t.Fatalf("workdir[0]: want %q, got %q", want, got)
	}
	if got, want := build.Configuration.Pipeline[0].Pipeline[1].WorkDir, "/do-not-inherit"; want != got {
		t.Fatalf("workdir[1]: want %q, got %q", want, got)
	}
	if got, want := build.Configuration.Pipeline[0].Pipeline[1].Runs, "#!/bin/bash\necho $SECRET\n"; want != got {
		t.Fatalf("runs[1]: should strip comments, want %q, got %q", want, got)
	}
}


func TestIdentity(t *testing.T) {
	tests := []struct {
		name     string
		pipeline config.Pipeline
		want     string
	}{
		{
			name:     "empty pipeline returns ???",
			pipeline: config.Pipeline{},
			want:     "???",
		},
		{
			name:     "pipeline with name returns name",
			pipeline: config.Pipeline{Name: "my-pipeline"},
			want:     "my-pipeline",
		},
		{
			name:     "pipeline with uses returns uses",
			pipeline: config.Pipeline{Uses: "go/build"},
			want:     "go/build",
		},
		{
			name:     "name takes precedence over uses",
			pipeline: config.Pipeline{Name: "custom-name", Uses: "go/build"},
			want:     "custom-name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := identity(&tt.pipeline)
			if got != tt.want {
				t.Errorf("identity() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestShouldRun(t *testing.T) {
	tests := []struct {
		name    string
		ifs     string
		want    bool
		wantErr bool
	}{
		{
			name: "empty string returns true",
			ifs:  "",
			want: true,
		},
		{
			name: "equal comparison true",
			ifs:  `"a" == "a"`,
			want: true,
		},
		{
			name: "equal comparison false",
			ifs:  `"a" == "b"`,
			want: false,
		},
		{
			name: "not equal comparison true",
			ifs:  `"a" != "b"`,
			want: true,
		},
		{
			name: "not equal comparison false",
			ifs:  `"a" != "a"`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := shouldRun(tt.ifs)
			if (err != nil) != tt.wantErr {
				t.Errorf("shouldRun() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("shouldRun() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGatherDeps(t *testing.T) {
	ctx := context.Background()

	t.Run("gathers packages from needs", func(t *testing.T) {
		c := &Compiled{}
		pipeline := &config.Pipeline{
			Name: "test",
			Needs: &config.Needs{
				Packages: []string{"pkg1", "pkg2"},
			},
		}

		err := c.gatherDeps(ctx, pipeline)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(c.Needs) != 2 {
			t.Fatalf("expected 2 needs, got %d", len(c.Needs))
		}
		if c.Needs[0] != "pkg1" || c.Needs[1] != "pkg2" {
			t.Errorf("unexpected needs: %v", c.Needs)
		}
	})

	t.Run("skips pipeline with false if condition", func(t *testing.T) {
		c := &Compiled{}
		pipeline := &config.Pipeline{
			Name: "test",
			If:   `"skip" == "run"`, // evaluates to false
			Needs: &config.Needs{
				Packages: []string{"should-not-appear"},
			},
		}

		err := c.gatherDeps(ctx, pipeline)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(c.Needs) != 0 {
			t.Errorf("expected 0 needs for skipped pipeline, got %d", len(c.Needs))
		}
	})

	t.Run("clears needs after gathering", func(t *testing.T) {
		c := &Compiled{}
		pipeline := &config.Pipeline{
			Name: "test",
			Needs: &config.Needs{
				Packages: []string{"pkg1"},
			},
		}

		err := c.gatherDeps(ctx, pipeline)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if pipeline.Needs != nil {
			t.Error("expected pipeline.Needs to be nil after gathering")
		}
	})

	t.Run("recursively gathers from nested pipelines", func(t *testing.T) {
		c := &Compiled{}
		pipeline := &config.Pipeline{
			Name: "parent",
			Needs: &config.Needs{
				Packages: []string{"parent-pkg"},
			},
			Pipeline: []config.Pipeline{
				{
					Name: "child",
					Needs: &config.Needs{
						Packages: []string{"child-pkg"},
					},
				},
			},
		}

		err := c.gatherDeps(ctx, pipeline)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(c.Needs) != 2 {
			t.Fatalf("expected 2 needs, got %d: %v", len(c.Needs), c.Needs)
		}
	})
}

func Test_stripComments(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"# foo\n", ""},
		{"\n", ""},
		{"#!/bin/bash\n", "#!/bin/bash\n"},
		{"#!/bin/bash\n# foo\n", "#!/bin/bash\n"},
		{"#!/bin/bash\nfoo\n", "#!/bin/bash\nfoo\n"},
		{"#!/bin/bash\nfoo\n# bar\n", "#!/bin/bash\nfoo\n"},
		{"#!/bin/bash\nfoo\nbar\n", "#!/bin/bash\nfoo\nbar\n"},
		{"#!/bin/bash\nfoo\n# bar\nbaz\n", "#!/bin/bash\nfoo\nbaz\n"},
	}

	for _, test := range tests {
		t.Run(test.in, func(t *testing.T) {
			got, err := stripComments(test.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != test.want {
				t.Errorf("stripComments(%q): want %q, got %q", test.in, test.want, got)
			}
		})
	}

	wantErr := `1:13: not a valid test operator: -m:
> if [[ uname -m == 'x86_64']]; then
              ^`

	got, err := stripComments("if [[ uname -m == 'x86_64']]; then")
	if err == nil {
		t.Errorf("expected error, got %q", got)
	} else if err.Error() != wantErr {
		t.Errorf("want:\n%s\ngot:\n%s", wantErr, err)
	}
}
