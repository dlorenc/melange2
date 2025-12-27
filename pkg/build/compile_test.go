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
