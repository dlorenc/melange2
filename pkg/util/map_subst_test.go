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

package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMutateStringFromMap(t *testing.T) {
	tests := []struct {
		name    string
		with    map[string]string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "simple substitution",
			with:  map[string]string{"name": "test-pkg"},
			input: "${{name}}",
			want:  "test-pkg",
		},
		{
			name:  "multiple substitutions",
			with:  map[string]string{"name": "foo", "version": "1.0.0"},
			input: "${{name}}-${{version}}",
			want:  "foo-1.0.0",
		},
		{
			name:  "no substitutions",
			with:  map[string]string{"name": "test"},
			input: "plain text",
			want:  "plain text",
		},
		{
			name:  "prefixed key lookup",
			with:  map[string]string{"${{package.name}}": "my-package"},
			input: "${{package.name}}",
			want:  "my-package",
		},
		{
			name:  "mixed content",
			with:  map[string]string{"dir": "/usr/bin"},
			input: "Installing to ${{dir}}/app",
			want:  "Installing to /usr/bin/app",
		},
		{
			name:    "undefined variable",
			with:    map[string]string{},
			input:   "${{undefined}}",
			wantErr: true,
		},
		{
			name:    "partially defined",
			with:    map[string]string{"name": "foo"},
			input:   "${{name}}-${{undefined}}",
			wantErr: true,
		},
		{
			name:  "empty map with no variables",
			with:  map[string]string{},
			input: "no variables here",
			want:  "no variables here",
		},
		{
			name:  "empty input",
			with:  map[string]string{"foo": "bar"},
			input: "",
			want:  "",
		},
		{
			name:  "special characters in value",
			with:  map[string]string{"path": "/home/user/my file.txt"},
			input: "File: ${{path}}",
			want:  "File: /home/user/my file.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MutateStringFromMap(tt.with, tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMutateAndQuoteStringFromMap(t *testing.T) {
	tests := []struct {
		name    string
		with    map[string]string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "simple substitution - not quoted without prefix",
			with:  map[string]string{"name": "test"},
			input: "${{name}}",
			want:  "test",
		},
		{
			name:  "prefixed key gets quoted",
			with:  map[string]string{"${{package.name}}": "my-package"},
			input: "${{package.name}}",
			want:  `"my-package"`,
		},
		{
			name:  "prefixed key with special chars gets escaped",
			with:  map[string]string{"${{path}}": `/home/user/"file".txt`},
			input: "${{path}}",
			want:  `"/home/user/\"file\".txt"`,
		},
		{
			name:  "no substitutions",
			with:  map[string]string{},
			input: "plain text",
			want:  "plain text",
		},
		{
			name:    "undefined variable",
			with:    map[string]string{},
			input:   "${{undefined}}",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MutateAndQuoteStringFromMap(tt.with, tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
