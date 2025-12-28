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

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/stretchr/testify/require"
)

func TestBuildExportEntriesTarball(t *testing.T) {
	cfg := &ExportConfig{
		Type: ExportTypeTarball,
		Ref:  "/tmp/debug.tar",
		Arch: apko_types.ParseArchitecture("amd64"),
	}

	entries, err := buildExportEntries(cfg)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "oci", entries[0].Type)
	require.NotNil(t, entries[0].Output)
}

func TestBuildExportEntriesDocker(t *testing.T) {
	cfg := &ExportConfig{
		Type: ExportTypeDocker,
		Ref:  "debug:failed-build",
		Arch: apko_types.ParseArchitecture("amd64"),
	}

	entries, err := buildExportEntries(cfg)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "docker", entries[0].Type)
	require.Equal(t, "debug:failed-build", entries[0].Attrs["name"])
}

func TestBuildExportEntriesRegistry(t *testing.T) {
	cfg := &ExportConfig{
		Type: ExportTypeRegistry,
		Ref:  "registry.example.com/debug:latest",
		Arch: apko_types.ParseArchitecture("amd64"),
	}

	entries, err := buildExportEntries(cfg)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "image", entries[0].Type)
	require.Equal(t, "registry.example.com/debug:latest", entries[0].Attrs["name"])
	require.Equal(t, "true", entries[0].Attrs["push"])
}

func TestBuildExportEntriesUnknownType(t *testing.T) {
	cfg := &ExportConfig{
		Type: ExportType("invalid"),
		Ref:  "test",
		Arch: apko_types.ParseArchitecture("amd64"),
	}

	entries, err := buildExportEntries(cfg)
	require.Error(t, err)
	require.Nil(t, entries)
	require.Contains(t, err.Error(), "unknown export type")
}

func TestExportTypeConstants(t *testing.T) {
	require.Equal(t, ExportType(""), ExportTypeNone)
	require.Equal(t, ExportType("tarball"), ExportTypeTarball)
	require.Equal(t, ExportType("docker"), ExportTypeDocker)
	require.Equal(t, ExportType("registry"), ExportTypeRegistry)
}
