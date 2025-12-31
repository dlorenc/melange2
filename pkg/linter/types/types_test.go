// Copyright 2025 Chainguard, Inc.
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

package types

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStructuredError(t *testing.T) {
	t.Run("Error returns message", func(t *testing.T) {
		err := &StructuredError{
			Message: "test error message",
			Details: nil,
		}
		assert.Equal(t, "test error message", err.Error())
	})

	t.Run("with details", func(t *testing.T) {
		details := &DuplicateFilesDetails{
			TotalDuplicateSets: 5,
			TotalWastedBytes:   1024,
		}
		err := &StructuredError{
			Message: "duplicate files found",
			Details: details,
		}
		assert.Equal(t, "duplicate files found", err.Error())
		assert.Equal(t, details, err.Details)
	})
}

func TestNewStructuredError(t *testing.T) {
	t.Run("creates error with message and details", func(t *testing.T) {
		details := map[string]string{"key": "value"}
		err := NewStructuredError("error message", details)

		require.NotNil(t, err)
		assert.Equal(t, "error message", err.Error())

		var structErr *StructuredError
		require.True(t, errors.As(err, &structErr))
		assert.Equal(t, details, structErr.Details)
	})

	t.Run("creates error with nil details", func(t *testing.T) {
		err := NewStructuredError("simple error", nil)

		require.NotNil(t, err)
		assert.Equal(t, "simple error", err.Error())
	})
}

func TestDuplicateFileInfo(t *testing.T) {
	info := &DuplicateFileInfo{
		Basename:    "libfoo.so",
		Count:       3,
		SizeBytes:   4096,
		Size:        "4.0 KB",
		WastedBytes: 8192,
		WastedSize:  "8.0 KB",
		Paths:       []string{"/usr/lib/libfoo.so", "/usr/lib64/libfoo.so", "/lib/libfoo.so"},
	}

	// Test JSON marshaling
	data, err := json.Marshal(info)
	require.NoError(t, err)

	var decoded DuplicateFileInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, info.Basename, decoded.Basename)
	assert.Equal(t, info.Count, decoded.Count)
	assert.Equal(t, info.SizeBytes, decoded.SizeBytes)
	assert.Equal(t, info.Paths, decoded.Paths)
}

func TestDuplicateFilesDetails(t *testing.T) {
	details := &DuplicateFilesDetails{
		TotalDuplicateSets: 2,
		TotalWastedBytes:   10240,
		TotalWastedSize:    "10 KB",
		Duplicates: []*DuplicateFileInfo{
			{Basename: "file1.txt", Count: 2},
			{Basename: "file2.txt", Count: 3},
		},
	}

	data, err := json.Marshal(details)
	require.NoError(t, err)

	var decoded DuplicateFilesDetails
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, 2, decoded.TotalDuplicateSets)
	assert.Len(t, decoded.Duplicates, 2)
}

func TestFilePermissionInfo(t *testing.T) {
	info := FilePermissionInfo{
		Path:        "/usr/bin/su",
		Mode:        "4755",
		Permissions: []string{"setuid"},
	}

	data, err := json.Marshal(info)
	require.NoError(t, err)

	var decoded FilePermissionInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "/usr/bin/su", decoded.Path)
	assert.Equal(t, "4755", decoded.Mode)
	assert.Equal(t, []string{"setuid"}, decoded.Permissions)
}

func TestSpecialPermissionsDetails(t *testing.T) {
	details := SpecialPermissionsDetails{
		Files: []FilePermissionInfo{
			{Path: "/usr/bin/sudo", Mode: "4755", Permissions: []string{"setuid"}},
			{Path: "/usr/bin/crontab", Mode: "2755", Permissions: []string{"setgid"}},
		},
	}

	data, err := json.Marshal(details)
	require.NoError(t, err)

	var decoded SpecialPermissionsDetails
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Len(t, decoded.Files, 2)
}

func TestBinaryArchInfo(t *testing.T) {
	info := BinaryArchInfo{
		Path: "/usr/bin/app",
		Arch: "x86_64",
	}

	data, err := json.Marshal(info)
	require.NoError(t, err)

	var decoded BinaryArchInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "/usr/bin/app", decoded.Path)
	assert.Equal(t, "x86_64", decoded.Arch)
}

func TestPathListDetails(t *testing.T) {
	details := PathListDetails{
		Paths: []string{"/path/one", "/path/two", "/path/three"},
	}

	data, err := json.Marshal(details)
	require.NoError(t, err)

	var decoded PathListDetails
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Len(t, decoded.Paths, 3)
}

func TestLinterFinding(t *testing.T) {
	finding := &LinterFinding{
		Message: "found issue",
		Explain: "this is why it's bad",
		Details: &PathListDetails{Paths: []string{"/bad/path"}},
	}

	data, err := json.Marshal(finding)
	require.NoError(t, err)

	var decoded LinterFinding
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "found issue", decoded.Message)
	assert.Equal(t, "this is why it's bad", decoded.Explain)
}

func TestPackageLintResults(t *testing.T) {
	results := &PackageLintResults{
		PackageName: "my-package",
		Findings: map[string][]*LinterFinding{
			"duplicate-files": {
				{Message: "duplicate found"},
			},
			"setuid": {
				{Message: "setuid binary"},
				{Message: "another setuid"},
			},
		},
	}

	data, err := json.Marshal(results)
	require.NoError(t, err)

	var decoded PackageLintResults
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "my-package", decoded.PackageName)
	assert.Len(t, decoded.Findings["duplicate-files"], 1)
	assert.Len(t, decoded.Findings["setuid"], 2)
}

func TestNonLinuxDetails(t *testing.T) {
	details := NonLinuxDetails{
		References: []NonLinuxReference{
			{Path: "/usr/lib/darwin.dylib", Platform: "macos"},
			{Path: "/usr/lib/windows.dll", Platform: "windows"},
		},
	}

	data, err := json.Marshal(details)
	require.NoError(t, err)

	var decoded NonLinuxDetails
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Len(t, decoded.References, 2)
	assert.Equal(t, "macos", decoded.References[0].Platform)
}

func TestPythonMultipleDetails(t *testing.T) {
	details := PythonMultipleDetails{
		Count:    3,
		Packages: []string{"pkg1", "pkg2", "pkg3"},
	}

	data, err := json.Marshal(details)
	require.NoError(t, err)

	var decoded PythonMultipleDetails
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, 3, decoded.Count)
	assert.Len(t, decoded.Packages, 3)
}

func TestUnstrippedBinaryDetails(t *testing.T) {
	details := UnstrippedBinaryDetails{
		Binaries: []string{"/usr/bin/app1", "/usr/bin/app2"},
	}

	data, err := json.Marshal(details)
	require.NoError(t, err)

	var decoded UnstrippedBinaryDetails
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Len(t, decoded.Binaries, 2)
}
