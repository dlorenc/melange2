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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/stretchr/testify/require"
)

// createTestLayer creates a v1.Layer with the specified files for testing.
func createTestLayer(t *testing.T, files map[string][]byte) v1.Layer {
	t.Helper()

	// Create a tar.gz buffer
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	for name, content := range files {
		// Create parent directories
		dir := filepath.Dir(name)
		if dir != "." && dir != "/" {
			if err := tw.WriteHeader(&tar.Header{
				Name:     dir + "/",
				Mode:     0755,
				Typeflag: tar.TypeDir,
			}); err != nil {
				t.Fatalf("writing dir header: %v", err)
			}
		}

		// Write the file
		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(content)),
		}); err != nil {
			t.Fatalf("writing file header: %v", err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("writing file content: %v", err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("closing tar writer: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("closing gzip writer: %v", err)
	}

	// Write to a temp file for tarball.LayerFromFile
	tmpFile := filepath.Join(t.TempDir(), "layer.tar.gz")
	if err := os.WriteFile(tmpFile, buf.Bytes(), 0644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	layer, err := tarball.LayerFromFile(tmpFile)
	if err != nil {
		t.Fatalf("creating layer: %v", err)
	}

	return layer
}

func TestImageLoaderLoadLayer(t *testing.T) {
	loader := NewImageLoader("")

	layer := createTestLayer(t, map[string][]byte{
		"etc/test-file":     []byte("test content\n"),
		"usr/bin/hello":     []byte("#!/bin/sh\necho hello\n"),
		"home/build/.empty": []byte(""),
	})

	result, err := loader.LoadLayer(context.Background(), layer, "test")
	require.NoError(t, err)
	defer result.Cleanup()

	// Verify extraction
	content, err := os.ReadFile(filepath.Join(result.ExtractDir, "etc", "test-file"))
	require.NoError(t, err)
	require.Equal(t, "test content\n", string(content))

	// Verify the LLB state is valid
	def, err := result.State.Marshal(context.Background(), llb.LinuxAmd64)
	require.NoError(t, err)
	require.NotEmpty(t, def.Def)

	// Verify LocalName is set
	require.Equal(t, "apko-test", result.LocalName)
}

func TestImageLoaderWithCustomDir(t *testing.T) {
	customDir := t.TempDir()
	loader := NewImageLoader(customDir)

	layer := createTestLayer(t, map[string][]byte{
		"test.txt": []byte("content"),
	})

	result, err := loader.LoadLayer(context.Background(), layer, "custom")
	require.NoError(t, err)
	defer result.Cleanup()

	// Should be in custom directory
	require.True(t, strings.HasPrefix(result.ExtractDir, customDir))
}

func TestImageLoaderCleanup(t *testing.T) {
	loader := NewImageLoader("")

	layer := createTestLayer(t, map[string][]byte{
		"test.txt": []byte("content"),
	})

	result, err := loader.LoadLayer(context.Background(), layer, "cleanup-test")
	require.NoError(t, err)

	// Directory should exist
	_, err = os.Stat(result.ExtractDir)
	require.NoError(t, err)

	// Cleanup should remove it
	require.NoError(t, result.Cleanup())
	_, err = os.Stat(result.ExtractDir)
	require.True(t, os.IsNotExist(err))
}

func TestImageLoaderSymlinks(t *testing.T) {
	// Create a layer with a symlink manually
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	// Add a regular file
	content := []byte("target content")
	tw.WriteHeader(&tar.Header{
		Name: "target.txt",
		Mode: 0644,
		Size: int64(len(content)),
	})
	tw.Write(content)

	// Add a symlink to it
	tw.WriteHeader(&tar.Header{
		Name:     "link.txt",
		Mode:     0777,
		Typeflag: tar.TypeSymlink,
		Linkname: "target.txt",
	})

	tw.Close()
	gz.Close()

	// Write to file
	tmpFile := filepath.Join(t.TempDir(), "layer.tar.gz")
	os.WriteFile(tmpFile, buf.Bytes(), 0644)

	layer, err := tarball.LayerFromFile(tmpFile)
	require.NoError(t, err)

	loader := NewImageLoader("")
	result, err := loader.LoadLayer(context.Background(), layer, "symlink-test")
	require.NoError(t, err)
	defer result.Cleanup()

	// Verify symlink exists and points correctly
	linkPath := filepath.Join(result.ExtractDir, "link.txt")
	target, err := os.Readlink(linkPath)
	require.NoError(t, err)
	require.Equal(t, "target.txt", target)

	// Reading through the symlink should work
	content2, err := os.ReadFile(linkPath)
	require.NoError(t, err)
	require.Equal(t, "target content", string(content2))
}

func TestImageLoaderIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	bk := startBuildKitContainer(t, ctx)

	c, err := client.New(ctx, bk.Addr)
	require.NoError(t, err)
	defer c.Close()

	// Create a test layer with a shell script
	layer := createTestLayer(t, map[string][]byte{
		"etc/test-config": []byte("config=value\n"),
	})

	loader := NewImageLoader("")
	result, err := loader.LoadLayer(ctx, layer, "integration")
	require.NoError(t, err)
	defer result.Cleanup()

	// Use alpine as base (for /bin/sh) and overlay our files
	state := llb.Image(TestBaseImage).File(
		llb.Copy(llb.Local(result.LocalName), "/etc/test-config", "/etc/test-config"),
	)

	// Run a command that reads our file
	state = state.Run(
		llb.Args([]string{"/bin/sh", "-c", "cat /etc/test-config"}),
	).Root()

	def, err := state.Marshal(ctx, llb.LinuxAmd64)
	require.NoError(t, err)

	_, err = c.Solve(ctx, def, client.SolveOpt{
		LocalDirs: map[string]string{
			result.LocalName: result.ExtractDir,
		},
	}, nil)
	require.NoError(t, err)
}

func TestIsValidPath(t *testing.T) {
	tests := []struct {
		name     string
		destDir  string
		target   string
		tarName  string
		expected bool
	}{
		{"normal path", "/dest", "/dest/foo/bar", "foo/bar", true},
		{"root file", "/dest", "/dest/file.txt", "file.txt", true},
		{"absolute in tar", "/dest", "/dest/etc/passwd", "/etc/passwd", false},
		{"path traversal", "/dest", "/dest/../etc/passwd", "../etc/passwd", false},
		{"hidden traversal", "/dest", "/dest/foo/../../etc", "foo/../../etc", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidPath(tt.destDir, tt.target, tt.tarName)
			require.Equal(t, tt.expected, result)
		})
	}
}

// Ensure the LoadResult state can be used in a real build
func TestLoadResultUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	bk := startBuildKitContainer(t, ctx)

	c, err := client.New(ctx, bk.Addr)
	require.NoError(t, err)
	defer c.Close()

	// Create layer with build artifacts
	layer := createTestLayer(t, map[string][]byte{
		"home/build/source.c": []byte("int main() { return 0; }\n"),
	})

	loader := NewImageLoader("")
	result, err := loader.LoadLayer(ctx, layer, "build-test")
	require.NoError(t, err)
	defer result.Cleanup()

	// Use alpine and copy in our source file
	state := llb.Image(TestBaseImage).File(
		llb.Mkdir("/home/build", 0755, llb.WithParents(true)),
	).File(
		llb.Copy(llb.Local(result.LocalName), "/home/build/source.c", "/home/build/source.c"),
	)

	// Verify file exists
	state = state.Run(
		llb.Args([]string{"/bin/sh", "-c", "cat /home/build/source.c"}),
	).Root()

	def, err := state.Marshal(ctx, llb.LinuxAmd64)
	require.NoError(t, err)

	_, err = c.Solve(ctx, def, client.SolveOpt{
		LocalDirs: map[string]string{
			result.LocalName: result.ExtractDir,
		},
	}, nil)
	require.NoError(t, err)
}
