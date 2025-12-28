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
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestBuildKitConnection verifies we can connect to BuildKit via testcontainers.
// This is the foundational test for the entire BuildKit integration.
func TestBuildKitConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	bk := startBuildKitContainer(t, ctx)

	// Connect to BuildKit
	c, err := client.New(ctx, bk.Addr)
	require.NoError(t, err, "should connect to BuildKit")
	defer c.Close()

	// Verify connection by listing workers
	workers, err := c.ListWorkers(ctx)
	require.NoError(t, err, "should list workers")
	require.NotEmpty(t, workers, "should have at least one worker")

	t.Logf("Connected to BuildKit with %d workers", len(workers))
}

// TestSimpleLLBExecution verifies we can build and execute a simple LLB graph.
func TestSimpleLLBExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	bk := startBuildKitContainer(t, ctx)

	c, err := client.New(ctx, bk.Addr)
	require.NoError(t, err)
	defer c.Close()

	// Build a simple LLB: alpine + echo hello
	state := llb.Image(TestBaseImage).
		Run(llb.Args([]string{"/bin/sh", "-c", "echo hello-from-buildkit"})).
		Root()

	def, err := state.Marshal(ctx, llb.LinuxAmd64)
	require.NoError(t, err, "should marshal LLB")

	// Solve (execute) the LLB
	_, err = c.Solve(ctx, def, client.SolveOpt{}, nil)
	require.NoError(t, err, "should solve LLB")

	t.Log("Successfully executed simple LLB")
}

// TestLocalFilesystemAsImage tests loading a local filesystem (extracted tar)
// as the base for BuildKit operations. This simulates what we need for apko images.
//
// KEY APPROACH: Use alpine as base (which is what apko produces - a full rootfs),
// then overlay local files via llb.Local() + Copy
func TestLocalFilesystemAsImage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	bk := startBuildKitContainer(t, ctx)

	c, err := client.New(ctx, bk.Addr)
	require.NoError(t, err)
	defer c.Close()

	// Create a tar.gz layer similar to what apko produces
	tarGzPath := filepath.Join(t.TempDir(), "layer.tar.gz")
	require.NoError(t, createMinimalTarGzLayer(tarGzPath))

	// Extract the tar to a directory (simulating what we'd do with v1.Layer)
	extractDir := t.TempDir()
	require.NoError(t, extractTarGz(tarGzPath, extractDir))

	// Verify extraction worked
	content, err := os.ReadFile(filepath.Join(extractDir, "etc", "test-file"))
	require.NoError(t, err)
	require.Contains(t, string(content), "test-content")

	// KEY INSIGHT: For apko, the layer IS a complete rootfs with /bin/sh.
	// For this test, we simulate by starting with alpine (which has /bin/sh)
	// and overlaying our local files on top.
	//
	// In the real implementation:
	// 1. Apko builds a complete rootfs with busybox/shell
	// 2. We extract it to a temp directory
	// 3. We use llb.Local() to load it into BuildKit
	// 4. We copy it to scratch to create the base image

	// Use llb.Local to reference the local filesystem
	localName := "apko-rootfs"
	local := llb.Local(localName)

	// Start with alpine (simulates apko rootfs which has /bin/sh)
	// Then overlay our test file from the extracted tar
	state := llb.Image(TestBaseImage).File(
		llb.Copy(local, "/etc/test-file", "/etc/test-file"),
	)

	// Now run a command to verify the file was copied
	state = state.Run(
		llb.Args([]string{"/bin/sh", "-c", "cat /etc/test-file"}),
		llb.Dir("/"),
	).Root()

	def, err := state.Marshal(ctx, llb.LinuxAmd64)
	require.NoError(t, err)

	// Solve with the local mount provided
	_, err = c.Solve(ctx, def, client.SolveOpt{
		LocalDirs: map[string]string{
			localName: extractDir,
		},
	}, nil)
	require.NoError(t, err, "should execute command with local filesystem overlay")

	t.Log("Successfully overlaid local files onto base image - THIS IS THE APPROACH FOR APKO")
}

// TestWorkspaceExport tests exporting build results back to the host filesystem.
// This is crucial for melange since we need to get the built packages out.
func TestWorkspaceExport(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	bk := startBuildKitContainer(t, ctx)

	c, err := client.New(ctx, bk.Addr)
	require.NoError(t, err)
	defer c.Close()

	// Build something that creates output files
	state := llb.Image(TestBaseImage).
		Run(llb.Args([]string{"/bin/sh", "-c", "mkdir -p /output && echo 'built content' > /output/result.txt"})).
		Root()

	// Extract just the output directory
	outputState := llb.Scratch().File(
		llb.Copy(state, "/output", "/", &llb.CopyInfo{
			CopyDirContentsOnly: true,
		}),
	)

	def, err := outputState.Marshal(ctx, llb.LinuxAmd64)
	require.NoError(t, err)

	// Export to local directory
	exportDir := t.TempDir()
	_, err = c.Solve(ctx, def, client.SolveOpt{
		Exports: []client.ExportEntry{{
			Type:      client.ExporterLocal,
			OutputDir: exportDir,
		}},
	}, nil)
	require.NoError(t, err)

	// List what was exported for debugging
	entries, _ := os.ReadDir(exportDir)
	t.Logf("Exported %d entries to %s", len(entries), exportDir)
	for _, e := range entries {
		t.Logf("  - %s", e.Name())
	}

	// Verify the exported file exists
	content, err := os.ReadFile(filepath.Join(exportDir, "result.txt"))
	require.NoError(t, err, "result.txt should exist in export dir")
	require.Contains(t, string(content), "built content")

	t.Log("Successfully exported workspace to host - THIS IS HOW WE GET APKs OUT")
}

// TestDeterministicLLB verifies that the same inputs produce the same LLB digest.
// This is critical for reproducible builds.
func TestDeterministicLLB(t *testing.T) {
	ctx := context.Background()

	// Build the same LLB graph multiple times with unsorted env vars
	env := map[string]string{
		"VAR_Z": "z-value",
		"VAR_A": "a-value",
		"VAR_M": "m-value",
	}

	buildLLB := func() (string, error) {
		state := llb.Image(TestBaseImage)

		// CRITICAL: Sort env vars for determinism
		// Go map iteration is random, so we must sort keys
		keys := make([]string, 0, len(env))
		for k := range env {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		runOpts := []llb.RunOption{
			llb.Args([]string{"/bin/sh", "-c", "echo hello"}),
		}
		for _, k := range keys {
			runOpts = append(runOpts, llb.AddEnv(k, env[k]))
		}

		state = state.Run(runOpts...).Root()

		def, err := state.Marshal(ctx, llb.LinuxAmd64)
		if err != nil {
			return "", err
		}

		dgst, err := def.Head()
		if err != nil {
			return "", err
		}
		return dgst.String(), nil
	}

	// Build 100 times and verify all digests match
	var digests []string
	for i := 0; i < 100; i++ {
		d, err := buildLLB()
		require.NoError(t, err)
		digests = append(digests, d)
	}

	for i := 1; i < len(digests); i++ {
		require.Equal(t, digests[0], digests[i], "LLB digest should be deterministic (iteration %d)", i)
	}

	t.Logf("LLB is deterministic across 100 iterations: %s", digests[0][:16]+"...")
}

// TestPipelineSimulation simulates running a melange pipeline in BuildKit.
// This is a more complete test of the pattern we'll use.
func TestPipelineSimulation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	bk := startBuildKitContainer(t, ctx)

	c, err := client.New(ctx, bk.Addr)
	require.NoError(t, err)
	defer c.Close()

	// Start with alpine (simulating apko-built image)
	state := llb.Image(TestBaseImage)

	// Simulate workspace mount via Local
	workspaceDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(workspaceDir, "source.txt"), []byte("source content\n"), 0644))

	localWorkspace := llb.Local("workspace")

	// Copy workspace into container
	state = state.File(
		llb.Mkdir("/home/build", 0755, llb.WithParents(true)),
	).File(
		llb.Copy(localWorkspace, "/", "/home/build/"),
	)

	// Create output directory
	state = state.File(
		llb.Mkdir("/home/build/melange-out/test-pkg", 0755, llb.WithParents(true)),
	)

	// Run pipeline step 1: process source
	state = state.Run(
		llb.Args([]string{"/bin/sh", "-c", `
set -e
cd /home/build
cat source.txt
echo "processed" > melange-out/test-pkg/output.txt
`}),
		llb.Dir("/home/build"),
		llb.AddEnv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
	).Root()

	// Run pipeline step 2: verify
	state = state.Run(
		llb.Args([]string{"/bin/sh", "-c", "cat /home/build/melange-out/test-pkg/output.txt"}),
		llb.Dir("/home/build"),
	).Root()

	// Export the melange-out directory
	outputState := llb.Scratch().File(
		llb.Copy(state, "/home/build/melange-out", "/", &llb.CopyInfo{
			CopyDirContentsOnly: true,
		}),
	)

	def, err := outputState.Marshal(ctx, llb.LinuxAmd64)
	require.NoError(t, err)

	exportDir := t.TempDir()
	_, err = c.Solve(ctx, def, client.SolveOpt{
		LocalDirs: map[string]string{
			"workspace": workspaceDir,
		},
		Exports: []client.ExportEntry{{
			Type:      client.ExporterLocal,
			OutputDir: exportDir,
		}},
	}, nil)
	require.NoError(t, err)

	// List what was exported for debugging
	entries, _ := os.ReadDir(exportDir)
	t.Logf("Exported %d entries to %s", len(entries), exportDir)
	for _, e := range entries {
		t.Logf("  - %s", e.Name())
	}

	// Verify output
	content, err := os.ReadFile(filepath.Join(exportDir, "test-pkg", "output.txt"))
	require.NoError(t, err)
	require.Contains(t, string(content), "processed")

	t.Log("Successfully simulated melange pipeline execution")
}

// Helper: Start BuildKit container using testcontainers
type buildKitContainer struct {
	container testcontainers.Container
	Addr      string
}

func startBuildKitContainer(t *testing.T, ctx context.Context) *buildKitContainer {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "moby/buildkit:latest",
		ExposedPorts: []string{"1234/tcp"},
		Privileged:   true,
		Cmd:          []string{"--addr", "tcp://0.0.0.0:1234"},
		WaitingFor:   wait.ForLog("running server").WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "should start BuildKit container")

	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate BuildKit container: %v", err)
		}
	})

	host, err := container.Host(ctx)
	require.NoError(t, err)

	port, err := container.MappedPort(ctx, "1234")
	require.NoError(t, err)

	addr := fmt.Sprintf("tcp://%s:%s", host, port.Port())
	t.Logf("BuildKit running at %s", addr)

	return &buildKitContainer{
		container: container,
		Addr:      addr,
	}
}

// Helper: Create a minimal tar.gz layer (simulating apko output)
func createMinimalTarGzLayer(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()

	tw := tar.NewWriter(gz)
	defer tw.Close()

	// Create directories
	dirs := []struct {
		name string
		mode int64
	}{
		{"bin/", 0755},
		{"etc/", 0755},
		{"home/", 0755},
		{"home/build/", 0755},
	}

	for _, d := range dirs {
		if err := tw.WriteHeader(&tar.Header{
			Name:     d.name,
			Mode:     d.mode,
			Typeflag: tar.TypeDir,
		}); err != nil {
			return err
		}
	}

	// Create test file
	content := []byte("test-content-tar\n")
	if err := tw.WriteHeader(&tar.Header{
		Name: "etc/test-file",
		Mode: 0644,
		Size: int64(len(content)),
	}); err != nil {
		return err
	}
	if _, err := tw.Write(content); err != nil {
		return err
	}

	return nil
}

// Helper: Extract tar.gz to directory
func extractTarGz(tarGzPath, destDir string) error {
	f, err := os.Open(tarGzPath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(destDir, hdr.Name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			outFile, err := os.Create(target)
			if err != nil {
				return err
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()
			if err := os.Chmod(target, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
		}
	}

	return nil
}
