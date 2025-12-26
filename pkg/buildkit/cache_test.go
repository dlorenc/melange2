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
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/pkg/config"
)

func TestDefaultCacheMounts(t *testing.T) {
	mounts := DefaultCacheMounts()

	// Verify we have all the expected cache mounts
	require.NotEmpty(t, mounts)

	expectedIDs := map[string]string{
		GoModCacheID:         "/go/pkg/mod",
		GoBuildCacheID:       "/root/.cache/go-build",
		PipCacheID:           "/root/.cache/pip",
		NpmCacheID:           "/root/.npm",
		CargoRegistryCacheID: "/root/.cargo/registry",
		CargoBuildCacheID:    "/root/.cargo/git",
		CcacheCacheID:        "/root/.ccache",
		ApkCacheID:           "/var/cache/apk",
	}

	// Create a map of ID to mount for easier lookup
	mountMap := make(map[string]CacheMount)
	for _, m := range mounts {
		mountMap[m.ID] = m
	}

	for id, expectedTarget := range expectedIDs {
		m, ok := mountMap[id]
		require.True(t, ok, "missing cache mount for %s", id)
		require.Equal(t, expectedTarget, m.Target, "wrong target for %s", id)
		require.Equal(t, llb.CacheMountShared, m.Mode, "wrong mode for %s", id)
	}
}

func TestGoCacheMounts(t *testing.T) {
	mounts := GoCacheMounts()
	require.Len(t, mounts, 2)

	ids := make(map[string]bool)
	for _, m := range mounts {
		ids[m.ID] = true
	}

	require.True(t, ids[GoModCacheID])
	require.True(t, ids[GoBuildCacheID])
}

func TestPythonCacheMounts(t *testing.T) {
	mounts := PythonCacheMounts()
	require.Len(t, mounts, 1)
	require.Equal(t, PipCacheID, mounts[0].ID)
	require.Equal(t, "/root/.cache/pip", mounts[0].Target)
}

func TestRustCacheMounts(t *testing.T) {
	mounts := RustCacheMounts()
	require.Len(t, mounts, 2)

	ids := make(map[string]bool)
	for _, m := range mounts {
		ids[m.ID] = true
	}

	require.True(t, ids[CargoRegistryCacheID])
	require.True(t, ids[CargoBuildCacheID])
}

func TestNodeCacheMounts(t *testing.T) {
	mounts := NodeCacheMounts()
	require.Len(t, mounts, 1)
	require.Equal(t, NpmCacheID, mounts[0].ID)
	require.Equal(t, "/root/.npm", mounts[0].Target)
}

func TestCCacheMounts(t *testing.T) {
	mounts := CCacheMounts()
	require.Len(t, mounts, 1)
	require.Equal(t, CcacheCacheID, mounts[0].ID)
	require.Equal(t, "/root/.ccache", mounts[0].Target)
}

func TestCacheMountOption(t *testing.T) {
	mount := CacheMount{
		ID:     "test-cache",
		Target: "/test/path",
		Mode:   llb.CacheMountShared,
	}

	opt := mount.CacheMountOption()
	require.NotNil(t, opt)
}

func TestCacheMountOptions(t *testing.T) {
	mounts := []CacheMount{
		{ID: "cache1", Target: "/path1", Mode: llb.CacheMountShared},
		{ID: "cache2", Target: "/path2", Mode: llb.CacheMountPrivate},
	}

	opts := CacheMountOptions(mounts)
	require.Len(t, opts, 2)
}

func TestCacheMountOptionsEmpty(t *testing.T) {
	opts := CacheMountOptions(nil)
	require.Empty(t, opts)

	opts = CacheMountOptions([]CacheMount{})
	require.Empty(t, opts)
}

func TestPipelineBuilderWithCacheMounts(t *testing.T) {
	builder := NewPipelineBuilder()
	builder.CacheMounts = GoCacheMounts()

	pipeline := config.Pipeline{
		Runs: "go build ./...",
	}

	base := llb.Image("golang:1.21")
	state, err := builder.BuildPipeline(base, &pipeline)
	require.NoError(t, err)

	// Verify we can marshal the state (this validates the cache mounts are valid LLB)
	def, err := state.Marshal(context.Background(), llb.LinuxAmd64)
	require.NoError(t, err)
	require.NotEmpty(t, def.Def)
}

func TestPipelineBuilderCacheMountsPassedToNestedPipelines(t *testing.T) {
	builder := NewPipelineBuilder()
	builder.CacheMounts = []CacheMount{
		{ID: "test-cache", Target: "/test", Mode: llb.CacheMountShared},
	}

	pipeline := config.Pipeline{
		Runs: "echo parent",
		Pipeline: []config.Pipeline{
			{Runs: "echo child"},
		},
	}

	base := llb.Image("alpine:latest")
	state, err := builder.BuildPipeline(base, &pipeline)
	require.NoError(t, err)

	def, err := state.Marshal(context.Background(), llb.LinuxAmd64)
	require.NoError(t, err)
	require.NotEmpty(t, def.Def)
}

// Integration test that verifies cache mounts work with BuildKit
func TestCacheMountsIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	bk := startBuildKitContainer(t, ctx)

	c, err := client.New(ctx, bk.Addr)
	require.NoError(t, err)
	defer c.Close()

	// Build with cache mount that writes a file
	builder := NewPipelineBuilder()
	builder.CacheMounts = []CacheMount{
		{ID: "test-integration-cache", Target: "/cache", Mode: llb.CacheMountShared},
	}

	pipelines := []config.Pipeline{
		{
			Name: "write-to-cache",
			Runs: `
mkdir -p /cache
echo "cached data" > /cache/data.txt
mkdir -p /home/build/melange-out/cache-test
cp /cache/data.txt /home/build/melange-out/cache-test/
`,
		},
	}

	base := llb.Image("alpine:latest")
	state := PrepareWorkspace(base, "cache-test")
	state, err = builder.BuildPipelines(state, pipelines)
	require.NoError(t, err)

	export := ExportWorkspace(state)
	def, err := export.Marshal(ctx, llb.LinuxAmd64)
	require.NoError(t, err)

	exportDir := t.TempDir()
	_, err = c.Solve(ctx, def, client.SolveOpt{
		Exports: []client.ExportEntry{{
			Type:      client.ExporterLocal,
			OutputDir: exportDir,
		}},
	}, nil)
	require.NoError(t, err)

	// Verify the cached file was copied to output
	content, err := os.ReadFile(filepath.Join(exportDir, "cache-test", "data.txt"))
	require.NoError(t, err)
	require.Contains(t, string(content), "cached data")
}

// Integration test that verifies cache persistence across builds
func TestCachePersistenceIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	bk := startBuildKitContainer(t, ctx)

	c, err := client.New(ctx, bk.Addr)
	require.NoError(t, err)
	defer c.Close()

	cacheID := "test-persistence-cache"

	// First build: write to cache
	builder1 := NewPipelineBuilder()
	builder1.CacheMounts = []CacheMount{
		{ID: cacheID, Target: "/cache", Mode: llb.CacheMountShared},
	}

	pipelines1 := []config.Pipeline{
		{
			Name: "write-to-cache",
			Runs: `
mkdir -p /cache
echo "first-build" > /cache/marker.txt
mkdir -p /home/build/melange-out/pkg1
echo "done" > /home/build/melange-out/pkg1/status.txt
`,
		},
	}

	base := llb.Image("alpine:latest")
	state1 := PrepareWorkspace(base, "pkg1")
	state1, err = builder1.BuildPipelines(state1, pipelines1)
	require.NoError(t, err)

	export1 := ExportWorkspace(state1)
	def1, err := export1.Marshal(ctx, llb.LinuxAmd64)
	require.NoError(t, err)

	exportDir1 := t.TempDir()
	_, err = c.Solve(ctx, def1, client.SolveOpt{
		Exports: []client.ExportEntry{{
			Type:      client.ExporterLocal,
			OutputDir: exportDir1,
		}},
	}, nil)
	require.NoError(t, err)

	// Second build: read from cache (same cache ID)
	builder2 := NewPipelineBuilder()
	builder2.CacheMounts = []CacheMount{
		{ID: cacheID, Target: "/cache", Mode: llb.CacheMountShared},
	}

	pipelines2 := []config.Pipeline{
		{
			Name: "read-from-cache",
			Runs: `
mkdir -p /home/build/melange-out/pkg2
if [ -f /cache/marker.txt ]; then
    cat /cache/marker.txt > /home/build/melange-out/pkg2/from-cache.txt
else
    echo "cache-miss" > /home/build/melange-out/pkg2/from-cache.txt
fi
`,
		},
	}

	state2 := PrepareWorkspace(base, "pkg2")
	state2, err = builder2.BuildPipelines(state2, pipelines2)
	require.NoError(t, err)

	export2 := ExportWorkspace(state2)
	def2, err := export2.Marshal(ctx, llb.LinuxAmd64)
	require.NoError(t, err)

	exportDir2 := t.TempDir()
	_, err = c.Solve(ctx, def2, client.SolveOpt{
		Exports: []client.ExportEntry{{
			Type:      client.ExporterLocal,
			OutputDir: exportDir2,
		}},
	}, nil)
	require.NoError(t, err)

	// Verify the cache persisted between builds
	content, err := os.ReadFile(filepath.Join(exportDir2, "pkg2", "from-cache.txt"))
	require.NoError(t, err)
	require.Contains(t, string(content), "first-build")
}
