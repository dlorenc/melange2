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

package dag

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGraph(t *testing.T) {
	g := NewGraph()
	assert.NotNil(t, g)
	assert.Equal(t, 0, g.Size())
}

func TestAddNode(t *testing.T) {
	g := NewGraph()

	err := g.AddNode("pkg-a", "config: a", []string{})
	require.NoError(t, err)
	assert.Equal(t, 1, g.Size())

	// Adding duplicate should fail
	err = g.AddNode("pkg-a", "config: a2", []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate package")

	// Adding different package should succeed
	err = g.AddNode("pkg-b", "config: b", []string{"pkg-a"})
	require.NoError(t, err)
	assert.Equal(t, 2, g.Size())
}

func TestGetNode(t *testing.T) {
	g := NewGraph()
	g.AddNode("pkg-a", "config: a", []string{"external-dep"})

	node := g.GetNode("pkg-a")
	require.NotNil(t, node)
	assert.Equal(t, "pkg-a", node.Name)
	assert.Equal(t, "config: a", node.ConfigYAML)
	assert.Equal(t, []string{"external-dep"}, node.Dependencies)

	// Non-existent node
	node = g.GetNode("pkg-nonexistent")
	assert.Nil(t, node)
}

func TestTopologicalSort_Empty(t *testing.T) {
	g := NewGraph()
	result, err := g.TopologicalSort()
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestTopologicalSort_SingleNode(t *testing.T) {
	g := NewGraph()
	g.AddNode("pkg-a", "config: a", []string{})

	result, err := g.TopologicalSort()
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "pkg-a", result[0].Name)
}

func TestTopologicalSort_LinearChain(t *testing.T) {
	// A -> B -> C (C depends on B, B depends on A)
	g := NewGraph()
	g.AddNode("pkg-c", "config: c", []string{"pkg-b"})
	g.AddNode("pkg-a", "config: a", []string{})
	g.AddNode("pkg-b", "config: b", []string{"pkg-a"})

	result, err := g.TopologicalSort()
	require.NoError(t, err)
	require.Len(t, result, 3)

	// A must come before B, B must come before C
	indexOf := func(name string) int {
		for i, n := range result {
			if n.Name == name {
				return i
			}
		}
		return -1
	}

	assert.Less(t, indexOf("pkg-a"), indexOf("pkg-b"))
	assert.Less(t, indexOf("pkg-b"), indexOf("pkg-c"))
}

func TestTopologicalSort_Diamond(t *testing.T) {
	//     A
	//    / \
	//   B   C
	//    \ /
	//     D
	g := NewGraph()
	g.AddNode("pkg-a", "config: a", []string{})
	g.AddNode("pkg-b", "config: b", []string{"pkg-a"})
	g.AddNode("pkg-c", "config: c", []string{"pkg-a"})
	g.AddNode("pkg-d", "config: d", []string{"pkg-b", "pkg-c"})

	result, err := g.TopologicalSort()
	require.NoError(t, err)
	require.Len(t, result, 4)

	indexOf := func(name string) int {
		for i, n := range result {
			if n.Name == name {
				return i
			}
		}
		return -1
	}

	// A must come first
	assert.Equal(t, 0, indexOf("pkg-a"))
	// B and C must come before D
	assert.Less(t, indexOf("pkg-b"), indexOf("pkg-d"))
	assert.Less(t, indexOf("pkg-c"), indexOf("pkg-d"))
}

func TestTopologicalSort_ExternalDeps(t *testing.T) {
	// External dependencies (not in graph) should be ignored
	g := NewGraph()
	g.AddNode("pkg-a", "config: a", []string{"external-lib", "another-external"})
	g.AddNode("pkg-b", "config: b", []string{"pkg-a", "build-base"})

	result, err := g.TopologicalSort()
	require.NoError(t, err)
	require.Len(t, result, 2)

	// A must come before B (since B depends on A)
	assert.Equal(t, "pkg-a", result[0].Name)
	assert.Equal(t, "pkg-b", result[1].Name)
}

func TestTopologicalSort_Cycle(t *testing.T) {
	// A -> B -> C -> A (cycle)
	g := NewGraph()
	g.AddNode("pkg-a", "config: a", []string{"pkg-c"})
	g.AddNode("pkg-b", "config: b", []string{"pkg-a"})
	g.AddNode("pkg-c", "config: c", []string{"pkg-b"})

	result, err := g.TopologicalSort()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cycle detected")
	assert.Nil(t, result)
}

func TestTopologicalSort_SelfLoop(t *testing.T) {
	g := NewGraph()
	g.AddNode("pkg-a", "config: a", []string{"pkg-a"})

	result, err := g.TopologicalSort()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cycle detected")
	assert.Nil(t, result)
}

func TestDetectCycle_NoCycle(t *testing.T) {
	g := NewGraph()
	g.AddNode("pkg-a", "config: a", []string{})
	g.AddNode("pkg-b", "config: b", []string{"pkg-a"})

	cycle, err := g.DetectCycle()
	assert.NoError(t, err)
	assert.Nil(t, cycle)
}

func TestDetectCycle_WithCycle(t *testing.T) {
	g := NewGraph()
	g.AddNode("pkg-a", "config: a", []string{"pkg-b"})
	g.AddNode("pkg-b", "config: b", []string{"pkg-a"})

	cycle, err := g.DetectCycle()
	assert.Error(t, err)
	assert.NotNil(t, cycle)
	// Cycle should contain both nodes
	assert.Contains(t, cycle, "pkg-a")
	assert.Contains(t, cycle, "pkg-b")
}

func TestFilterInGraphDeps(t *testing.T) {
	g := NewGraph()
	g.AddNode("pkg-a", "config: a", []string{})
	g.AddNode("pkg-b", "config: b", []string{})

	deps := []string{"pkg-a", "external-lib", "pkg-b", "another-external"}
	filtered := g.FilterInGraphDeps(deps)

	assert.Len(t, filtered, 2)
	assert.Contains(t, filtered, "pkg-a")
	assert.Contains(t, filtered, "pkg-b")
}

func TestGetBuildablePaths(t *testing.T) {
	g := NewGraph()
	g.AddNode("pkg-a", "config: a", []string{})
	g.AddNode("pkg-b", "config: b", []string{"external-only"})
	g.AddNode("pkg-c", "config: c", []string{"pkg-a"})
	g.AddNode("pkg-d", "config: d", []string{"pkg-a", "pkg-b"})

	buildable := g.GetBuildablePaths()

	// pkg-a and pkg-b have no in-graph deps, so they're buildable
	assert.Len(t, buildable, 2)
	assert.Contains(t, buildable, "pkg-a")
	assert.Contains(t, buildable, "pkg-b")
}

func TestTopologicalSort_Deterministic(t *testing.T) {
	// Run multiple times to ensure deterministic ordering
	for i := 0; i < 10; i++ {
		g := NewGraph()
		// Add in random-ish order
		g.AddNode("pkg-z", "config: z", []string{})
		g.AddNode("pkg-a", "config: a", []string{})
		g.AddNode("pkg-m", "config: m", []string{})

		result, err := g.TopologicalSort()
		require.NoError(t, err)
		require.Len(t, result, 3)

		// Should be alphabetically sorted since no deps
		assert.Equal(t, "pkg-a", result[0].Name)
		assert.Equal(t, "pkg-m", result[1].Name)
		assert.Equal(t, "pkg-z", result[2].Name)
	}
}

func TestTopologicalSort_Complex(t *testing.T) {
	// More complex graph:
	//   A   B
	//   |\ /|
	//   | X |
	//   |/ \|
	//   C   D
	//    \ /
	//     E
	g := NewGraph()
	g.AddNode("pkg-a", "config: a", []string{})
	g.AddNode("pkg-b", "config: b", []string{})
	g.AddNode("pkg-c", "config: c", []string{"pkg-a", "pkg-b"})
	g.AddNode("pkg-d", "config: d", []string{"pkg-a", "pkg-b"})
	g.AddNode("pkg-e", "config: e", []string{"pkg-c", "pkg-d"})

	result, err := g.TopologicalSort()
	require.NoError(t, err)
	require.Len(t, result, 5)

	indexOf := func(name string) int {
		for i, n := range result {
			if n.Name == name {
				return i
			}
		}
		return -1
	}

	// A and B must come before C, D
	assert.Less(t, indexOf("pkg-a"), indexOf("pkg-c"))
	assert.Less(t, indexOf("pkg-a"), indexOf("pkg-d"))
	assert.Less(t, indexOf("pkg-b"), indexOf("pkg-c"))
	assert.Less(t, indexOf("pkg-b"), indexOf("pkg-d"))
	// C and D must come before E
	assert.Less(t, indexOf("pkg-c"), indexOf("pkg-e"))
	assert.Less(t, indexOf("pkg-d"), indexOf("pkg-e"))
}
