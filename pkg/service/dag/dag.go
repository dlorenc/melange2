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

// Package dag provides dependency graph construction and topological sorting
// for multi-package builds.
package dag

import (
	"fmt"
	"sort"
)

// Node represents a package in the dependency graph.
type Node struct {
	Name         string
	ConfigYAML   string
	Dependencies []string // package names from environment.contents.packages
}

// Graph represents a directed acyclic graph of package dependencies.
type Graph struct {
	nodes map[string]*Node
}

// NewGraph creates an empty dependency graph.
func NewGraph() *Graph {
	return &Graph{
		nodes: make(map[string]*Node),
	}
}

// AddNode adds a package node to the graph.
// Returns an error if a node with the same name already exists.
func (g *Graph) AddNode(name, configYAML string, deps []string) error {
	if _, exists := g.nodes[name]; exists {
		return fmt.Errorf("duplicate package: %s", name)
	}

	g.nodes[name] = &Node{
		Name:         name,
		ConfigYAML:   configYAML,
		Dependencies: deps,
	}
	return nil
}

// GetNode returns a node by name, or nil if not found.
func (g *Graph) GetNode(name string) *Node {
	return g.nodes[name]
}

// Nodes returns all nodes in the graph.
func (g *Graph) Nodes() []*Node {
	nodes := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, n)
	}
	return nodes
}

// Size returns the number of nodes in the graph.
func (g *Graph) Size() int {
	return len(g.nodes)
}

// TopologicalSort returns nodes in dependency order using Kahn's algorithm.
// Nodes are returned such that dependencies come before dependents.
// Only considers dependencies that exist within the graph (external deps are ignored).
// Returns an error if a cycle is detected.
func (g *Graph) TopologicalSort() ([]Node, error) {
	if len(g.nodes) == 0 {
		return nil, nil
	}

	// Calculate in-degree for each node (only counting in-graph deps)
	inDegree := make(map[string]int)
	for name := range g.nodes {
		inDegree[name] = 0
	}

	for _, node := range g.nodes {
		for _, dep := range node.Dependencies {
			// Only count dependencies that are in the graph
			if _, exists := g.nodes[dep]; exists {
				inDegree[node.Name]++
			}
		}
	}

	// Initialize queue with nodes that have no in-graph dependencies
	var queue []string
	for name, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, name)
		}
	}
	// Sort for deterministic ordering
	sort.Strings(queue)

	var result []Node
	for len(queue) > 0 {
		// Pop from front
		name := queue[0]
		queue = queue[1:]

		node := g.nodes[name]
		if node == nil {
			continue
		}
		result = append(result, *node)

		// For each node in the graph
		for _, node := range g.nodes {
			// Check if this node depends on the one we just processed
			for _, dep := range node.Dependencies {
				if dep == name {
					inDegree[node.Name]--
					if inDegree[node.Name] == 0 {
						queue = append(queue, node.Name)
						// Re-sort to maintain deterministic order
						sort.Strings(queue)
					}
					break
				}
			}
		}
	}

	if len(result) != len(g.nodes) {
		// Cycle detected - find and report it
		cycle, _ := g.DetectCycle()
		return nil, fmt.Errorf("cycle detected in dependency graph: %v", cycle)
	}

	return result, nil
}

// DetectCycle uses DFS to detect and return a cycle path if one exists.
// Returns nil if no cycle is found.
func (g *Graph) DetectCycle() ([]string, error) {
	// States: 0 = unvisited, 1 = in current path, 2 = done
	state := make(map[string]int)
	parent := make(map[string]string)

	var cyclePath []string

	var dfs func(name string) bool
	dfs = func(name string) bool {
		state[name] = 1 // Mark as in current path

		node := g.nodes[name]
		for _, dep := range node.Dependencies {
			// Only consider in-graph dependencies
			if _, exists := g.nodes[dep]; !exists {
				continue
			}

			if state[dep] == 1 {
				// Found cycle - reconstruct path
				cyclePath = []string{dep, name}
				for cur := name; cur != dep; {
					p, ok := parent[cur]
					if !ok {
						break
					}
					cyclePath = append([]string{p}, cyclePath...)
					cur = p
				}
				return true
			}

			if state[dep] == 0 {
				parent[dep] = name
				if dfs(dep) {
					return true
				}
			}
		}

		state[name] = 2 // Mark as done
		return false
	}

	// Run DFS from each unvisited node
	for name := range g.nodes {
		if state[name] == 0 {
			if dfs(name) {
				return cyclePath, fmt.Errorf("cycle detected: %v", cyclePath)
			}
		}
	}

	return nil, nil
}

// FilterInGraphDeps returns only the dependencies that exist within the graph.
func (g *Graph) FilterInGraphDeps(deps []string) []string {
	var filtered []string
	for _, dep := range deps {
		if _, exists := g.nodes[dep]; exists {
			filtered = append(filtered, dep)
		}
	}
	return filtered
}

// GetBuildablePaths returns packages that have no unmet in-graph dependencies.
// These packages can be built immediately.
func (g *Graph) GetBuildablePaths() []string {
	var buildable []string

	for _, node := range g.nodes {
		ready := true
		for _, dep := range node.Dependencies {
			if _, exists := g.nodes[dep]; exists {
				// Has an in-graph dependency, so not immediately buildable
				ready = false
				break
			}
		}
		if ready {
			buildable = append(buildable, node.Name)
		}
	}

	sort.Strings(buildable)
	return buildable
}
