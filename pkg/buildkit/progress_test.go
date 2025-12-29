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
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/moby/buildkit/client"
	digest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

func TestNewProgressWriter(t *testing.T) {
	var buf bytes.Buffer
	pw := NewProgressWriter(&buf, ProgressModePlain, true)

	require.NotNil(t, pw)
	require.Equal(t, ProgressModePlain, pw.mode)
	require.True(t, pw.showLogs)
	require.NotNil(t, pw.vertices)
}

func TestProgressModeConstants(t *testing.T) {
	require.Equal(t, ProgressMode("auto"), ProgressModeAuto)
	require.Equal(t, ProgressMode("plain"), ProgressModePlain)
	require.Equal(t, ProgressMode("tty"), ProgressModeTTY)
	require.Equal(t, ProgressMode("quiet"), ProgressModeQuiet)
}

func TestProgressWriterGetSummary(t *testing.T) {
	var buf bytes.Buffer
	pw := NewProgressWriter(&buf, ProgressModePlain, false)

	// Simulate some vertex activity
	d1 := digest.FromString("vertex1")
	d2 := digest.FromString("vertex2")
	d3 := digest.FromString("vertex3")

	now := time.Now()
	earlier := now.Add(-2 * time.Second)
	muchEarlier := now.Add(-5 * time.Second)

	// Add vertices manually to simulate build progress
	pw.mu.Lock()
	pw.vertexOrder = []digest.Digest{d1, d2, d3}
	pw.vertices[d1] = &vertexState{
		name:      "step 1",
		started:   &muchEarlier,
		completed: &earlier,
		cached:    false,
	}
	pw.vertices[d2] = &vertexState{
		name:      "step 2",
		started:   &earlier,
		completed: &now,
		cached:    true,
	}
	pw.vertices[d3] = &vertexState{
		name:      "step 3",
		started:   &now,
		completed: nil, // still running
		error:     "failed",
	}
	pw.mu.Unlock()

	summary := pw.GetSummary()

	require.Len(t, summary.Steps, 3)
	require.Equal(t, 1, summary.Errors)

	// Find the failed step
	var foundError bool
	for _, step := range summary.Steps {
		if step.Error == "failed" {
			foundError = true
			require.Equal(t, "step 3", step.Name)
		}
	}
	require.True(t, foundError, "should have found error step")
}

func TestProgressWriterGetSummaryEmpty(t *testing.T) {
	var buf bytes.Buffer
	pw := NewProgressWriter(&buf, ProgressModePlain, false)

	summary := pw.GetSummary()
	require.Empty(t, summary.Steps)
	require.Zero(t, summary.Errors)
}

func TestProgressWriterGetSummaryCached(t *testing.T) {
	var buf bytes.Buffer
	pw := NewProgressWriter(&buf, ProgressModePlain, false)

	d1 := digest.FromString("cached-vertex")
	now := time.Now()

	pw.mu.Lock()
	pw.vertexOrder = []digest.Digest{d1}
	pw.vertices[d1] = &vertexState{
		name:      "cached step",
		started:   &now,
		completed: &now,
		cached:    true,
	}
	pw.mu.Unlock()

	summary := pw.GetSummary()

	require.Len(t, summary.Steps, 1)
	require.True(t, summary.Steps[0].Cached)
	require.Equal(t, "cached step", summary.Steps[0].Name)
}

func TestProgressWriterWriteIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	var buf bytes.Buffer
	pw := NewProgressWriter(&buf, ProgressModePlain, false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a channel to send status updates
	ch := make(chan *client.SolveStatus)

	// Start the writer in a goroutine
	done := make(chan error)
	go func() {
		done <- pw.Write(ctx, ch)
	}()

	// Send some status updates
	d := digest.FromString("test-vertex")
	now := time.Now()

	ch <- &client.SolveStatus{
		Vertexes: []*client.Vertex{
			{
				Digest:  d,
				Name:    "test step",
				Started: &now,
			},
		},
	}

	completed := now.Add(time.Second)
	ch <- &client.SolveStatus{
		Vertexes: []*client.Vertex{
			{
				Digest:    d,
				Name:      "test step",
				Started:   &now,
				Completed: &completed,
			},
		},
	}

	// Close the channel to signal completion
	close(ch)

	// Wait for writer to finish
	err := <-done
	require.NoError(t, err)

	// Verify vertex was tracked
	pw.mu.Lock()
	state, ok := pw.vertices[d]
	pw.mu.Unlock()

	require.True(t, ok)
	require.Equal(t, "test step", state.name)
	require.NotNil(t, state.completed)
}

func TestProgressWriterWriteWithLogs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	var buf bytes.Buffer
	pw := NewProgressWriter(&buf, ProgressModePlain, true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := make(chan *client.SolveStatus)

	done := make(chan error)
	go func() {
		done <- pw.Write(ctx, ch)
	}()

	d := digest.FromString("test-vertex")
	now := time.Now()

	// First create the vertex
	ch <- &client.SolveStatus{
		Vertexes: []*client.Vertex{
			{
				Digest:  d,
				Name:    "test step",
				Started: &now,
			},
		},
	}

	// Then send logs
	ch <- &client.SolveStatus{
		Logs: []*client.VertexLog{
			{
				Vertex: d,
				Data:   []byte("test log output\n"),
			},
		},
	}

	close(ch)
	err := <-done
	require.NoError(t, err)

	// Verify logs were captured
	pw.mu.Lock()
	state := pw.vertices[d]
	pw.mu.Unlock()

	require.Contains(t, string(state.logs), "test log output")
}

func TestProgressWriterWriteError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	var buf bytes.Buffer
	pw := NewProgressWriter(&buf, ProgressModePlain, false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := make(chan *client.SolveStatus)

	done := make(chan error)
	go func() {
		done <- pw.Write(ctx, ch)
	}()

	d := digest.FromString("error-vertex")
	now := time.Now()

	ch <- &client.SolveStatus{
		Vertexes: []*client.Vertex{
			{
				Digest:    d,
				Name:      "failed step",
				Started:   &now,
				Completed: &now,
				Error:     "something went wrong",
			},
		},
	}

	close(ch)
	err := <-done
	require.NoError(t, err)

	// Verify error was tracked
	pw.mu.Lock()
	state := pw.vertices[d]
	pw.mu.Unlock()

	require.Equal(t, "something went wrong", state.error)
}
