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
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/moby/buildkit/client"
	digest "github.com/opencontainers/go-digest"
)

// ProgressMode controls how build progress is displayed.
type ProgressMode string

const (
	// ProgressModeAuto automatically detects TTY and uses appropriate mode.
	ProgressModeAuto ProgressMode = "auto"
	// ProgressModePlain outputs plain text progress suitable for logs.
	ProgressModePlain ProgressMode = "plain"
	// ProgressModeTTY uses terminal UI with live updates.
	ProgressModeTTY ProgressMode = "tty"
	// ProgressModeQuiet suppresses progress output.
	ProgressModeQuiet ProgressMode = "quiet"
)

// ProgressWriter handles BuildKit solve status updates and displays progress.
type ProgressWriter struct {
	mode      ProgressMode
	out       io.Writer
	showLogs  bool
	startTime time.Time

	mu          sync.Mutex
	vertices    map[digest.Digest]*vertexState
	vertexOrder []digest.Digest
	completed   int
	cached      int
	total       int
}

type vertexState struct {
	name      string
	started   *time.Time
	completed *time.Time
	cached    bool
	error     string
	logs      []byte
}

// NewProgressWriter creates a new progress writer.
func NewProgressWriter(out io.Writer, mode ProgressMode, showLogs bool) *ProgressWriter {
	return &ProgressWriter{
		mode:      mode,
		out:       out,
		showLogs:  showLogs,
		startTime: time.Now(),
		vertices:  make(map[digest.Digest]*vertexState),
	}
}

// Write processes status updates from BuildKit and displays progress.
// This should be called in a goroutine while Solve is running.
func (p *ProgressWriter) Write(ctx context.Context, ch chan *client.SolveStatus) error {
	log := clog.FromContext(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case status, ok := <-ch:
			if !ok {
				p.printSummary(log)
				return nil
			}
			p.processStatus(log, status)
		}
	}
}

func (p *ProgressWriter) processStatus(log *clog.Logger, status *client.SolveStatus) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Process vertices (build steps)
	for _, v := range status.Vertexes {
		state, exists := p.vertices[v.Digest]
		if !exists {
			state = &vertexState{
				name: v.Name,
			}
			p.vertices[v.Digest] = state
			p.vertexOrder = append(p.vertexOrder, v.Digest)
			p.total++
		}

		// Update state
		if v.Started != nil && state.started == nil {
			state.started = v.Started
			p.printVertexStarted(log, state)
		}

		if v.Completed != nil && state.completed == nil {
			state.completed = v.Completed
			state.cached = v.Cached
			if v.Error != "" {
				state.error = v.Error
			}
			p.printVertexCompleted(log, state)
			p.completed++
			if state.cached {
				p.cached++
			}
		}
	}

	// Process logs (stdout/stderr from build steps)
	// Always accumulate logs so we can show them for failed steps
	for _, l := range status.Logs {
		state, exists := p.vertices[l.Vertex]
		if exists {
			state.logs = append(state.logs, l.Data...)
			// Only print logs in real-time if showLogs is enabled
			if p.showLogs {
				p.printLog(log, state, l.Data)
			}
		}
	}
}

func (p *ProgressWriter) printVertexStarted(log *clog.Logger, state *vertexState) {
	if p.mode == ProgressModeQuiet {
		return
	}

	name := p.formatName(state.name)
	if name == "" {
		return
	}

	if p.mode == ProgressModePlain || p.mode == ProgressModeAuto {
		log.Infof("[%d/%d] %s", p.completed+1, p.total, name)
	}
}

func (p *ProgressWriter) printVertexCompleted(log *clog.Logger, state *vertexState) {
	if p.mode == ProgressModeQuiet {
		return
	}

	name := p.formatName(state.name)
	if name == "" {
		return
	}

	duration := ""
	if state.started != nil && state.completed != nil {
		d := state.completed.Sub(*state.started)
		duration = fmt.Sprintf(" (%.1fs)", d.Seconds())
	}

	status := "done"
	if state.cached {
		status = "CACHED"
	}
	if state.error != "" {
		status = "ERROR"
	}

	if p.mode == ProgressModePlain || p.mode == ProgressModeAuto {
		log.Infof("  -> %s%s [%s]", name, duration, status)

		// Always print logs for failed steps, even if showLogs is false
		// This helps users diagnose build failures without needing --debug
		if state.error != "" && len(state.logs) > 0 && !p.showLogs {
			log.Infof("")
			log.Infof("  Error output from failed step:")
			p.printLog(log, state, state.logs)
		}
	}
}

func (p *ProgressWriter) printLog(log *clog.Logger, _ *vertexState, data []byte) {
	if p.mode == ProgressModeQuiet {
		return
	}
	p.printLogUnlocked(log, data)
}

// printLogUnlocked prints log data without checking mode (for use when lock is held).
func (p *ProgressWriter) printLogUnlocked(log *clog.Logger, data []byte) {
	// Print each line with a prefix
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if line != "" {
			log.Infof("    | %s", line)
		}
	}
}

func (p *ProgressWriter) printSummary(log *clog.Logger) {
	if p.mode == ProgressModeQuiet {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	elapsed := time.Since(p.startTime)

	// Collect failed steps and count errors
	errors := 0
	var failedSteps []*vertexState
	for _, d := range p.vertexOrder {
		state := p.vertices[d]
		if state == nil {
			continue
		}
		if state.error != "" {
			errors++
			if len(state.logs) > 0 {
				failedSteps = append(failedSteps, state)
			}
		}
	}

	// Print logs from failed steps (catches any logs that came in after completion)
	if len(failedSteps) > 0 && !p.showLogs {
		log.Infof("")
		log.Infof("Failed step output:")
		for _, state := range failedSteps {
			name := p.formatName(state.name)
			if name != "" {
				log.Infof("")
				log.Infof("  Step: %s", name)
			}
			p.printLogUnlocked(log, state.logs)
		}
	}

	log.Infof("")
	log.Infof("Build summary:")
	log.Infof("  Total steps:  %d", p.total)
	log.Infof("  Cached:       %d", p.cached)
	log.Infof("  Executed:     %d", p.completed-p.cached)
	if errors > 0 {
		log.Infof("  Errors:       %d", errors)
	}
	log.Infof("  Duration:     %.1fs", elapsed.Seconds())
}

// formatName cleans up vertex names for display.
func (p *ProgressWriter) formatName(name string) string {
	// Skip internal operations
	if name == "" {
		return ""
	}

	// Skip some internal BuildKit operations
	if strings.HasPrefix(name, "[internal]") {
		return ""
	}

	// Truncate long names
	if len(name) > 80 {
		return name[:77] + "..."
	}

	return name
}

// Summary returns build statistics after completion.
type Summary struct {
	Total     int
	Completed int
	Cached    int
	Errors    int
	Duration  time.Duration
	Steps     []StepSummary
}

// StepSummary contains information about a single build step.
type StepSummary struct {
	Name     string
	Duration time.Duration
	Cached   bool
	Error    string
}

// GetSummary returns the build summary after the build completes.
func (p *ProgressWriter) GetSummary() Summary {
	p.mu.Lock()
	defer p.mu.Unlock()

	errors := 0
	steps := make([]StepSummary, 0, len(p.vertexOrder))

	// Sort by order of appearance
	for _, d := range p.vertexOrder {
		state := p.vertices[d]
		if state == nil || state.name == "" {
			continue
		}

		var duration time.Duration
		if state.started != nil && state.completed != nil {
			duration = state.completed.Sub(*state.started)
		}

		if state.error != "" {
			errors++
		}

		steps = append(steps, StepSummary{
			Name:     state.name,
			Duration: duration,
			Cached:   state.cached,
			Error:    state.error,
		})
	}

	// Sort steps by duration for the summary (longest first)
	sort.Slice(steps, func(i, j int) bool {
		return steps[i].Duration > steps[j].Duration
	})

	return Summary{
		Total:     p.total,
		Completed: p.completed,
		Cached:    p.cached,
		Errors:    errors,
		Duration:  time.Since(p.startTime),
		Steps:     steps,
	}
}
