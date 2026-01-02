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
	"fmt"
	"path/filepath"
	"strings"

	"github.com/moby/buildkit/client/llb"

	"github.com/dlorenc/melange2/pkg/cond"
	"github.com/dlorenc/melange2/pkg/config"
)

const (
	// DefaultWorkDir is the default working directory for pipeline steps.
	DefaultWorkDir = "/home/build"

	// MelangeOutDir is the output directory name for melange packages.
	MelangeOutDir = "melange-out"

	// DefaultPath is the default PATH for pipeline execution.
	DefaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

	// DefaultCacheDir is the default path where the melange cache is mounted.
	// This is used for caching fetch artifacts, Go modules, etc.
	DefaultCacheDir = "/var/cache/melange"

	// CacheLocalName is the name used for the cache directory local mount.
	CacheLocalName = "cache"

	// BuildUserUID is the UID for the build user.
	// This matches the QEMU runner behavior in baseline melange which uses root.
	BuildUserUID = 0

	// BuildUserGID is the GID for the build user/group.
	BuildUserGID = 0

	// BuildUserName is the username for the build user.
	BuildUserName = "root"

	// TestBaseImage is the base image used for e2e tests.
	// Uses wolfi-base to avoid Docker Hub rate limits.
	TestBaseImage = "cgr.dev/chainguard/wolfi-base:latest"
)

// PipelineBuilder converts melange pipelines to BuildKit LLB.
type PipelineBuilder struct {
	// Debug enables shell debugging (set -x)
	Debug bool

	// BaseEnv is the base environment for all pipeline steps.
	// Pipeline-specific environment variables override these.
	BaseEnv map[string]string

	// CacheMounts specifies cache mounts to use for build steps.
	// These are applied to all pipeline steps.
	CacheMounts []CacheMount
}

// NewPipelineBuilder creates a new PipelineBuilder with default configuration.
func NewPipelineBuilder() *PipelineBuilder {
	return &PipelineBuilder{
		BaseEnv: map[string]string{
			"PATH": DefaultPath,
			"HOME": DefaultWorkDir,
		},
	}
}

// PipelineResult contains the result of building pipelines.
type PipelineResult struct {
	// State is the final LLB state after all pipelines complete.
	// On error, this contains the state before the failed pipeline.
	State llb.State

	// FailedAtIndex is the index of the pipeline that failed, or -1 if all succeeded.
	FailedAtIndex int

	// Error is the error that occurred, or nil if all pipelines succeeded.
	Error error
}

// BuildPipelines builds LLB for multiple pipelines in sequence.
// Each pipeline operates on the state returned by the previous one.
func (b *PipelineBuilder) BuildPipelines(base llb.State, pipelines []config.Pipeline) (llb.State, error) {
	result := b.BuildPipelinesWithRecovery(base, pipelines)
	if result.Error != nil {
		return llb.State{}, result.Error
	}
	return result.State, nil
}

// BuildPipelinesWithRecovery builds LLB for multiple pipelines in sequence,
// returning the last good state on failure for debugging purposes.
// This allows exporting a debug image of the build environment before
// the failing step executed.
func (b *PipelineBuilder) BuildPipelinesWithRecovery(base llb.State, pipelines []config.Pipeline) PipelineResult {
	state := base
	for i := range pipelines {
		prevState := state
		var err error
		state, err = b.BuildPipeline(state, &pipelines[i])
		if err != nil {
			return PipelineResult{
				State:         prevState,
				FailedAtIndex: i,
				Error:         fmt.Errorf("pipeline %d: %w", i, err),
			}
		}
	}
	return PipelineResult{
		State:         state,
		FailedAtIndex: -1,
		Error:         nil,
	}
}

// BuildPipeline converts a single pipeline to LLB operations.
// Returns the modified state after running the pipeline.
func (b *PipelineBuilder) BuildPipeline(base llb.State, p *config.Pipeline) (llb.State, error) {
	// Check if this pipeline should run
	if p.If != "" {
		shouldRun, err := cond.Evaluate(p.If)
		if err != nil {
			return llb.State{}, fmt.Errorf("evaluating if condition %q: %w", p.If, err)
		}
		if !shouldRun {
			return base, nil
		}
	}

	state := base

	// Only run if there's something to run
	if p.Runs != "" {
		// Determine working directory
		workdir := DefaultWorkDir
		if p.WorkDir != "" {
			if filepath.IsAbs(p.WorkDir) {
				workdir = p.WorkDir
			} else {
				workdir = filepath.Join(DefaultWorkDir, p.WorkDir)
			}
		}

		// Build the script
		script := b.buildScript(p.Runs, workdir)

		// Build environment
		env := MergeEnv(b.BaseEnv, p.Environment)

		// Build run options
		// Run as build user (UID 1000) for permission parity with baseline melange.
		// Some installers (like Perl's ExtUtils::MakeMaker) set different permissions
		// when running as root (444/555) vs a regular user (644/755).
		// The workspace directories are created with proper ownership before this runs.
		opts := []llb.RunOption{
			llb.Args([]string{"/bin/sh", "-c", script}),
			llb.Dir(workdir),
			llb.User(BuildUserName),
		}

		// Add sorted environment variables for determinism
		opts = append(opts, SortedEnvOpts(env)...)

		// Add cache mounts
		opts = append(opts, CacheMountOptions(b.CacheMounts)...)

		// Add custom name for better logging
		if name := pipelineName(p); name != "" {
			opts = append(opts, llb.WithCustomName(name))
		}

		state = state.Run(opts...).Root()
	}

	// Process nested pipelines
	if len(p.Pipeline) > 0 {
		// Create a child builder with merged environment
		childBuilder := &PipelineBuilder{
			Debug:       b.Debug,
			BaseEnv:     MergeEnv(b.BaseEnv, p.Environment),
			CacheMounts: b.CacheMounts,
		}

		for i := range p.Pipeline {
			var err error
			state, err = childBuilder.BuildPipeline(state, &p.Pipeline[i])
			if err != nil {
				return llb.State{}, fmt.Errorf("nested pipeline %d: %w", i, err)
			}
		}
	}

	return state, nil
}

// buildScript creates the shell script to run for a pipeline step.
func (b *PipelineBuilder) buildScript(runs, workdir string) string {
	debugOpt := ' '
	if b.Debug {
		debugOpt = 'x'
	}

	return fmt.Sprintf(`set -e%c
[ -d '%s' ] || mkdir -p '%s'
cd '%s'
%s
exit 0`, debugOpt, workdir, workdir, workdir, runs)
}

// pipelineName returns a human-readable name for the pipeline.
func pipelineName(p *config.Pipeline) string {
	if p.Name != "" {
		return p.Name
	}
	if p.Uses != "" {
		return fmt.Sprintf("uses: %s", p.Uses)
	}
	if p.Label != "" {
		return p.Label
	}
	return ""
}

// WorkspaceOutputDir returns the full path to the package output directory.
func WorkspaceOutputDir(pkgName string) string {
	return filepath.Join(DefaultWorkDir, MelangeOutDir, pkgName)
}

// SetupBuildUser prepares the build environment.
// Since we run as root (matching QEMU runner behavior), this just ensures
// /tmp exists with proper permissions for temporary files.
func SetupBuildUser(base llb.State) llb.State {
	// Ensure /tmp exists with world-writable permissions (standard Linux behavior)
	// and create the work directory
	script := fmt.Sprintf(`mkdir -p %s
mkdir -p /tmp
chmod 1777 /tmp`,
		DefaultWorkDir,
	)

	return base.Run(
		llb.Args([]string{"/bin/sh", "-c", script}),
		llb.WithCustomName("setup build environment"),
	).Root()
}

// PrepareWorkspace creates the initial workspace structure.
// Returns a state with workspace and melange-out directories created.
// Runs as root (matching QEMU runner behavior).
func PrepareWorkspace(base llb.State, pkgName string) llb.State {
	// Ensure workspace, cache, and tmp directories exist with proper permissions.
	state := base.Run(
		llb.Args([]string{"/bin/sh", "-c", fmt.Sprintf(
			"mkdir -p %s && chmod 755 %s && "+
				"mkdir -p /tmp && chmod 1777 /tmp && "+
				"mkdir -p %s && chmod 755 %s",
			DefaultWorkDir, DefaultWorkDir,
			DefaultCacheDir, DefaultCacheDir,
		)}),
		llb.WithCustomName("create workspace"),
	).Root()

	return state.File(
		llb.Mkdir(WorkspaceOutputDir(pkgName), 0755,
			llb.WithParents(true),
		),
		llb.WithCustomName("create output directory"),
	)
}

// CopySourceToWorkspace copies source files from a Local mount to the workspace.
func CopySourceToWorkspace(base llb.State, localName string) llb.State {
	return base.File(
		llb.Copy(llb.Local(localName), "/", DefaultWorkDir+"/", &llb.CopyInfo{
			CopyDirContentsOnly: true,
		}),
		llb.WithCustomName("copy source to workspace"),
	)
}

// ExportWorkspace creates a state suitable for exporting the workspace output.
// This extracts the melange-out directory to the root for export.
func ExportWorkspace(state llb.State) llb.State {
	melangeOutPath := filepath.Join(DefaultWorkDir, MelangeOutDir)
	return llb.Scratch().File(
		llb.Copy(state, melangeOutPath, "/", &llb.CopyInfo{
			CopyDirContentsOnly: true,
		}),
		llb.WithCustomName("export workspace"),
	)
}

// CopyCacheToWorkspace copies cache files from a Local mount to /var/cache/melange.
// This enables pre-populating the cache from the host filesystem.
func CopyCacheToWorkspace(base llb.State, localName string) llb.State {
	return base.File(
		llb.Copy(llb.Local(localName), "/", DefaultCacheDir+"/", &llb.CopyInfo{
			CopyDirContentsOnly: true,
			CreateDestPath:      true,
		}),
		llb.WithCustomName("copy cache to workspace"),
	)
}

// BuildTestPipelines builds all test pipelines as a single LLB Run operation.
// This maintains process state (background processes, files, etc.) between steps
// while isolating environment variables by wrapping each step in a subshell.
//
// This matches the behavior of the old QEMU runner where all test steps ran
// in a single container with persistent process state.
func (b *PipelineBuilder) BuildTestPipelines(base llb.State, pipelines []config.Pipeline) (llb.State, error) {
	if len(pipelines) == 0 {
		return base, nil
	}

	// Collect all the scripts from all pipelines
	var scripts []string
	for i, p := range pipelines {
		script, err := b.buildTestPipelineScript(&p, i)
		if err != nil {
			return llb.State{}, fmt.Errorf("pipeline %d: %w", i, err)
		}
		if script != "" {
			scripts = append(scripts, script)
		}
	}

	if len(scripts) == 0 {
		return base, nil
	}

	// Build the combined script with all steps
	combinedScript := b.buildCombinedTestScript(scripts)

	// Build environment from base env
	env := make(map[string]string, len(b.BaseEnv))
	for k, v := range b.BaseEnv {
		env[k] = v
	}

	// Build run options
	opts := []llb.RunOption{
		llb.Args([]string{"/bin/sh", "-c", combinedScript}),
		llb.Dir(DefaultWorkDir),
		llb.User(BuildUserName),
	}

	// Add sorted environment variables for determinism
	opts = append(opts, SortedEnvOpts(env)...)

	// Add cache mounts
	opts = append(opts, CacheMountOptions(b.CacheMounts)...)

	// Add custom name
	opts = append(opts, llb.WithCustomName("run test pipelines"))

	return base.Run(opts...).Root(), nil
}

// buildTestPipelineScript builds the script for a single test pipeline step.
// Returns empty string if the pipeline should be skipped.
func (b *PipelineBuilder) buildTestPipelineScript(p *config.Pipeline, index int) (string, error) {
	// Check if this pipeline should run
	if p.If != "" {
		shouldRun, err := cond.Evaluate(p.If)
		if err != nil {
			return "", fmt.Errorf("evaluating if condition %q: %w", p.If, err)
		}
		if !shouldRun {
			return "", nil
		}
	}

	// Skip if nothing to run
	if p.Runs == "" && len(p.Pipeline) == 0 {
		return "", nil
	}

	// Determine working directory
	workdir := DefaultWorkDir
	if p.WorkDir != "" {
		if filepath.IsAbs(p.WorkDir) {
			workdir = p.WorkDir
		} else {
			workdir = filepath.Join(DefaultWorkDir, p.WorkDir)
		}
	}

	// Build environment exports for this step
	var envExports string
	if len(p.Environment) > 0 {
		for k, v := range p.Environment {
			// Escape single quotes in value
			escapedV := strings.ReplaceAll(v, "'", "'\"'\"'")
			envExports += fmt.Sprintf("export %s='%s'\n", k, escapedV)
		}
	}

	// Build nested pipeline scripts recursively
	var nestedScripts string
	if len(p.Pipeline) > 0 {
		for i := range p.Pipeline {
			nested, err := b.buildTestPipelineScript(&p.Pipeline[i], i)
			if err != nil {
				return "", fmt.Errorf("nested pipeline %d: %w", i, err)
			}
			if nested != "" {
				nestedScripts += nested + "\n"
			}
		}
	}

	// Build the script for this step
	var script string
	if p.Runs != "" {
		script = p.Runs
	}

	// Combine environment, main script, and nested scripts
	var fullScript string
	if envExports != "" {
		fullScript = envExports
	}
	if script != "" {
		fullScript += script + "\n"
	}
	if nestedScripts != "" {
		fullScript += nestedScripts
	}

	if fullScript == "" {
		return "", nil
	}

	debugOpt := ' '
	if b.Debug {
		debugOpt = 'x'
	}

	// Get step name for logging
	stepName := pipelineName(p)
	if stepName == "" {
		stepName = fmt.Sprintf("step %d", index)
	}

	// Wrap in a subshell to isolate environment variables
	// The subshell runs in a new shell process, so env vars don't leak
	// but the process state (background jobs, files, etc.) is maintained
	return fmt.Sprintf(`
# Test step: %s
(
  set -e%c
  [ -d '%s' ] || mkdir -p '%s'
  cd '%s'
%s
)
`, stepName, debugOpt, workdir, workdir, workdir, fullScript), nil
}

// buildCombinedTestScript combines multiple test step scripts into one.
func (b *PipelineBuilder) buildCombinedTestScript(scripts []string) string {
	// Each script is already wrapped in a subshell, so we just need to
	// combine them and ensure we exit on first failure
	var combined strings.Builder
	combined.WriteString("set -e\n")

	for _, script := range scripts {
		combined.WriteString(script)
		combined.WriteString("\n")
	}

	combined.WriteString("exit 0\n")
	return combined.String()
}
