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
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/moby/buildkit/client/llb"
	digest "github.com/opencontainers/go-digest"

	"github.com/dlorenc/melange2/pkg/config"
)

// ErrFetchSHA512NotSupported is returned when fetch is called with expected-sha512,
// indicating that the shell fallback should be used since BuildKit HTTP only supports sha256.
var ErrFetchSHA512NotSupported = errors.New("fetch with expected-sha512 requires shell fallback (BuildKit HTTP only supports sha256)")

// BuiltinPipelines is the set of pipeline names that have native LLB implementations.
var BuiltinPipelines = map[string]bool{
	"git-checkout": true,
	"fetch":        true,
}

// IsBuiltinPipeline returns true if the pipeline name has a native LLB implementation.
func IsBuiltinPipeline(name string) bool {
	return BuiltinPipelines[name]
}

// BuildBuiltinPipeline builds native LLB operations for a built-in pipeline.
// Returns the modified state after the pipeline operations.
func BuildBuiltinPipeline(base llb.State, p *config.Pipeline) (llb.State, error) {
	switch p.Uses {
	case "git-checkout":
		return buildGitCheckout(base, p)
	case "fetch":
		return buildFetch(base, p)
	default:
		return llb.State{}, fmt.Errorf("unknown built-in pipeline: %s", p.Uses)
	}
}

// buildGitCheckout implements the git-checkout pipeline using native LLB operations.
// This uses BuildKit's llb.Git() source operation for efficient, cached git clones.
func buildGitCheckout(base llb.State, p *config.Pipeline) (llb.State, error) {
	with := p.With

	// Required: repository URL
	repo := with["repository"]
	if repo == "" {
		return llb.State{}, fmt.Errorf("git-checkout: repository is required")
	}

	// Optional: destination directory (default: ".")
	dest := with["destination"]
	if dest == "" {
		dest = "."
	}

	// Determine the ref to checkout (tag, branch, or expected-commit)
	// Priority: tag > branch > expected-commit
	ref := ""
	tag := with["tag"]
	branch := with["branch"]
	expectedCommit := with["expected-commit"]

	switch {
	case tag != "":
		ref = tag
	case branch != "":
		ref = branch
	case expectedCommit != "":
		ref = expectedCommit
	}

	// If no ref specified, use HEAD
	if ref == "" {
		ref = "HEAD"
	}

	// Build git options
	var gitOpts []llb.GitOption

	// Handle depth - BuildKit's Git() doesn't have a direct depth option,
	// but we can use KeepGitDir to preserve .git for full history
	depth := with["depth"]
	keepGitDir := false
	if depth == "-1" || depth == "unset" || depth == "" {
		// Full clone or unset - keep git dir for cherry-picks
		keepGitDir = true
	}
	if keepGitDir {
		gitOpts = append(gitOpts, llb.KeepGitDir())
	}

	// Custom name for progress display
	gitOpts = append(gitOpts, llb.WithCustomNamef("[git] clone %s@%s", repo, ref))

	// Create the git source
	gitState := llb.Git(repo, ref, gitOpts...)

	// Determine the full destination path
	destPath := dest
	if !filepath.IsAbs(destPath) {
		destPath = filepath.Join(DefaultWorkDir, destPath)
	}

	// Copy git contents to the workspace
	// We need to ensure the destination directory exists and has proper ownership
	state := base.Run(
		llb.Args([]string{"/bin/sh", "-c", fmt.Sprintf("mkdir -p %s && chown %d:%d %s",
			destPath, BuildUserUID, BuildUserGID, destPath)}),
		llb.WithCustomNamef("[git-checkout] prepare %s", destPath),
	).Root()

	// Copy the git clone to the destination
	state = state.File(
		llb.Copy(gitState, "/", destPath+"/", &llb.CopyInfo{
			CopyDirContentsOnly: true,
			CreateDestPath:      true,
			ChownOpt: &llb.ChownOpt{
				User:  &llb.UserOpt{UID: BuildUserUID},
				Group: &llb.UserOpt{UID: BuildUserGID},
			},
		}),
		llb.WithCustomNamef("[git-checkout] copy to %s", destPath),
	)

	// Handle expected-commit verification and cherry-picks if needed
	// These require shell commands since BuildKit's Git doesn't support them directly
	if expectedCommit != "" && branch != "" {
		// If we have a branch and expected-commit, we may need to reset to the commit
		state = state.Run(
			llb.Args([]string{"/bin/sh", "-c", fmt.Sprintf(`
cd %s
current=$(git rev-parse HEAD)
if [ "$current" != "%s" ]; then
    echo "[git-checkout] resetting to expected commit %s"
    git reset --hard %s
fi
`, destPath, expectedCommit, expectedCommit, expectedCommit)}),
			llb.Dir(destPath),
			llb.User(BuildUserName),
			llb.WithCustomNamef("[git-checkout] verify commit %s", expectedCommit[:12]),
		).Root()
	}

	// Handle cherry-picks if specified
	cherryPicks := with["cherry-picks"]
	if cherryPicks != "" {
		// Cherry-picks require running git commands, so we use a shell
		state = state.Run(
			llb.Args([]string{"/bin/sh", "-c", fmt.Sprintf(`
cd %s
git config user.name "Melange Build"
git config user.email "melange-build@cgr.dev"
# Process cherry-picks
echo '%s' | while IFS= read -r line; do
    line="${line%%#*}"
    [ -z "$line" ] && continue
    echo "$line" | grep -q ':' || continue
    hash="${line%%:*}"
    hash="${hash##*/}"
    echo "[git-checkout] cherry-picking $hash"
    git cherry-pick -x "$hash" || exit 1
done
`, destPath, cherryPicks)}),
			llb.Dir(destPath),
			llb.User(BuildUserName),
			llb.WithCustomName("[git-checkout] apply cherry-picks"),
		).Root()
	}

	return state, nil
}

// buildFetch implements the fetch pipeline using native LLB operations.
// This uses BuildKit's llb.HTTP() source operation for efficient, cached downloads.
//
// Note: This implementation requires a checksum (sha256 or sha512) to leverage
// BuildKit's content-addressable caching. If expected-none is set, this function
// returns ErrFetchNeedsChecksum to signal that the shell fallback should be used.
func buildFetch(base llb.State, p *config.Pipeline) (llb.State, error) {
	with := p.With

	// Required: URI to fetch
	uri := with["uri"]
	if uri == "" {
		return llb.State{}, fmt.Errorf("fetch: uri is required")
	}

	// Check for expected checksum
	expectedSHA256 := with["expected-sha256"]
	expectedSHA512 := with["expected-sha512"]
	expectedNone := with["expected-none"]

	// expected-none is not supported - a checksum is required
	if expectedNone != "" {
		return llb.State{}, fmt.Errorf("fetch: expected-none is not supported, a checksum (expected-sha256 or expected-sha512) is required")
	}

	// BuildKit's HTTP operation only supports sha256 checksums
	// Return a special error to signal fallback to shell implementation for sha512
	if expectedSHA512 != "" {
		return llb.State{}, ErrFetchSHA512NotSupported
	}

	if expectedSHA256 == "" {
		return llb.State{}, fmt.Errorf("fetch: expected-sha256 is required for native LLB (sha512 and expected-none use shell fallback)")
	}

	// Optional: extract settings
	extract := with["extract"]
	if extract == "" {
		extract = "true"
	}

	stripComponents := with["strip-components"]
	if stripComponents == "" {
		stripComponents = "1"
	}

	directory := with["directory"]
	if directory == "" {
		directory = "."
	}

	deleteFetch := with["delete"]
	if deleteFetch == "" {
		deleteFetch = "false"
	}

	// Build HTTP options
	var httpOpts []llb.HTTPOption

	// Add checksum for verification and caching (sha256 only - sha512 uses shell fallback)
	httpOpts = append(httpOpts, llb.Checksum(digest.NewDigestFromEncoded(digest.SHA256, expectedSHA256)))

	// Set ownership
	httpOpts = append(httpOpts, llb.Chown(BuildUserUID, BuildUserGID))

	// Custom name for progress display
	httpOpts = append(httpOpts, llb.WithCustomNamef("[fetch] download %s", uri))

	// Create the HTTP source
	httpState := llb.HTTP(uri, httpOpts...)

	// Determine the full destination path
	destPath := directory
	if !filepath.IsAbs(destPath) {
		destPath = filepath.Join(DefaultWorkDir, destPath)
	}

	// Copy the downloaded file to a temp location in the workspace
	// The file will be at /fetched-file in the httpState
	downloadPath := filepath.Join(DefaultWorkDir, ".melange-fetch-temp")
	state := base.File(
		llb.Copy(httpState, "/", downloadPath, &llb.CopyInfo{
			ChownOpt: &llb.ChownOpt{
				User:  &llb.UserOpt{UID: BuildUserUID},
				Group: &llb.UserOpt{UID: BuildUserGID},
			},
		}),
		llb.WithCustomName("[fetch] stage download"),
	)

	// Extract if requested
	if extract == "true" {
		stripInt, _ := strconv.Atoi(stripComponents)
		state = state.Run(
			llb.Args([]string{"/bin/sh", "-c", fmt.Sprintf(`
mkdir -p %s
tar -x --strip-components=%d --no-same-owner -C %s -f %s
echo "[fetch] extracted to %s"
`, destPath, stripInt, destPath, downloadPath, destPath)}),
			llb.Dir(DefaultWorkDir),
			llb.User(BuildUserName),
			llb.WithCustomNamef("[fetch] extract to %s", destPath),
		).Root()
	} else {
		// Just copy the file to the destination
		state = state.Run(
			llb.Args([]string{"/bin/sh", "-c", fmt.Sprintf(`
mkdir -p %s
cp %s %s/
`, destPath, downloadPath, destPath)}),
			llb.Dir(DefaultWorkDir),
			llb.User(BuildUserName),
			llb.WithCustomNamef("[fetch] copy to %s", destPath),
		).Root()
	}

	// Delete the temp file only if explicitly requested (matches original fetch.yaml behavior)
	if deleteFetch == "true" {
		state = state.Run(
			llb.Args([]string{"/bin/sh", "-c", fmt.Sprintf("rm -f %s", downloadPath)}),
			llb.Dir(DefaultWorkDir),
			llb.User(BuildUserName),
			llb.WithCustomName("[fetch] cleanup"),
		).Root()
	}

	return state, nil
}
