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

// ErrGitCheckoutNoRef is returned when git-checkout is called without a branch, tag, or expected-commit,
// indicating that the shell fallback should be used since BuildKit's llb.Git() requires an explicit ref.
var ErrGitCheckoutNoRef = errors.New("git-checkout without branch/tag/expected-commit requires shell fallback (BuildKit Git requires explicit ref)")

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
//
// Like the shell implementation, the git clone is mounted at a temporary location
// and then tar-copied into the destination. This ensures existing files in the
// destination (like user-provided source files) are preserved, not overwritten.
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

	// If no ref specified, fall back to shell implementation
	// BuildKit's llb.Git() requires an explicit ref and doesn't support "HEAD"
	if ref == "" {
		return llb.State{}, ErrGitCheckoutNoRef
	}

	// Build git options
	var gitOpts []llb.GitOption

	// Always keep the .git directory to match shell implementation behavior.
	// Many builds rely on checking .git existence or running git commands.
	// BuildKit's Git() doesn't have a direct depth option - it always does a
	// shallow clone unless KeepGitDir is set, in which case it preserves .git.
	gitOpts = append(gitOpts, llb.KeepGitDir())

	// Custom name for progress display
	gitOpts = append(gitOpts, llb.WithCustomNamef("[git] clone %s@%s", repo, ref))

	// Create the git source
	gitState := llb.Git(repo, ref, gitOpts...)

	// Determine the full destination path
	destPath := dest
	if !filepath.IsAbs(destPath) {
		destPath = filepath.Join(DefaultWorkDir, destPath)
	}

	// Mount the git clone at a temporary location and use tar to copy to destination.
	// This matches the shell implementation's behavior of:
	//   tar -c . | tar -C "$dest_fullpath" -x --no-same-owner
	// This ensures existing files in the destination (like user-provided source files)
	// are preserved, not deleted or overwritten (unless they conflict with git files).
	state := base.Run(
		llb.Args([]string{"/bin/sh", "-c", fmt.Sprintf(`
mkdir -p %s
cd /mnt/gitclone && tar -c . | tar -C %s -x --no-same-owner
chown -R %d:%d %s
`, destPath, destPath, BuildUserUID, BuildUserGID, destPath)}),
		llb.AddMount("/mnt/gitclone", gitState, llb.Readonly),
		llb.WithCustomNamef("[git-checkout] clone and copy to %s", destPath),
	).Root()

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

// getCompressionFlag returns the tar flag needed for the given URI based on file extension.
// Returns empty string if no special flag is needed (e.g., for .tar or unknown formats).
func getCompressionFlag(uri string) string {
	switch {
	case filepath.Ext(uri) == ".bz2" || filepath.Ext(uri) == ".tbz2" || filepath.Ext(uri) == ".tbz":
		return "-j"
	case filepath.Ext(uri) == ".gz" || filepath.Ext(uri) == ".tgz":
		return "-z"
	case filepath.Ext(uri) == ".xz" || filepath.Ext(uri) == ".txz":
		return "-J"
	case filepath.Ext(uri) == ".zst" || filepath.Ext(uri) == ".tzst":
		return "--zstd"
	case filepath.Ext(uri) == ".lz":
		return "--lzip"
	case filepath.Ext(uri) == ".lzma" || filepath.Ext(uri) == ".tlz":
		return "--lzma"
	default:
		return ""
	}
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

	// Get the basename from the URI for the downloaded filename
	// This matches the original fetch.yaml behavior: bn=$(basename ${{inputs.uri}})
	basename := filepath.Base(uri)

	// Build HTTP options
	var httpOpts []llb.HTTPOption

	// Add checksum for verification and caching (sha256 only - sha512 uses shell fallback)
	httpOpts = append(httpOpts, llb.Checksum(digest.NewDigestFromEncoded(digest.SHA256, expectedSHA256)))

	// Set ownership
	httpOpts = append(httpOpts, llb.Chown(BuildUserUID, BuildUserGID))

	// Set the filename to the original basename from the URI
	httpOpts = append(httpOpts, llb.Filename(basename))

	// Custom name for progress display
	httpOpts = append(httpOpts, llb.WithCustomNamef("[fetch] download %s", uri))

	// Create the HTTP source
	httpState := llb.HTTP(uri, httpOpts...)

	// Determine the full destination path
	destPath := directory
	if !filepath.IsAbs(destPath) {
		destPath = filepath.Join(DefaultWorkDir, destPath)
	}

	// The downloaded file path in the workspace (matches original fetch.yaml behavior)
	downloadPath := filepath.Join(DefaultWorkDir, basename)

	// Mount the HTTP source and copy the file to the workspace in a single Run command.
	// This approach is more reliable than llb.File(llb.Copy(...)) because it ensures
	// the file operation happens within the context of the existing filesystem.
	state := base.Run(
		llb.Args([]string{"/bin/sh", "-c", fmt.Sprintf("mkdir -p %s && cp /mnt/fetch/%s %s",
			DefaultWorkDir, basename, downloadPath)}),
		llb.AddMount("/mnt/fetch", httpState, llb.Readonly),
		llb.Dir(DefaultWorkDir),
		llb.User(BuildUserName),
		llb.WithCustomName("[fetch] stage download"),
	).Root()

	// Extract if requested
	if extract == "true" {
		stripInt, _ := strconv.Atoi(stripComponents)
		compressionFlag := getCompressionFlag(uri)
		tarCmd := fmt.Sprintf("tar -xf %s %s --strip-components=%d --no-same-owner -C %s",
			downloadPath, compressionFlag, stripInt, destPath)
		state = state.Run(
			llb.Args([]string{"/bin/sh", "-c", fmt.Sprintf(`
mkdir -p %s
%s
`, destPath, tarCmd)}),
			llb.Dir(DefaultWorkDir),
			llb.User(BuildUserName),
			llb.WithCustomNamef("[fetch] extract to %s", destPath),
		).Root()

		// When extracting, delete the archive unless delete is explicitly false
		// This matches the original behavior where the tarball is consumed
		if deleteFetch != "false" {
			state = state.Run(
				llb.Args([]string{"/bin/sh", "-c", fmt.Sprintf("rm -f %s", downloadPath)}),
				llb.Dir(DefaultWorkDir),
				llb.User(BuildUserName),
				llb.WithCustomName("[fetch] cleanup"),
			).Root()
		}
	} else if destPath != DefaultWorkDir {
		// When not extracting and directory differs from default, move the file there
		state = state.Run(
			llb.Args([]string{"/bin/sh", "-c", fmt.Sprintf(`
mkdir -p %s
mv %s %s/
`, destPath, downloadPath, destPath)}),
			llb.Dir(DefaultWorkDir),
			llb.User(BuildUserName),
			llb.WithCustomNamef("[fetch] move to %s", destPath),
		).Root()
	}
	// When not extracting and directory is default (.), file is already in place with correct name

	return state, nil
}
