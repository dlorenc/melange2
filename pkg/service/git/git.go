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

// Package git provides git repository cloning and config file discovery
// for multi-package builds.
package git

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dlorenc/melange2/pkg/service/types"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// Source represents a git repository source for package configs.
type Source struct {
	// Repository is the git repository URL.
	Repository string

	// Ref is the branch, tag, or commit to checkout (default: HEAD).
	Ref string

	// Pattern is the glob pattern for config files (default: "*.yaml").
	Pattern string

	// Path is the subdirectory within the repo to search.
	Path string
}

// NewSourceFromGitSource creates a Source from a GitSource type.
func NewSourceFromGitSource(gs *types.GitSource) *Source {
	if gs == nil {
		return nil
	}
	return &Source{
		Repository: gs.Repository,
		Ref:        gs.Ref,
		Pattern:    gs.Pattern,
		Path:       gs.Path,
	}
}

// Clone clones the repository and returns the temp directory path and cleanup function.
func (s *Source) Clone(ctx context.Context) (string, func(), error) {
	tmpDir, err := os.MkdirTemp("", "melange-git-*")
	if err != nil {
		return "", nil, fmt.Errorf("creating temp directory: %w", err)
	}
	cleanup := func() { os.RemoveAll(tmpDir) }

	cloneOpts := &git.CloneOptions{
		URL:   s.Repository,
		Depth: 1,
	}

	// Handle ref (branch, tag, or commit)
	if s.Ref != "" {
		// Try as a branch first
		cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(s.Ref)
		cloneOpts.SingleBranch = true
	}

	repo, err := git.PlainCloneContext(ctx, tmpDir, false, cloneOpts)
	if err != nil {
		// If branch failed, try as tag
		if s.Ref != "" {
			cloneOpts.ReferenceName = plumbing.NewTagReferenceName(s.Ref)
			repo, err = git.PlainCloneContext(ctx, tmpDir, false, cloneOpts)
		}
		if err != nil {
			cleanup()
			return "", nil, fmt.Errorf("cloning repository %s: %w", s.Repository, err)
		}
	}

	// If a specific ref was provided, try to checkout the commit
	if s.Ref != "" && repo != nil {
		w, err := repo.Worktree()
		if err == nil {
			// Try to resolve as a commit hash
			hash, err := repo.ResolveRevision(plumbing.Revision(s.Ref))
			if err == nil {
				_ = w.Checkout(&git.CheckoutOptions{
					Hash: *hash,
				})
			}
		}
	}

	return tmpDir, cleanup, nil
}

// FindConfigs finds all config files matching the pattern in the repository.
func (s *Source) FindConfigs(ctx context.Context, repoDir string) ([]string, error) {
	searchPath := repoDir
	if s.Path != "" {
		searchPath = filepath.Join(repoDir, s.Path)
	}

	pattern := s.Pattern
	if pattern == "" {
		pattern = "*.yaml"
	}

	matches, err := filepath.Glob(filepath.Join(searchPath, pattern))
	if err != nil {
		return nil, fmt.Errorf("finding configs with pattern %s: %w", pattern, err)
	}

	return matches, nil
}

// LoadConfigs clones the repository and returns the content of all matching config files.
func (s *Source) LoadConfigs(ctx context.Context) ([]string, error) {
	repoDir, cleanup, err := s.Clone(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	paths, err := s.FindConfigs(ctx, repoDir)
	if err != nil {
		return nil, err
	}

	if len(paths) == 0 {
		pattern := s.Pattern
		if pattern == "" {
			pattern = "*.yaml"
		}
		return nil, fmt.Errorf("no config files found matching pattern %s in %s", pattern, s.Path)
	}

	configs := make([]string, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		configs = append(configs, string(data))
	}

	return configs, nil
}

// ValidateSource validates that the git source has required fields.
func ValidateSource(gs *types.GitSource) error {
	if gs == nil {
		return fmt.Errorf("git source is nil")
	}
	if gs.Repository == "" {
		return fmt.Errorf("git source repository is required")
	}
	return nil
}
