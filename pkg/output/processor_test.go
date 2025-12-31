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

package output

import (
	"context"
	"testing"
	"time"

	apkofs "chainguard.dev/apko/pkg/apk/fs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dlorenc/melange2/pkg/config"
)

func TestNewProcessor(t *testing.T) {
	p := NewProcessor()
	require.NotNil(t, p)

	// Default options should all be false (nothing skipped)
	assert.False(t, p.Options.SkipLint)
	assert.False(t, p.Options.SkipLicenseCheck)
	assert.False(t, p.Options.SkipSBOM)
	assert.False(t, p.Options.SkipEmit)
	assert.False(t, p.Options.SkipIndex)
}

func TestPkgFromSub(t *testing.T) {
	t.Run("converts subpackage to package", func(t *testing.T) {
		sub := &config.Subpackage{
			Name:        "mylib-dev",
			Description: "Development files for mylib",
			URL:         "https://example.com/mylib",
			Dependencies: config.Dependencies{
				Runtime: []string{"mylib"},
			},
		}

		pkg := pkgFromSub(sub)

		require.NotNil(t, pkg)
		assert.Equal(t, "mylib-dev", pkg.Name)
		assert.Equal(t, "Development files for mylib", pkg.Description)
		assert.Equal(t, "https://example.com/mylib", pkg.URL)
		assert.Equal(t, []string{"mylib"}, pkg.Dependencies.Runtime)
	})

	t.Run("handles empty subpackage", func(t *testing.T) {
		sub := &config.Subpackage{
			Name: "minimal-pkg",
		}

		pkg := pkgFromSub(sub)

		require.NotNil(t, pkg)
		assert.Equal(t, "minimal-pkg", pkg.Name)
		assert.Empty(t, pkg.Description)
		assert.Empty(t, pkg.URL)
	})

	t.Run("copies scriptlets", func(t *testing.T) {
		sub := &config.Subpackage{
			Name: "with-scriptlets",
			Scriptlets: &config.Scriptlets{
				PreInstall: "echo pre",
			},
		}

		pkg := pkgFromSub(sub)

		require.NotNil(t, pkg.Scriptlets)
		assert.Equal(t, "echo pre", pkg.Scriptlets.PreInstall)
	})
}

func TestProcessOptions(t *testing.T) {
	t.Run("all options default to false", func(t *testing.T) {
		opts := ProcessOptions{}

		assert.False(t, opts.SkipLint)
		assert.False(t, opts.SkipLicenseCheck)
		assert.False(t, opts.SkipSBOM)
		assert.False(t, opts.SkipEmit)
		assert.False(t, opts.SkipIndex)
	})

	t.Run("options can be set independently", func(t *testing.T) {
		opts := ProcessOptions{
			SkipLint:   true,
			SkipEmit:   true,
			SkipIndex:  false,
			SkipSBOM:   false,
		}

		assert.True(t, opts.SkipLint)
		assert.False(t, opts.SkipLicenseCheck)
		assert.False(t, opts.SkipSBOM)
		assert.True(t, opts.SkipEmit)
		assert.False(t, opts.SkipIndex)
	})
}

func TestLintConfig(t *testing.T) {
	t.Run("empty config", func(t *testing.T) {
		cfg := LintConfig{}

		assert.Empty(t, cfg.Require)
		assert.Empty(t, cfg.Warn)
		assert.False(t, cfg.PersistResults)
		assert.Empty(t, cfg.OutDir)
	})

	t.Run("configured lint settings", func(t *testing.T) {
		cfg := LintConfig{
			Require:        []string{"dev", "opt"},
			Warn:           []string{"usrlocal"},
			PersistResults: true,
			OutDir:         "/tmp/lint-results",
		}

		assert.Len(t, cfg.Require, 2)
		assert.Len(t, cfg.Warn, 1)
		assert.True(t, cfg.PersistResults)
		assert.Equal(t, "/tmp/lint-results", cfg.OutDir)
	})
}

func TestProcessInput(t *testing.T) {
	t.Run("all fields populated", func(t *testing.T) {
		cfg := &config.Configuration{
			Package: config.Package{
				Name:    "test-pkg",
				Version: "1.0.0",
			},
		}
		now := time.Now()

		input := &ProcessInput{
			Configuration:   cfg,
			WorkspaceDir:    "/workspace",
			OutDir:          "/output",
			Arch:            "x86_64",
			SourceDateEpoch: now,
		}

		assert.Equal(t, cfg, input.Configuration)
		assert.Equal(t, "/workspace", input.WorkspaceDir)
		assert.Equal(t, "/output", input.OutDir)
		assert.Equal(t, "x86_64", input.Arch)
		assert.Equal(t, now, input.SourceDateEpoch)
	})
}

func TestProcessor_ProcessSkipsAll(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	cfg := &config.Configuration{
		Package: config.Package{
			Name:    "test-package",
			Version: "1.0.0",
		},
	}

	wsFS := apkofs.DirFS(ctx, tmpDir)

	processor := &Processor{
		Options: ProcessOptions{
			SkipLint:         true,
			SkipLicenseCheck: true,
			SkipSBOM:         true,
			SkipEmit:         true,
			SkipIndex:        true,
		},
	}

	input := &ProcessInput{
		Configuration:   cfg,
		WorkspaceDir:    tmpDir,
		WorkspaceDirFS:  wsFS,
		OutDir:          tmpDir,
		Arch:            "x86_64",
		SourceDateEpoch: time.Now(),
	}

	// Should succeed when everything is skipped
	err := processor.Process(ctx, input)
	assert.NoError(t, err)
}

func TestProcessor_ProcessWithNilGenerator(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	cfg := &config.Configuration{
		Package: config.Package{
			Name:    "test-package",
			Version: "1.0.0",
		},
	}

	wsFS := apkofs.DirFS(ctx, tmpDir)

	processor := &Processor{
		Options: ProcessOptions{
			SkipLint:         true,
			SkipLicenseCheck: true,
			SkipSBOM:         false, // Don't skip SBOM
			SkipEmit:         true,
			SkipIndex:        true,
		},
		SBOM: SBOMConfig{
			Generator: nil, // Nil generator should be handled gracefully
		},
	}

	input := &ProcessInput{
		Configuration:   cfg,
		WorkspaceDir:    tmpDir,
		WorkspaceDirFS:  wsFS,
		OutDir:          tmpDir,
		Arch:            "x86_64",
		SourceDateEpoch: time.Now(),
	}

	// Should succeed with nil generator
	err := processor.Process(ctx, input)
	assert.NoError(t, err)
}

func TestProcessor_ProcessWithNilEmitter(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	cfg := &config.Configuration{
		Package: config.Package{
			Name:    "test-package",
			Version: "1.0.0",
		},
	}

	wsFS := apkofs.DirFS(ctx, tmpDir)

	processor := &Processor{
		Options: ProcessOptions{
			SkipLint:         true,
			SkipLicenseCheck: true,
			SkipSBOM:         true,
			SkipEmit:         false, // Don't skip emit
			SkipIndex:        true,
		},
		Emit: EmitConfig{
			Emitter: nil, // Nil emitter should be handled gracefully
		},
	}

	input := &ProcessInput{
		Configuration:   cfg,
		WorkspaceDir:    tmpDir,
		WorkspaceDirFS:  wsFS,
		OutDir:          tmpDir,
		Arch:            "x86_64",
		SourceDateEpoch: time.Now(),
	}

	// Should succeed with nil emitter
	err := processor.Process(ctx, input)
	assert.NoError(t, err)
}

func TestProcessor_EmitterCalled(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	cfg := &config.Configuration{
		Package: config.Package{
			Name:    "main-package",
			Version: "2.0.0",
		},
		Subpackages: []config.Subpackage{
			{Name: "main-package-dev"},
			{Name: "main-package-doc"},
		},
	}

	wsFS := apkofs.DirFS(ctx, tmpDir)

	emittedPkgs := []string{}
	processor := &Processor{
		Options: ProcessOptions{
			SkipLint:         true,
			SkipLicenseCheck: true,
			SkipSBOM:         true,
			SkipEmit:         false,
			SkipIndex:        true,
		},
		Emit: EmitConfig{
			Emitter: func(ctx context.Context, pkg *config.Package) error {
				emittedPkgs = append(emittedPkgs, pkg.Name)
				return nil
			},
		},
	}

	input := &ProcessInput{
		Configuration:   cfg,
		WorkspaceDir:    tmpDir,
		WorkspaceDirFS:  wsFS,
		OutDir:          tmpDir,
		Arch:            "x86_64",
		SourceDateEpoch: time.Now(),
	}

	err := processor.Process(ctx, input)
	require.NoError(t, err)

	// Should have emitted main package + 2 subpackages
	assert.Len(t, emittedPkgs, 3)
	assert.Contains(t, emittedPkgs, "main-package")
	assert.Contains(t, emittedPkgs, "main-package-dev")
	assert.Contains(t, emittedPkgs, "main-package-doc")
}

func TestMelangeOutputDirName(t *testing.T) {
	assert.Equal(t, "melange-out", melangeOutputDirName)
}
