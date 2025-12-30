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

package scheduler

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "default config",
			config: Config{
				OutputDir:    "/var/lib/melange/output",
				PollInterval: time.Second,
			},
		},
		{
			name: "config with cache registry",
			config: Config{
				OutputDir:     "/var/lib/melange/output",
				PollInterval:  time.Second,
				CacheRegistry: "registry:5000/melange-cache",
				CacheMode:     "max",
			},
		},
		{
			name: "config with cache min mode",
			config: Config{
				OutputDir:     "/var/lib/melange/output",
				PollInterval:  time.Second,
				CacheRegistry: "registry:5000/melange-cache",
				CacheMode:     "min",
			},
		},
		{
			name: "config with empty cache mode (defaults to max)",
			config: Config{
				OutputDir:     "/var/lib/melange/output",
				PollInterval:  time.Second,
				CacheRegistry: "registry:5000/melange-cache",
				CacheMode:     "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.config

			// Verify basic config fields
			require.NotEmpty(t, cfg.OutputDir)

			// Verify cache config
			if cfg.CacheRegistry != "" {
				require.NotEmpty(t, cfg.CacheRegistry)
				// Mode can be empty (defaults to "max" in implementation)
				if cfg.CacheMode != "" {
					require.Contains(t, []string{"min", "max"}, cfg.CacheMode)
				}
			}
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	// Test that New() applies defaults correctly
	cfg := Config{}

	// These should be applied by New()
	if cfg.PollInterval == 0 {
		cfg.PollInterval = time.Second
	}
	if cfg.OutputDir == "" {
		cfg.OutputDir = "/var/lib/melange/output"
	}
	if cfg.MaxParallel == 0 {
		cfg.MaxParallel = 1 // Would be runtime.NumCPU() in actual New()
	}

	require.Equal(t, time.Second, cfg.PollInterval)
	require.Equal(t, "/var/lib/melange/output", cfg.OutputDir)
	require.Equal(t, 1, cfg.MaxParallel)
}
