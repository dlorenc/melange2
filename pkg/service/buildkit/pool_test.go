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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewPool(t *testing.T) {
	tests := []struct {
		name     string
		backends []Backend
		wantErr  bool
	}{
		{
			name:     "empty backends",
			backends: []Backend{},
			wantErr:  true,
		},
		{
			name: "missing addr",
			backends: []Backend{
				{Arch: "x86_64"},
			},
			wantErr: true,
		},
		{
			name: "missing arch",
			backends: []Backend{
				{Addr: "tcp://localhost:1234"},
			},
			wantErr: true,
		},
		{
			name: "valid single backend",
			backends: []Backend{
				{Addr: "tcp://localhost:1234", Arch: "x86_64"},
			},
			wantErr: false,
		},
		{
			name: "valid multiple backends",
			backends: []Backend{
				{Addr: "tcp://amd64-1:1234", Arch: "x86_64", Labels: map[string]string{"tier": "standard"}},
				{Addr: "tcp://amd64-2:1234", Arch: "x86_64", Labels: map[string]string{"tier": "high-memory"}},
				{Addr: "tcp://arm64-1:1234", Arch: "aarch64", Labels: map[string]string{"tier": "standard"}},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool, err := NewPool(tt.backends)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, pool)
		})
	}
}

func TestPoolSelect(t *testing.T) {
	backends := []Backend{
		{Addr: "tcp://amd64-std:1234", Arch: "x86_64", Labels: map[string]string{"tier": "standard"}},
		{Addr: "tcp://amd64-high:1234", Arch: "x86_64", Labels: map[string]string{"tier": "high-memory"}},
		{Addr: "tcp://arm64-std:1234", Arch: "aarch64", Labels: map[string]string{"tier": "standard"}},
	}
	pool, err := NewPool(backends)
	require.NoError(t, err)

	tests := []struct {
		name     string
		arch     string
		selector map[string]string
		wantAddr string
		wantErr  bool
	}{
		{
			name:     "select by arch only",
			arch:     "aarch64",
			selector: nil,
			wantAddr: "tcp://arm64-std:1234",
			wantErr:  false,
		},
		{
			name:     "select by arch and tier",
			arch:     "x86_64",
			selector: map[string]string{"tier": "high-memory"},
			wantAddr: "tcp://amd64-high:1234",
			wantErr:  false,
		},
		{
			name:     "no matching arch",
			arch:     "riscv64",
			selector: nil,
			wantErr:  true,
		},
		{
			name:     "no matching selector",
			arch:     "x86_64",
			selector: map[string]string{"tier": "nonexistent"},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, err := pool.Select(tt.arch, tt.selector)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantAddr, backend.Addr)
		})
	}
}

func TestPoolSelectRoundRobin(t *testing.T) {
	backends := []Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64", Labels: map[string]string{}},
		{Addr: "tcp://amd64-2:1234", Arch: "x86_64", Labels: map[string]string{}},
		{Addr: "tcp://amd64-3:1234", Arch: "x86_64", Labels: map[string]string{}},
	}
	pool, err := NewPool(backends)
	require.NoError(t, err)

	// Select multiple times and verify round-robin
	addrs := make(map[string]int)
	for i := 0; i < 9; i++ {
		backend, err := pool.Select("x86_64", nil)
		require.NoError(t, err)
		addrs[backend.Addr]++
	}

	// Each backend should be selected 3 times
	require.Equal(t, 3, addrs["tcp://amd64-1:1234"])
	require.Equal(t, 3, addrs["tcp://amd64-2:1234"])
	require.Equal(t, 3, addrs["tcp://amd64-3:1234"])
}

func TestPoolFromConfig(t *testing.T) {
	configContent := `
backends:
  - addr: tcp://amd64-1:1234
    arch: x86_64
    labels:
      tier: standard
  - addr: tcp://arm64-1:1234
    arch: aarch64
    labels:
      tier: standard
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "backends.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	pool, err := NewPoolFromConfig(configPath)
	require.NoError(t, err)
	require.Len(t, pool.List(), 2)

	archs := pool.Architectures()
	require.Len(t, archs, 2)
}

func TestPoolFromSingleAddr(t *testing.T) {
	pool, err := NewPoolFromSingleAddr("tcp://localhost:1234", "")
	require.NoError(t, err)

	backends := pool.List()
	require.Len(t, backends, 1)
	require.Equal(t, "tcp://localhost:1234", backends[0].Addr)
	require.Equal(t, "x86_64", backends[0].Arch) // default arch
}

func TestPoolListByArch(t *testing.T) {
	backends := []Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
		{Addr: "tcp://amd64-2:1234", Arch: "x86_64"},
		{Addr: "tcp://arm64-1:1234", Arch: "aarch64"},
	}
	pool, err := NewPool(backends)
	require.NoError(t, err)

	amd64 := pool.ListByArch("x86_64")
	require.Len(t, amd64, 2)

	arm64 := pool.ListByArch("aarch64")
	require.Len(t, arm64, 1)

	riscv := pool.ListByArch("riscv64")
	require.Len(t, riscv, 0)
}

func TestPoolAdd(t *testing.T) {
	pool, err := NewPool([]Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	})
	require.NoError(t, err)
	require.Len(t, pool.List(), 1)

	// Add a new backend
	err = pool.Add(Backend{
		Addr:   "tcp://arm64-1:1234",
		Arch:   "aarch64",
		Labels: map[string]string{"tier": "standard"},
	})
	require.NoError(t, err)
	require.Len(t, pool.List(), 2)

	// Verify new architecture is available
	archs := pool.Architectures()
	require.Len(t, archs, 2)

	// Should be able to select the new backend
	backend, err := pool.Select("aarch64", nil)
	require.NoError(t, err)
	require.Equal(t, "tcp://arm64-1:1234", backend.Addr)
}

func TestPoolAddValidation(t *testing.T) {
	pool, err := NewPool([]Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	})
	require.NoError(t, err)

	// Missing addr
	err = pool.Add(Backend{Arch: "x86_64"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "addr is required")

	// Missing arch
	err = pool.Add(Backend{Addr: "tcp://new:1234"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "arch is required")

	// Duplicate addr
	err = pool.Add(Backend{Addr: "tcp://amd64-1:1234", Arch: "x86_64"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}

func TestPoolRemove(t *testing.T) {
	pool, err := NewPool([]Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
		{Addr: "tcp://amd64-2:1234", Arch: "x86_64"},
		{Addr: "tcp://arm64-1:1234", Arch: "aarch64"},
	})
	require.NoError(t, err)
	require.Len(t, pool.List(), 3)

	// Remove a backend
	err = pool.Remove("tcp://amd64-2:1234")
	require.NoError(t, err)
	require.Len(t, pool.List(), 2)

	// Verify it's gone
	for _, b := range pool.List() {
		require.NotEqual(t, "tcp://amd64-2:1234", b.Addr)
	}
}

func TestPoolRemoveValidation(t *testing.T) {
	pool, err := NewPool([]Backend{
		{Addr: "tcp://amd64-1:1234", Arch: "x86_64"},
	})
	require.NoError(t, err)

	// Cannot remove last backend
	err = pool.Remove("tcp://amd64-1:1234")
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot remove the last backend")

	// Add another backend first
	err = pool.Add(Backend{Addr: "tcp://amd64-2:1234", Arch: "x86_64"})
	require.NoError(t, err)

	// Non-existent backend (need 2+ backends to test this)
	err = pool.Remove("tcp://nonexistent:1234")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")

	// Now can remove one of the backends
	err = pool.Remove("tcp://amd64-1:1234")
	require.NoError(t, err)
}
