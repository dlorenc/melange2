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

package harness

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// RegistryContainer represents a running Zot registry container.
type RegistryContainer struct {
	container testcontainers.Container
	Addr      string
}

// zotConfig is the Zot configuration for e2e tests.
// GC is enabled with a 2-hour delay to match production settings.
// The "docker2s2" compat mode enables Docker Manifest v2 Schema 2 support.
const zotConfig = `{
  "distSpecVersion": "1.1.0",
  "storage": {
    "rootDirectory": "/var/lib/registry",
    "gc": true,
    "gcDelay": "2h",
    "gcInterval": "1h"
  },
  "http": {
    "address": "0.0.0.0",
    "port": "5000",
    "compat": ["docker2s2"]
  },
  "log": {
    "level": "warn"
  }
}`

// StartRegistry starts a Zot registry container using testcontainers.
// Zot is an OCI-native registry with built-in garbage collection.
func StartRegistry(t *testing.T, ctx context.Context) *RegistryContainer {
	t.Helper()

	// Create a temp directory for the config file
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "config.json")
	err := os.WriteFile(configPath, []byte(zotConfig), 0600)
	require.NoError(t, err, "should write zot config")

	req := testcontainers.ContainerRequest{
		Image:        "ghcr.io/project-zot/zot-linux-amd64:latest",
		ExposedPorts: []string{"5000/tcp"},
		Cmd:          []string{"serve", "/etc/zot/config.json"},
		WaitingFor:   wait.ForHTTP("/v2/").WithPort("5000/tcp").WithStartupTimeout(30 * time.Second),
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      configPath,
				ContainerFilePath: "/etc/zot/config.json",
				FileMode:          0600,
			},
		},
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "should start zot registry container")

	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate registry container: %v", err)
		}
	})

	host, err := container.Host(ctx)
	require.NoError(t, err)

	port, err := container.MappedPort(ctx, "5000")
	require.NoError(t, err)

	addr := fmt.Sprintf("%s:%s", host, port.Port())
	t.Logf("Zot registry running at %s", addr)

	return &RegistryContainer{
		container: container,
		Addr:      addr,
	}
}
