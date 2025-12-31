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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// RegistryContainer represents a running Docker registry container.
type RegistryContainer struct {
	container testcontainers.Container
	Addr      string
}

// StartRegistry starts a Docker registry container using testcontainers.
func StartRegistry(t *testing.T, ctx context.Context) *RegistryContainer {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "registry:2",
		ExposedPorts: []string{"5000/tcp"},
		WaitingFor:   wait.ForHTTP("/v2/").WithPort("5000/tcp").WithStartupTimeout(30 * time.Second),
		Env: map[string]string{
			"REGISTRY_STORAGE_DELETE_ENABLED": "true",
		},
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "should start registry container")

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
	t.Logf("Registry running at %s", addr)

	return &RegistryContainer{
		container: container,
		Addr:      addr,
	}
}
