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

// BuildKitContainer represents a running BuildKit container.
type BuildKitContainer struct {
	container testcontainers.Container
	Addr      string
}

// StartBuildKit starts a BuildKit container using testcontainers.
func StartBuildKit(t *testing.T, ctx context.Context) *BuildKitContainer {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "moby/buildkit:latest",
		ExposedPorts: []string{"1234/tcp"},
		Privileged:   true,
		Cmd:          []string{"--addr", "tcp://0.0.0.0:1234"},
		WaitingFor:   wait.ForLog("running server").WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "should start BuildKit container")

	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate BuildKit container: %v", err)
		}
	})

	host, err := container.Host(ctx)
	require.NoError(t, err)

	port, err := container.MappedPort(ctx, "1234")
	require.NoError(t, err)

	addr := fmt.Sprintf("tcp://%s:%s", host, port.Port())
	t.Logf("BuildKit running at %s", addr)

	return &BuildKitContainer{
		container: container,
		Addr:      addr,
	}
}

// Logs returns the container logs.
func (b *BuildKitContainer) Logs(ctx context.Context) (string, error) {
	reader, err := b.container.Logs(ctx)
	if err != nil {
		return "", err
	}
	defer reader.Close()

	buf := make([]byte, 64*1024)
	n, _ := reader.Read(buf)
	return string(buf[:n]), nil
}
