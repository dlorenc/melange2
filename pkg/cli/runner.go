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

package cli

import (
	"context"
	"fmt"
	"runtime"

	"chainguard.dev/melange/pkg/container"
	"chainguard.dev/melange/pkg/container/docker"
)

// getRunner returns a container runner for the test and rebuild commands.
// These commands still use the legacy runner pattern.
// The build command uses BuildKit instead.
func getRunner(ctx context.Context, runner string, remove bool) (container.Runner, error) {
	if runner != "" {
		switch runner {
		case "bubblewrap":
			return container.BubblewrapRunner(remove), nil
		case "qemu":
			return container.QemuRunner(), nil
		case "docker":
			return docker.NewRunner(ctx)
		default:
			return nil, fmt.Errorf("unknown runner: %s", runner)
		}
	}

	switch runtime.GOOS {
	case "linux":
		return container.BubblewrapRunner(remove), nil
	case "darwin":
		// darwin is the same as default, but we want to keep it explicit
		fallthrough
	default:
		return docker.NewRunner(ctx)
	}
}
