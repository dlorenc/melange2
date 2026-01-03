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

package e2e

import (
	"testing"
)

// TestBuildFixtures runs all build fixtures through the local BuildKit pipeline.
// Each fixture is:
// 1. Compiled using production Build.Compile()
// 2. Built using production Builder.BuildWithImage()
// 3. Tested using production Builder.TestWithImage() (if test: section exists)
func TestBuildFixtures(t *testing.T) {
	RunAllFixtures(t, "fixtures/build", BuildModeLocal)
}
