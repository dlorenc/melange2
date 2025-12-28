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

//go:build compare

package compare

import (
	"strings"
	"testing"
)

func TestParseAPKIndex(t *testing.T) {
	// Sample APKINDEX content
	indexContent := `C:Q1abc123=
P:test-package
V:1.2.3-r0
A:x86_64
S:12345
I:67890
T:Test package description
U:https://example.com
L:MIT
o:test-package
m:Test Maintainer <test@example.com>
c:abc123def
D:dep1 dep2
p:so:libtest.so.1

C:Q2xyz456=
P:another-package
V:2.0.0-r1
A:x86_64
S:54321
I:98765
T:Another test package
U:https://example.org
L:Apache-2.0
o:another-package
m:Another Maintainer <another@example.com>
c:xyz789abc
D:dep3
p:so:libanother.so.2

`

	reader := strings.NewReader(indexContent)
	idx, err := parseAPKIndexFile(reader)
	if err != nil {
		t.Fatalf("failed to parse APKINDEX: %v", err)
	}

	// Check that we parsed two packages
	if len(idx.Packages) != 2 {
		t.Errorf("expected 2 packages, got %d", len(idx.Packages))
	}

	// Check first package
	pkg1 := idx.GetPackage("test-package")
	if pkg1 == nil {
		t.Fatal("test-package not found")
	}
	if pkg1.Version != "1.2.3-r0" {
		t.Errorf("expected version 1.2.3-r0, got %s", pkg1.Version)
	}
	if pkg1.Description != "Test package description" {
		t.Errorf("expected description 'Test package description', got %s", pkg1.Description)
	}
	if len(pkg1.Dependencies) != 2 {
		t.Errorf("expected 2 dependencies, got %d", len(pkg1.Dependencies))
	}

	// Check second package
	pkg2 := idx.GetPackage("another-package")
	if pkg2 == nil {
		t.Fatal("another-package not found")
	}
	if pkg2.Version != "2.0.0-r1" {
		t.Errorf("expected version 2.0.0-r1, got %s", pkg2.Version)
	}
	if pkg2.License != "Apache-2.0" {
		t.Errorf("expected license Apache-2.0, got %s", pkg2.License)
	}

	// Check HasPackage
	if !idx.HasPackage("test-package") {
		t.Error("HasPackage returned false for existing package")
	}
	if idx.HasPackage("nonexistent") {
		t.Error("HasPackage returned true for non-existent package")
	}
}

func TestAPKPackageFilename(t *testing.T) {
	pkg := &APKPackage{
		Name:    "test-pkg",
		Version: "1.0.0-r0",
	}

	expected := "test-pkg-1.0.0-r0.apk"
	if pkg.Filename() != expected {
		t.Errorf("expected filename %s, got %s", expected, pkg.Filename())
	}
}

func TestFetchAPKIndexIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Test fetching the actual Wolfi APKINDEX
	idx, err := FetchAPKIndex(DefaultWolfiRepoURL, "x86_64")
	if err != nil {
		t.Fatalf("failed to fetch APKINDEX: %v", err)
	}

	// Should have many packages
	if len(idx.Packages) < 1000 {
		t.Errorf("expected at least 1000 packages, got %d", len(idx.Packages))
	}

	// Check for some well-known packages
	wellKnown := []string{"busybox", "ca-certificates-bundle", "wolfi-baselayout"}
	for _, name := range wellKnown {
		if !idx.HasPackage(name) {
			t.Errorf("expected to find package %s", name)
		}
	}

	t.Logf("Loaded %d packages from Wolfi repository", len(idx.Packages))
}
