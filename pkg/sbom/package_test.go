// Copyright 2024 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package sbom

import (
	"context"
	"testing"
	"time"

	apko_build "chainguard.dev/apko/pkg/build"
	"chainguard.dev/apko/pkg/sbom/generator/spdx"
	purl "github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/require"
)

func Test_stringToIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "basic_colon",
			input:    "foo:bar",
			expected: "foo-bar", // Colons replaced with dashes.
		},
		{
			name:     "basic_slash",
			input:    "foo/bar",
			expected: "foo-bar", // Slashes replaced with dashes.
		},
		{
			name:     "space_replacement",
			input:    "foo bar",
			expected: "fooC32bar", // Spaces encoded as Unicode prefix.
		},
		{
			name:     "mixed_colon_and_slash",
			input:    "foo:bar/baz",
			expected: "foo-bar-baz", // Mixed colons and slashes replaced with dashes.
		},
		{
			name:     "valid_characters_unchanged",
			input:    "example-valid.123",
			expected: "example-valid.123", // Valid characters remain unchanged.
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := stringToIdentifier(test.input)
			require.Equal(t, test.expected, result, "unexpected result for input %q", test.input)
		})
	}
}

func TestPackageID(t *testing.T) {
	tests := []struct {
		name     string
		pkg      Package
		expected string
	}{
		{
			name: "basic package ID",
			pkg: Package{
				Name:    "test-package",
				Version: "1.0.0",
			},
			expected: "SPDXRef-Package-test-package-1.0.0",
		},
		{
			name: "package with special characters in name",
			pkg: Package{
				Name:    "test:package/sub",
				Version: "2.0.0",
			},
			expected: "SPDXRef-Package-test-package-sub-2.0.0",
		},
		{
			name: "package with custom ID components",
			pkg: Package{
				IDComponents: []string{"custom", "component", "id"},
				Name:         "ignored-name",
				Version:      "ignored-version",
			},
			expected: "SPDXRef-Package-custom-component-id",
		},
		{
			name: "package with single ID component",
			pkg: Package{
				IDComponents: []string{"single"},
				Name:         "test",
				Version:      "1.0",
			},
			expected: "SPDXRef-Package-single",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.pkg.ID()
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestPackageToSPDX(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name  string
		pkg   Package
		check func(t *testing.T, sp spdx.Package)
	}{
		{
			name: "basic package",
			pkg: Package{
				Name:      "test-pkg",
				Version:   "1.0.0",
				Namespace: "wolfi",
			},
			check: func(t *testing.T, sp spdx.Package) {
				require.Equal(t, "SPDXRef-Package-test-pkg-1.0.0", sp.ID)
				require.Equal(t, "test-pkg", sp.Name)
				require.Equal(t, "1.0.0", sp.Version)
				require.Equal(t, spdx.NOASSERTION, sp.LicenseDeclared)
				require.Equal(t, spdx.NOASSERTION, sp.LicenseConcluded)
				require.Equal(t, "Organization: Wolfi", sp.Supplier)
				require.False(t, sp.FilesAnalyzed)
			},
		},
		{
			name: "package with license",
			pkg: Package{
				Name:            "licensed-pkg",
				Version:         "2.0.0",
				LicenseDeclared: "MIT",
				Namespace:       "alpine",
			},
			check: func(t *testing.T, sp spdx.Package) {
				require.Equal(t, "MIT", sp.LicenseDeclared)
				require.Equal(t, "Organization: Alpine", sp.Supplier)
			},
		},
		{
			name: "package with copyright",
			pkg: Package{
				Name:      "copyrighted-pkg",
				Version:   "1.0.0",
				Copyright: "Copyright 2024 Test Corp",
				Namespace: "test",
			},
			check: func(t *testing.T, sp spdx.Package) {
				require.Equal(t, "Copyright 2024 Test Corp", sp.CopyrightText)
			},
		},
		{
			name: "package with checksums",
			pkg: Package{
				Name:    "checksum-pkg",
				Version: "1.0.0",
				Checksums: map[string]string{
					"SHA-256": "abc123def456",
					"SHA-512": "789xyz000aaa",
				},
				Namespace: "test",
			},
			check: func(t *testing.T, sp spdx.Package) {
				require.Len(t, sp.Checksums, 2)
				// Checksums should be sorted by algorithm
				require.Equal(t, "SHA-256", sp.Checksums[0].Algorithm)
				require.Equal(t, "abc123def456", sp.Checksums[0].Value)
				require.Equal(t, "SHA-512", sp.Checksums[1].Algorithm)
				require.Equal(t, "789xyz000aaa", sp.Checksums[1].Value)
			},
		},
		{
			name: "package with PURL",
			pkg: Package{
				Name:    "purl-pkg",
				Version: "1.0.0",
				PURL: &purl.PackageURL{
					Type:      "apk",
					Namespace: "wolfi",
					Name:      "purl-pkg",
					Version:   "1.0.0",
				},
				Namespace: "wolfi",
			},
			check: func(t *testing.T, sp spdx.Package) {
				require.Len(t, sp.ExternalRefs, 1)
				require.Equal(t, spdx.ExtRefPackageManager, sp.ExternalRefs[0].Category)
				require.Equal(t, spdx.ExtRefTypePurl, sp.ExternalRefs[0].Type)
				require.Contains(t, sp.ExternalRefs[0].Locator, "pkg:apk/wolfi/purl-pkg")
			},
		},
		{
			name: "package with download location",
			pkg: Package{
				Name:             "download-pkg",
				Version:          "1.0.0",
				DownloadLocation: "https://example.com/download/pkg-1.0.0.tar.gz",
				Namespace:        "test",
			},
			check: func(t *testing.T, sp spdx.Package) {
				require.Equal(t, "https://example.com/download/pkg-1.0.0.tar.gz", sp.DownloadLocation)
			},
		},
		{
			name: "package with empty download location defaults to NOASSERTION",
			pkg: Package{
				Name:      "no-download-pkg",
				Version:   "1.0.0",
				Namespace: "test",
			},
			check: func(t *testing.T, sp spdx.Package) {
				require.Equal(t, spdx.NOASSERTION, sp.DownloadLocation)
			},
		},
		{
			name: "package with no checksums returns empty array",
			pkg: Package{
				Name:      "no-checksum-pkg",
				Version:   "1.0.0",
				Namespace: "test",
			},
			check: func(t *testing.T, sp spdx.Package) {
				require.NotNil(t, sp.Checksums, "checksums should be empty array, not nil")
				require.Len(t, sp.Checksums, 0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.pkg.ToSPDX(ctx)
			tt.check(t, result)
		})
	}
}

func TestDocument(t *testing.T) {
	t.Run("NewDocument creates empty document", func(t *testing.T) {
		doc := NewDocument()
		require.NotNil(t, doc)
		require.Nil(t, doc.Describes)
		require.Empty(t, doc.Packages)
		require.Empty(t, doc.Relationships)
	})

	t.Run("AddPackage adds package to document", func(t *testing.T) {
		doc := NewDocument()
		pkg := &Package{Name: "test", Version: "1.0.0"}

		doc.AddPackage(pkg)

		require.Len(t, doc.Packages, 1)
		require.Equal(t, "test", doc.Packages[0].Name)
	})

	t.Run("AddPackage ignores nil package", func(t *testing.T) {
		doc := NewDocument()
		doc.AddPackage(nil)
		require.Empty(t, doc.Packages)
	})

	t.Run("AddPackageAndSetDescribed sets described package", func(t *testing.T) {
		doc := NewDocument()
		pkg := &Package{Name: "main-pkg", Version: "2.0.0"}

		doc.AddPackageAndSetDescribed(pkg)

		require.NotNil(t, doc.Describes)
		require.Equal(t, "main-pkg", doc.Describes.Name)
		require.Len(t, doc.Packages, 1)
	})

	t.Run("AddRelationship adds relationship between elements", func(t *testing.T) {
		doc := NewDocument()
		pkg1 := &Package{Name: "pkg1", Version: "1.0.0"}
		pkg2 := &Package{Name: "pkg2", Version: "1.0.0"}

		doc.AddRelationship(pkg1, pkg2, "DEPENDS_ON")

		require.Len(t, doc.Relationships, 1)
		require.Equal(t, pkg1.ID(), doc.Relationships[0].Element)
		require.Equal(t, pkg2.ID(), doc.Relationships[0].Related)
		require.Equal(t, "DEPENDS_ON", doc.Relationships[0].Type)
	})

	t.Run("AddUpstreamSourcePackage adds package and relationship", func(t *testing.T) {
		doc := NewDocument()
		mainPkg := &Package{Name: "main", Version: "1.0.0"}
		doc.AddPackageAndSetDescribed(mainPkg)

		sourcePkg := &Package{Name: "source", Version: "1.0.0"}
		doc.AddUpstreamSourcePackage(sourcePkg)

		require.Len(t, doc.Packages, 2)
		require.Len(t, doc.Relationships, 1)
		require.Equal(t, "GENERATED_FROM", doc.Relationships[0].Type)
	})
}

func TestDocumentToSPDX(t *testing.T) {
	ctx := context.Background()
	createdTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	t.Run("basic document conversion", func(t *testing.T) {
		doc := &Document{
			CreatedTime: createdTime,
			Describes: &Package{
				Name:      "test-pkg",
				Version:   "1.0.0-r0",
				Namespace: "wolfi",
			},
			Packages: []Package{
				{Name: "test-pkg", Version: "1.0.0-r0", Namespace: "wolfi"},
			},
		}

		result := doc.ToSPDX(ctx, nil)

		require.Equal(t, "SPDXRef-DOCUMENT", result.ID)
		require.Equal(t, "SPDX-2.3", result.Version)
		require.Equal(t, "CC0-1.0", result.DataLicense)
		require.Equal(t, "apk-test-pkg-1.0.0-r0", result.Name)
		require.Contains(t, result.Namespace, "spdx.org/spdxdocs/chainguard/melange")
		require.Len(t, result.DocumentDescribes, 1)
		require.Equal(t, doc.Describes.ID(), result.DocumentDescribes[0])
	})

	t.Run("document with release data includes OS package", func(t *testing.T) {
		doc := &Document{
			CreatedTime: createdTime,
			Describes: &Package{
				Name:      "test-pkg",
				Version:   "1.0.0",
				Namespace: "wolfi",
			},
			Packages: []Package{
				{Name: "test-pkg", Version: "1.0.0", Namespace: "wolfi"},
			},
		}

		releaseData := &apko_build.ReleaseData{
			ID:        "wolfi",
			VersionID: "20240101",
		}

		result := doc.ToSPDX(ctx, releaseData)

		// Should have OS package + the regular package
		require.Len(t, result.Packages, 2)

		// First package should be the OS
		osPackage := result.Packages[0]
		require.Equal(t, "SPDXRef-OperatingSystem", osPackage.ID)
		require.Equal(t, "wolfi", osPackage.Name)
		require.Equal(t, "20240101", osPackage.Version)
		require.Equal(t, "OPERATING-SYSTEM", osPackage.PrimaryPurpose)
	})

	t.Run("document with licensing infos", func(t *testing.T) {
		doc := &Document{
			CreatedTime: createdTime,
			Describes: &Package{
				Name:      "test-pkg",
				Version:   "1.0.0",
				Namespace: "test",
			},
			Packages: []Package{
				{Name: "test-pkg", Version: "1.0.0", Namespace: "test"},
			},
			LicensingInfos: map[string]string{
				"LicenseRef-Custom-1": "Custom license text here",
				"LicenseRef-Custom-2": "Another custom license",
			},
		}

		result := doc.ToSPDX(ctx, nil)

		require.Len(t, result.LicensingInfos, 2)
	})

	t.Run("document with relationships", func(t *testing.T) {
		mainPkg := Package{Name: "main", Version: "1.0.0", Namespace: "test"}
		depPkg := Package{Name: "dep", Version: "2.0.0", Namespace: "test"}

		doc := &Document{
			CreatedTime: createdTime,
			Describes:   &mainPkg,
			Packages:    []Package{mainPkg, depPkg},
			Relationships: []spdx.Relationship{
				{Element: mainPkg.ID(), Related: depPkg.ID(), Type: "DEPENDS_ON"},
			},
		}

		result := doc.ToSPDX(ctx, nil)

		require.Len(t, result.Relationships, 1)
		require.Equal(t, mainPkg.ID(), result.Relationships[0].Element)
		require.Equal(t, depPkg.ID(), result.Relationships[0].Related)
		require.Equal(t, "DEPENDS_ON", result.Relationships[0].Type)
	})
}

func Test_encodeInvalidRune(t *testing.T) {
	tests := []struct {
		r        rune
		expected string
	}{
		{' ', "C32"},
		{'@', "C64"},
		{'!', "C33"},
		{'[', "C91"},
		{'\n', "C10"},
	}

	for _, tt := range tests {
		t.Run(string(tt.r), func(t *testing.T) {
			result := encodeInvalidRune(tt.r)
			require.Equal(t, tt.expected, result)
		})
	}
}
