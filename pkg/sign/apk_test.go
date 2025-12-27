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

package sign

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"chainguard.dev/apko/pkg/apk/expandapk"
	"chainguard.dev/apko/pkg/apk/signature"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

const (
	testAPK     = "testdata/test.apk"
	testPubkey  = "test.pem.pub"
	testPrivKey = "test.pem"
)

func TestAPK(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()
	apkPath := tmpDir + "/out.apk"

	// copy testdata/test.apk to tmpDir
	if err := CopyFile(testAPK, apkPath); err != nil {
		t.Fatal(err)
	}
	// sign the apk
	if err := APK(ctx, apkPath, "testdata/"+testPrivKey); err != nil {
		t.Fatal(err)
	}
	// verify the signature
	controlData, sigName, sig, err := parseAPK(ctx, apkPath)
	if err != nil {
		t.Fatal(err)
	}
	if sigName != ".SIGN.RSA256."+testPubkey {
		t.Fatalf("unexpected signature name %s", sigName)
	}
	digest, err := HashData(controlData, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := os.ReadFile("testdata/" + testPubkey)
	if err != nil {
		t.Fatal(err)
	}
	if err := signature.RSAVerifyDigest(digest, crypto.SHA256, sig, pubKey); err != nil {
		t.Fatal(err)
	}
}

func parseAPK(_ context.Context, apkPath string) (control []byte, sigName string, sig []byte, err error) {
	apkr, err := os.Open(apkPath)
	if err != nil {
		return nil, "", nil, err
	}
	eapk, err := expandapk.ExpandApk(context.TODO(), apkr, "")
	if err != nil {
		return nil, "", nil, err
	}
	defer eapk.Close()
	gzSig, err := os.ReadFile(eapk.SignatureFile)
	if err != nil {
		return nil, "", nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(gzSig))
	if err != nil {
		return nil, "", nil, err
	}
	tr := tar.NewReader(zr)
	hdr, err := tr.Next()
	if err != nil {
		return nil, "", nil, err
	}
	if !strings.HasPrefix(hdr.Name, ".SIGN.") {
		return nil, "", nil, fmt.Errorf("unexpected header name %s", hdr.Name)
	}
	sig, err = io.ReadAll(tr)
	control, err = os.ReadFile(eapk.ControlFile)
	if err != nil {
		return nil, "", nil, err
	}
	return control, hdr.Name, sig, err
}

func CopyFile(src, dest string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dest, b, 0o644); err != nil {
		return err
	}
	return nil
}

const MockName = "mockiavelli"

func TestEmitSignature(t *testing.T) {
	sde := time.Unix(12345678, 0)

	controlData := []byte("donkey")

	signer := &mockSigner{}

	sig, err := EmitSignature(signer, controlData, sde)
	if err != nil {
		t.Fatal(err)
	}

	gr, err := gzip.NewReader(bytes.NewReader(sig))
	if err != nil {
		t.Fatal(err)
	}

	// Decompress the sig to first check for end of archive markers
	dsig, err := io.ReadAll(gr)
	if err != nil {
		t.Fatal(err)
	}

	// Check for end of archive markers
	if bytes.HasSuffix(dsig, make([]byte, 1024)) {
		t.Fatalf("found end of archive makers in the signature tarball")
	}

	// Now create the tar reader from the decompressed sig archive for the remainder of the tests
	tr := tar.NewReader(bytes.NewBuffer(dsig))

	hdr, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}

	// Should only have a single file in here
	hdrWant := &tar.Header{
		Name:     MockName,
		Typeflag: tar.TypeReg,
		Size:     int64(len(controlData)),
		Mode:     int64(0o644),
		Uid:      0,
		Gid:      0,
		Uname:    "root",
		Gname:    "root",
		ModTime:  sde,
	}
	if diff := cmp.Diff(hdr, hdrWant, cmpopts.IgnoreFields(tar.Header{}, "AccessTime", "ChangeTime", "Format")); diff != "" {
		t.Errorf("Expected %v got %v", hdrWant, hdr)
	}

	if hdr.Name != "mockiavelli" {
		t.Errorf("Unexpected tar header name: got %v want %v", hdr.Name, "mockaveli")
	}

	want, err := io.ReadAll(tr)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(controlData, want) {
		t.Errorf("Unexpected signature contents: got %v want %v", want, controlData)
	}

	_, err = tr.Next()
	//nolint:errorlint
	if err != io.EOF {
		t.Fatalf("Expected tar EOF")
	}
}

type mockSigner struct{}

// Sign implements build.ApkSigner.
func (*mockSigner) Sign(controlData []byte) ([]byte, error) {
	return controlData, nil
}

// SignatureName implements build.ApkSigner.
func (*mockSigner) SignatureName() string {
	return "mockiavelli"
}

func TestHashData(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		digestType crypto.Hash
		wantLen    int
		wantErr    bool
	}{
		{
			name:       "SHA256 hash",
			data:       []byte("test data for hashing"),
			digestType: crypto.SHA256,
			wantLen:    32, // SHA256 produces 32 bytes
		},
		{
			name:       "SHA512 hash",
			data:       []byte("test data for hashing"),
			digestType: crypto.SHA512,
			wantLen:    64, // SHA512 produces 64 bytes
		},
		{
			name:       "SHA1 hash",
			data:       []byte("test data for hashing"),
			digestType: crypto.SHA1,
			wantLen:    20, // SHA1 produces 20 bytes
		},
		{
			name:       "empty data",
			data:       []byte{},
			digestType: crypto.SHA256,
			wantLen:    32,
		},
		{
			name:       "large data",
			data:       bytes.Repeat([]byte("x"), 10000),
			digestType: crypto.SHA256,
			wantLen:    32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := HashData(tt.data, tt.digestType)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(result) != tt.wantLen {
				t.Errorf("expected hash length %d, got %d", tt.wantLen, len(result))
			}
		})
	}
}

func TestHashDataConsistency(t *testing.T) {
	// Test that same input produces same output
	data := []byte("consistent test data")

	hash1, err := HashData(data, crypto.SHA256)
	if err != nil {
		t.Fatalf("first hash failed: %v", err)
	}

	hash2, err := HashData(data, crypto.SHA256)
	if err != nil {
		t.Fatalf("second hash failed: %v", err)
	}

	if !bytes.Equal(hash1, hash2) {
		t.Error("same input produced different hashes")
	}
}

func TestHashDataDifferentInputs(t *testing.T) {
	// Test that different inputs produce different outputs
	data1 := []byte("data one")
	data2 := []byte("data two")

	hash1, err := HashData(data1, crypto.SHA256)
	if err != nil {
		t.Fatalf("first hash failed: %v", err)
	}

	hash2, err := HashData(data2, crypto.SHA256)
	if err != nil {
		t.Fatalf("second hash failed: %v", err)
	}

	if bytes.Equal(hash1, hash2) {
		t.Error("different inputs produced same hash")
	}
}

func TestKeyApkSignerSignatureName(t *testing.T) {
	tests := []struct {
		keyFile  string
		expected string
	}{
		{
			keyFile:  "/path/to/key.pem",
			expected: ".SIGN.RSA256.key.pem.pub",
		},
		{
			keyFile:  "simple.pem",
			expected: ".SIGN.RSA256.simple.pem.pub",
		},
		{
			keyFile:  "/very/long/path/to/melange.rsa",
			expected: ".SIGN.RSA256.melange.rsa.pub",
		},
	}

	for _, tt := range tests {
		t.Run(tt.keyFile, func(t *testing.T) {
			signer := KeyApkSigner{
				KeyFile:       tt.keyFile,
				KeyPassphrase: "",
			}
			result := signer.SignatureName()
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestEmitSignatureHeader(t *testing.T) {
	// Test that EmitSignature produces correct tar headers
	sde := time.Unix(1704067200, 0) // 2024-01-01 00:00:00 UTC
	controlData := []byte("test control data")

	signer := &mockSigner{}

	sig, err := EmitSignature(signer, controlData, sde)
	if err != nil {
		t.Fatalf("EmitSignature failed: %v", err)
	}

	gr, err := gzip.NewReader(bytes.NewReader(sig))
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer gr.Close()

	dsig, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("failed to decompress: %v", err)
	}

	tr := tar.NewReader(bytes.NewBuffer(dsig))
	hdr, err := tr.Next()
	if err != nil {
		t.Fatalf("failed to read tar header: %v", err)
	}

	// Verify header fields
	if hdr.Name != MockName {
		t.Errorf("expected name %q, got %q", MockName, hdr.Name)
	}
	if hdr.Typeflag != tar.TypeReg {
		t.Errorf("expected TypeReg, got %v", hdr.Typeflag)
	}
	if hdr.Mode != 0o644 {
		t.Errorf("expected mode 0644, got %o", hdr.Mode)
	}
	if hdr.Uid != 0 {
		t.Errorf("expected uid 0, got %d", hdr.Uid)
	}
	if hdr.Gid != 0 {
		t.Errorf("expected gid 0, got %d", hdr.Gid)
	}
	if hdr.Uname != "root" {
		t.Errorf("expected uname 'root', got %q", hdr.Uname)
	}
	if hdr.Gname != "root" {
		t.Errorf("expected gname 'root', got %q", hdr.Gname)
	}
	if !hdr.ModTime.Equal(sde) {
		t.Errorf("expected modtime %v, got %v", sde, hdr.ModTime)
	}
}

func TestEmitSignatureSize(t *testing.T) {
	// Test that signature size matches control data size when using mock signer
	testCases := []struct {
		name        string
		controlData []byte
	}{
		{"small data", []byte("small")},
		{"medium data", bytes.Repeat([]byte("x"), 1000)},
		{"empty data", []byte{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signer := &mockSigner{}
			sde := time.Now()

			sig, err := EmitSignature(signer, tc.controlData, sde)
			if err != nil {
				t.Fatalf("EmitSignature failed: %v", err)
			}

			gr, err := gzip.NewReader(bytes.NewReader(sig))
			if err != nil {
				t.Fatalf("failed to create gzip reader: %v", err)
			}
			defer gr.Close()

			dsig, err := io.ReadAll(gr)
			if err != nil {
				t.Fatalf("failed to decompress: %v", err)
			}

			tr := tar.NewReader(bytes.NewBuffer(dsig))
			hdr, err := tr.Next()
			if err != nil {
				t.Fatalf("failed to read tar header: %v", err)
			}

			// Mock signer returns control data as signature
			if hdr.Size != int64(len(tc.controlData)) {
				t.Errorf("expected size %d, got %d", len(tc.controlData), hdr.Size)
			}
		})
	}
}
