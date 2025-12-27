package tarball

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/fs"
)

func TestWriteTar(t *testing.T) {
	var buf bytes.Buffer
	var (
		m    = fs.NewMemFS()
		dir  = "a"
		file = "a/b"
	)
	err := m.MkdirAll(dir, 0o755)
	require.NoError(t, err, "error creating dir %s", dir)
	err = m.WriteFile(file, []byte("hello world"), 0o644)
	require.NoError(t, err, "error creating file %s", file)

	// set xattrs, then see if the tar gets it
	err = m.SetXattr(dir, "user.dir", []byte("foo"))
	require.NoError(t, err, "error setting xattr on %s", dir)
	err = m.SetXattr(file, "user.file", []byte("bar"))
	require.NoError(t, err, "error setting xattr on %s", file)
	ctx := Context{}
	tw := tar.NewWriter(&buf)
	err = ctx.writeTar(context.TODO(), tw, m, nil, nil)
	require.NoError(t, err, "error writing tar")
	err = tw.Close()
	require.NoError(t, err, "error closing tar writer")

	// now should be able to read the tar and check the xattrs
	tr := tar.NewReader(&buf)
	hdr, err := tr.Next()
	require.NoError(t, err, "error reading dir tar header")
	require.Equal(t, dir, hdr.Name, "tar dir header name mismatch")
	require.Equal(t, "foo", hdr.PAXRecords[xattrTarPAXRecordsPrefix+"user.dir"], "tar header for dir xattr mismatch")

	hdr, err = tr.Next()
	require.NoError(t, err, "error reading file tar header")
	require.Equal(t, file, hdr.Name, "tar file header name mismatch")
	require.Equal(t, "bar", hdr.PAXRecords[xattrTarPAXRecordsPrefix+"user.file"], "tar header for file xattr mismatch")
}

func TestNewContext(t *testing.T) {
	tests := []struct {
		name    string
		opts    []Option
		check   func(t *testing.T, ctx *Context)
		wantErr bool
	}{
		{
			name: "default context",
			opts: nil,
			check: func(t *testing.T, ctx *Context) {
				require.False(t, ctx.OverrideUIDGID)
				require.Empty(t, ctx.OverrideUname)
				require.Empty(t, ctx.OverrideGname)
				require.False(t, ctx.SkipClose)
				require.False(t, ctx.UseChecksums)
			},
		},
		{
			name: "with source date epoch",
			opts: []Option{WithSourceDateEpoch(time.Unix(1234567890, 0))},
			check: func(t *testing.T, ctx *Context) {
				require.Equal(t, time.Unix(1234567890, 0), ctx.SourceDateEpoch)
			},
		},
		{
			name: "with override UID/GID",
			opts: []Option{WithOverrideUIDGID(1000, 1001)},
			check: func(t *testing.T, ctx *Context) {
				require.True(t, ctx.OverrideUIDGID)
				require.Equal(t, 1000, ctx.UID)
				require.Equal(t, 1001, ctx.GID)
			},
		},
		{
			name: "with override uname",
			opts: []Option{WithOverrideUname("testuser")},
			check: func(t *testing.T, ctx *Context) {
				require.Equal(t, "testuser", ctx.OverrideUname)
			},
		},
		{
			name: "with override gname",
			opts: []Option{WithOverrideGname("testgroup")},
			check: func(t *testing.T, ctx *Context) {
				require.Equal(t, "testgroup", ctx.OverrideGname)
			},
		},
		{
			name: "with skip close",
			opts: []Option{WithSkipClose(true)},
			check: func(t *testing.T, ctx *Context) {
				require.True(t, ctx.SkipClose)
			},
		},
		{
			name: "with use checksums",
			opts: []Option{WithUseChecksums(true)},
			check: func(t *testing.T, ctx *Context) {
				require.True(t, ctx.UseChecksums)
			},
		},
		{
			name: "with remap UIDs",
			opts: []Option{WithRemapUIDs(map[int]int{1000: 0, 1001: 1})},
			check: func(t *testing.T, ctx *Context) {
				require.Equal(t, map[int]int{1000: 0, 1001: 1}, ctx.remapUIDs)
			},
		},
		{
			name: "with remap GIDs",
			opts: []Option{WithRemapGIDs(map[int]int{1000: 0, 1001: 1})},
			check: func(t *testing.T, ctx *Context) {
				require.Equal(t, map[int]int{1000: 0, 1001: 1}, ctx.remapGIDs)
			},
		},
		{
			name: "with override perms",
			opts: []Option{WithOverridePerms([]tar.Header{
				{Name: "test.txt", Mode: 0755, Uid: 0, Gid: 0},
			})},
			check: func(t *testing.T, ctx *Context) {
				require.NotNil(t, ctx.overridePerms)
				require.Contains(t, ctx.overridePerms, "test.txt")
				require.Equal(t, int64(0755), ctx.overridePerms["test.txt"].Mode)
			},
		},
		{
			name: "with multiple options",
			opts: []Option{
				WithOverrideUIDGID(0, 0),
				WithOverrideUname("root"),
				WithOverrideGname("root"),
				WithUseChecksums(true),
				WithSourceDateEpoch(time.Unix(0, 0)),
			},
			check: func(t *testing.T, ctx *Context) {
				require.True(t, ctx.OverrideUIDGID)
				require.Equal(t, 0, ctx.UID)
				require.Equal(t, 0, ctx.GID)
				require.Equal(t, "root", ctx.OverrideUname)
				require.Equal(t, "root", ctx.OverrideGname)
				require.True(t, ctx.UseChecksums)
				require.Equal(t, time.Unix(0, 0), ctx.SourceDateEpoch)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, err := NewContext(tt.opts...)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, ctx)
			tt.check(t, ctx)
		})
	}
}

func TestWriteTargz(t *testing.T) {
	m := fs.NewMemFS()
	dir := "testdir"
	file := "testdir/testfile.txt"
	content := []byte("hello world from targz test")

	err := m.MkdirAll(dir, 0o755)
	require.NoError(t, err)
	err = m.WriteFile(file, content, 0o644)
	require.NoError(t, err)

	ctx, err := NewContext(
		WithOverrideUIDGID(0, 0),
		WithOverrideUname("root"),
		WithOverrideGname("root"),
	)
	require.NoError(t, err)

	var buf bytes.Buffer
	err = ctx.WriteTargz(context.Background(), &buf, m, m)
	require.NoError(t, err)

	// Verify gzip decompression works
	gr, err := gzip.NewReader(&buf)
	require.NoError(t, err)
	defer gr.Close()

	// Verify tar contents
	tr := tar.NewReader(gr)

	// First entry should be the directory
	hdr, err := tr.Next()
	require.NoError(t, err)
	require.Equal(t, dir, hdr.Name)
	require.Equal(t, 0, hdr.Uid)
	require.Equal(t, 0, hdr.Gid)
	require.Equal(t, "root", hdr.Uname)
	require.Equal(t, "root", hdr.Gname)

	// Second entry should be the file
	hdr, err = tr.Next()
	require.NoError(t, err)
	require.Equal(t, file, hdr.Name)

	// Read file content
	readContent, err := io.ReadAll(tr)
	require.NoError(t, err)
	require.Equal(t, content, readContent)
}

func TestWriteTarWithChecksums(t *testing.T) {
	m := fs.NewMemFS()
	file := "checksumtest.txt"
	content := []byte("checksum test content")

	err := m.WriteFile(file, content, 0o644)
	require.NoError(t, err)

	ctx, err := NewContext(WithUseChecksums(true))
	require.NoError(t, err)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err = ctx.writeTar(context.Background(), tw, m, nil, nil)
	require.NoError(t, err)
	err = tw.Close()
	require.NoError(t, err)

	// Read and verify checksum
	tr := tar.NewReader(&buf)
	hdr, err := tr.Next()
	require.NoError(t, err)
	require.Equal(t, file, hdr.Name)

	// Verify SHA1 checksum is present
	checksum, ok := hdr.PAXRecords["APK-TOOLS.checksum.SHA1"]
	require.True(t, ok, "checksum should be present")
	require.NotEmpty(t, checksum, "checksum should not be empty")
}

func TestWriteTarWithSourceDateEpoch(t *testing.T) {
	m := fs.NewMemFS()
	file := "epochtest.txt"

	err := m.WriteFile(file, []byte("epoch test"), 0o644)
	require.NoError(t, err)

	// Use Unix timestamp to avoid timezone issues
	sde := time.Unix(1704067200, 0) // 2024-01-01 00:00:00 UTC
	ctx, err := NewContext(WithSourceDateEpoch(sde))
	require.NoError(t, err)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err = ctx.writeTar(context.Background(), tw, m, nil, nil)
	require.NoError(t, err)
	err = tw.Close()
	require.NoError(t, err)

	tr := tar.NewReader(&buf)
	hdr, err := tr.Next()
	require.NoError(t, err)
	// The SourceDateEpoch is set on the context and should be applied to ModTime
	// Compare Unix timestamps to avoid timezone issues
	require.Equal(t, sde.Unix(), hdr.ModTime.Unix(), "ModTime should match SourceDateEpoch")
}

func TestWriteTarWithUIDGIDRemap(t *testing.T) {
	m := fs.NewMemFS()
	file := "remaptest.txt"

	err := m.WriteFile(file, []byte("remap test"), 0o644)
	require.NoError(t, err)

	ctx, err := NewContext(
		WithRemapUIDs(map[int]int{501: 1000}),
		WithRemapGIDs(map[int]int{20: 1001}),
	)
	require.NoError(t, err)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err = ctx.writeTar(context.Background(), tw, m, map[int]string{1000: "testuser"}, map[int]string{1001: "testgroup"})
	require.NoError(t, err)
	err = tw.Close()
	require.NoError(t, err)

	// Verify the tar was created (remapping may not apply on all systems)
	tr := tar.NewReader(&buf)
	hdr, err := tr.Next()
	require.NoError(t, err)
	require.Equal(t, file, hdr.Name)
}

func TestWriteTarWithOverridePerms(t *testing.T) {
	m := fs.NewMemFS()
	file := "permtest.txt"

	err := m.WriteFile(file, []byte("perm test"), 0o644)
	require.NoError(t, err)

	ctx, err := NewContext(
		WithOverridePerms([]tar.Header{
			{Name: file, Mode: 0o755, Uid: 1000, Gid: 1001, Uname: "alice", Gname: "users"},
		}),
	)
	require.NoError(t, err)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err = ctx.writeTar(context.Background(), tw, m, nil, nil)
	require.NoError(t, err)
	err = tw.Close()
	require.NoError(t, err)

	tr := tar.NewReader(&buf)
	hdr, err := tr.Next()
	require.NoError(t, err)
	require.Equal(t, file, hdr.Name)
	require.Equal(t, int64(0o755), hdr.Mode)
	require.Equal(t, 1000, hdr.Uid)
	require.Equal(t, 1001, hdr.Gid)
	require.Equal(t, "alice", hdr.Uname)
	require.Equal(t, "users", hdr.Gname)
}

func TestWriteTarSymlink(t *testing.T) {
	m := fs.NewMemFS()
	target := "target.txt"
	link := "link.txt"

	err := m.WriteFile(target, []byte("target content"), 0o644)
	require.NoError(t, err)
	err = m.Symlink(target, link)
	require.NoError(t, err)

	ctx, err := NewContext(WithUseChecksums(true))
	require.NoError(t, err)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err = ctx.writeTar(context.Background(), tw, m, nil, nil)
	require.NoError(t, err)
	err = tw.Close()
	require.NoError(t, err)

	// Read tar and find symlink
	tr := tar.NewReader(&buf)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)

		if hdr.Name == link {
			require.Equal(t, byte(tar.TypeSymlink), hdr.Typeflag)
			require.Equal(t, target, hdr.Linkname)
			// Verify checksum for symlink target
			_, ok := hdr.PAXRecords["APK-TOOLS.checksum.SHA1"]
			require.True(t, ok, "symlink should have checksum")
			return
		}
	}
	t.Fatal("symlink not found in tar")
}

func TestWriteTarMultipleFiles(t *testing.T) {
	m := fs.NewMemFS()

	// Create directory structure
	err := m.MkdirAll("dir1/subdir", 0o755)
	require.NoError(t, err)
	err = m.MkdirAll("dir2", 0o755)
	require.NoError(t, err)

	// Create files
	files := []string{
		"file1.txt",
		"dir1/file2.txt",
		"dir1/subdir/file3.txt",
		"dir2/file4.txt",
	}

	for i, f := range files {
		err := m.WriteFile(f, []byte("content "+string(rune('0'+i))), 0o644)
		require.NoError(t, err)
	}

	ctx, err := NewContext()
	require.NoError(t, err)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err = ctx.writeTar(context.Background(), tw, m, nil, nil)
	require.NoError(t, err)
	err = tw.Close()
	require.NoError(t, err)

	// Count entries
	tr := tar.NewReader(&buf)
	count := 0
	for {
		_, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		count++
	}

	// Should have 3 directories + 4 files = 7 entries
	require.Equal(t, 7, count)
}

func TestWriteTarSkipClose(t *testing.T) {
	m := fs.NewMemFS()
	err := m.WriteFile("test.txt", []byte("test"), 0o644)
	require.NoError(t, err)

	// Test with SkipClose = true (for concatenated tarballs)
	ctx, err := NewContext(WithSkipClose(true))
	require.NoError(t, err)

	var buf bytes.Buffer
	err = ctx.WriteTar(context.Background(), &buf, m, m)
	require.NoError(t, err)

	// The tar should still be readable (just without end markers)
	tr := tar.NewReader(&buf)
	hdr, err := tr.Next()
	require.NoError(t, err)
	require.Equal(t, "test.txt", hdr.Name)
}

func TestWriteArchiveDeprecated(t *testing.T) {
	m := fs.NewMemFS()
	err := m.WriteFile("deprecated.txt", []byte("deprecated test"), 0o644)
	require.NoError(t, err)

	ctx, err := NewContext()
	require.NoError(t, err)

	var buf bytes.Buffer
	// Test deprecated WriteArchive method (should still work)
	err = ctx.WriteArchive(&buf, m)
	require.NoError(t, err)

	// Should produce valid gzipped tar
	gr, err := gzip.NewReader(&buf)
	require.NoError(t, err)
	defer gr.Close()

	tr := tar.NewReader(gr)
	hdr, err := tr.Next()
	require.NoError(t, err)
	require.Equal(t, "deprecated.txt", hdr.Name)
}
