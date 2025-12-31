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

package contextreader

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	ctx := context.Background()
	r := strings.NewReader("test data")

	cr := New(ctx, r)

	require.NotNil(t, cr)
	// New returns io.Reader, so cr is guaranteed to implement io.Reader
}

func TestContextReader_Read(t *testing.T) {
	t.Run("reads data successfully", func(t *testing.T) {
		ctx := context.Background()
		data := "hello world"
		r := strings.NewReader(data)
		cr := New(ctx, r)

		buf := make([]byte, len(data))
		n, err := cr.Read(buf)

		require.NoError(t, err)
		assert.Equal(t, len(data), n)
		assert.Equal(t, data, string(buf))
	})

	t.Run("reads data in chunks", func(t *testing.T) {
		ctx := context.Background()
		data := "hello world this is a longer string"
		r := strings.NewReader(data)
		cr := New(ctx, r)

		var result bytes.Buffer
		buf := make([]byte, 5)
		for {
			n, err := cr.Read(buf)
			if n > 0 {
				result.Write(buf[:n])
			}
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
		}

		assert.Equal(t, data, result.String())
	})

	t.Run("returns EOF at end of data", func(t *testing.T) {
		ctx := context.Background()
		data := "short"
		r := strings.NewReader(data)
		cr := New(ctx, r)

		buf := make([]byte, 100)
		n, err := cr.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, len(data), n)

		// Second read should return EOF
		n, err = cr.Read(buf)
		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("returns error when context already cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		r := strings.NewReader("test data")
		cr := New(ctx, r)

		buf := make([]byte, 10)
		_, err := cr.Read(buf)

		assert.Error(t, err)
		assert.Equal(t, context.Canceled, err)
	})

	t.Run("returns EOF when context cancelled during read", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		// Use a slow reader that blocks
		slowReader := &slowReader{delay: 100 * time.Millisecond}
		cr := New(ctx, slowReader)

		// Start reading in goroutine
		done := make(chan struct{})
		var readErr error
		go func() {
			buf := make([]byte, 10)
			_, readErr = cr.Read(buf)
			close(done)
		}()

		// Cancel context after small delay
		time.Sleep(10 * time.Millisecond)
		cancel()

		// Wait for read to complete
		select {
		case <-done:
			// Read should have returned EOF due to context cancellation
			assert.Equal(t, io.EOF, readErr)
		case <-time.After(500 * time.Millisecond):
			t.Fatal("read did not complete in time")
		}
	})

	t.Run("handles empty reader", func(t *testing.T) {
		ctx := context.Background()
		r := strings.NewReader("")
		cr := New(ctx, r)

		buf := make([]byte, 10)
		n, err := cr.Read(buf)

		assert.Equal(t, io.EOF, err)
		assert.Equal(t, 0, n)
	})

	t.Run("multiple sequential reads work", func(t *testing.T) {
		ctx := context.Background()
		data := "abcdefghij"
		r := strings.NewReader(data)
		cr := New(ctx, r)

		buf1 := make([]byte, 3)
		n1, err1 := cr.Read(buf1)
		require.NoError(t, err1)
		assert.Equal(t, 3, n1)
		assert.Equal(t, "abc", string(buf1))

		buf2 := make([]byte, 3)
		n2, err2 := cr.Read(buf2)
		require.NoError(t, err2)
		assert.Equal(t, 3, n2)
		assert.Equal(t, "def", string(buf2))
	})
}

// slowReader is a reader that delays before returning
type slowReader struct {
	delay time.Duration
}

func (s *slowReader) Read(p []byte) (int, error) {
	time.Sleep(s.delay)
	return 0, io.EOF
}

func TestContextReader_Integration(t *testing.T) {
	t.Run("works with io.Copy", func(t *testing.T) {
		ctx := context.Background()
		data := "test data for io.Copy"
		r := strings.NewReader(data)
		cr := New(ctx, r)

		var buf bytes.Buffer
		n, err := io.Copy(&buf, cr)

		require.NoError(t, err)
		assert.Equal(t, int64(len(data)), n)
		assert.Equal(t, data, buf.String())
	})

	t.Run("works with io.ReadAll", func(t *testing.T) {
		ctx := context.Background()
		data := "test data for io.ReadAll"
		r := strings.NewReader(data)
		cr := New(ctx, r)

		result, err := io.ReadAll(cr)

		require.NoError(t, err)
		assert.Equal(t, data, string(result))
	})
}
