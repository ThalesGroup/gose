
// Copyright 2024 Thales Group
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package gose

import (
	"crypto/sha256"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestHmacShaCryptor(t *testing.T) {
	kid := "hmac-0"
	cryptor := NewHmacShaCryptor(kid, sha256.New())
	t.Run("testHmacKid", func(t *testing.T) {
		testHmacKid(t, cryptor, kid)
	})
	t.Run("testHmacHash", func(t *testing.T) {
		testHmacHash(t, cryptor, []byte("hashme"))
	})
}

func testHmacKid(t *testing.T, cryptor HmacKey, kid string) {
	require.Equal(t, kid, cryptor.Kid())
}

func testHmacHash(t *testing.T, cryptor HmacKey, input []byte) {
	sha := cryptor.Hash(input)
	require.NotEmpty(t, sha)
	require.Equal(t, 32, len(sha))
	require.NotContains(t, string(sha), string(input))
}
