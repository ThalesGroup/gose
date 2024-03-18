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
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/ThalesGroup/gose/jose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVerifierSucceeds(t *testing.T) {
	// Setup
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk, err := JwkFromPublicKey(rsaKey.Public(), []jose.KeyOps{jose.KeyOpsVerify}, nil)
	require.NoError(t, err)

	cases := []jose.Alg{
		jose.AlgPS256,
		jose.AlgRS256,
	}

	// Act
	for _, test := range cases {
		jwk.SetAlg(test)
		k, err := NewVerificationKey(jwk)

		// Assert
		require.Nil(t, err)
		require.NotNil(t, k)
		require.NotEmpty(t, k.Kid())
		require.Equal(t, test, jwk.Alg())
	}
}

func TestNewVerifierFailsWithInvalidOps(t *testing.T) {
	// Setup
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	testCase := [][]jose.KeyOps{
		{jose.KeyOpsSign},
	}
	for _, test := range testCase {
		jwk, err := JwkFromPublicKey(rsaKey.Public(), test, nil)
		require.NoError(t, err)

		// Act
		k, err := NewVerificationKey(jwk)

		// Assert
		assert.Nil(t, k)
		assert.Equal(t, ErrInvalidOperations, err)
	}
}

func TestNewVerifierFailsWhenNotAVerfierKey(t *testing.T) {
	// Setup
	var jwk jose.PrivateRsaKey
	jwk.SetAlg(jose.AlgPS256)
	jwk.SetOps([]jose.KeyOps{jose.KeyOpsSign})

	// Act
	k, err := NewVerificationKey(&jwk)

	// Assert
	require.Equal(t, ErrInvalidOperations, err)
	require.Nil(t, k)
}