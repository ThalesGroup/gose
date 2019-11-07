// Copyright 2019 Thales e-Security, Inc
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
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"regexp"
	"testing"

	"github.com/thalesignite/gose/jose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKID(t *testing.T) {
	// Setup
	var jwk jose.PublicRsaKey
	jwk.N.SetBytes([]byte("12345678"))
	jwk.E.SetBytes([]byte("87654321"))

	// Act
	uid, err := CalculateKeyID(&jwk)

	// Assert
	assert.NoError(t, err)
	assert.Regexp(t, regexp.MustCompile("^[a-z0-9]{64}$"), uid)
}

func TestPrivateKeySerializeationAndDeserialization(t *testing.T) {
	// Setup
	expectedOps := []jose.KeyOps{jose.KeyOpsSign}
	originalKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Act
	jwk, err := JwkFromPrivateKey(originalKey, expectedOps, nil)
	require.NoError(t, err)
	recoveredKey, err := LoadPrivateKey(jwk, nil)
	require.NoError(t, err)

	// Assert
	recoveredRsaKey, ok := recoveredKey.(*rsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, originalKey.E, recoveredRsaKey.E)
	assert.Equal(t, originalKey.N.Cmp(recoveredRsaKey.N), 0)
	assert.Equal(t, originalKey.D.Cmp(recoveredRsaKey.D), 0)
	require.Equal(t, len(originalKey.Primes), len(recoveredRsaKey.Primes))
	for i, prime := range originalKey.Primes {
		assert.Equal(t, prime.Cmp(recoveredRsaKey.Primes[i]), 0)
	}
	assert.Equal(t, originalKey.Precomputed.Qinv.Cmp(recoveredRsaKey.Precomputed.Qinv), 0)
	assert.Equal(t, originalKey.Precomputed.Dq.Cmp(recoveredRsaKey.Precomputed.Dq), 0)
	assert.Equal(t, originalKey.Precomputed.Dp.Cmp(recoveredRsaKey.Precomputed.Dp), 0)
	require.Equal(t, len(originalKey.Precomputed.CRTValues), len(recoveredRsaKey.Precomputed.CRTValues))
	for i, value := range originalKey.Precomputed.CRTValues {
		assert.Equal(t, value.Coeff.Cmp(recoveredRsaKey.Precomputed.CRTValues[i].Coeff), 0)
		assert.Equal(t, value.Exp.Cmp(recoveredRsaKey.Precomputed.CRTValues[i].Exp), 0)
		assert.Equal(t, value.R.Cmp(recoveredRsaKey.Precomputed.CRTValues[i].R), 0)
	}
	require.Equal(t, len(expectedOps), len(jwk.Ops()))
	for i, got := range jwk.Ops() {
		assert.Equal(t, expectedOps[i], got)
	}
}

func TestPublicKeySerializeationAndDeserialization(t *testing.T) {
	// Setup
	expectedOps := []jose.KeyOps{jose.KeyOpsVerify}
	originalKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Act
	jwk, err := JwkFromPublicKey(originalKey.Public(), expectedOps, nil)
	require.NoError(t, err)
	recoveredKey, err := LoadPublicKey(jwk, nil)
	require.NoError(t, err)

	// Assert
	recoveredRsaKey, ok := recoveredKey.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, originalKey.E, recoveredRsaKey.E)
	assert.Equal(t, originalKey.N.Cmp(recoveredRsaKey.N), 0)
	require.Equal(t, len(expectedOps), len(jwk.Ops()))
	for i, got := range jwk.Ops() {
		assert.Equal(t, expectedOps[i], got)
	}
}

func TestAESKeySerializationAndDeserialization(t *testing.T) {
	var err error
	key8 := make([]byte, 8)
	key16 := make([]byte, 16)
	key24 := make([]byte, 24)
	key32 := make([]byte, 32)
	_, err = rand.Read(key8)
	require.NoError(t, err)
	_, err = rand.Read(key16)
	require.NoError(t, err)
	_, err = rand.Read(key24)
	require.NoError(t, err)
	_, err = rand.Read(key32)
	require.NoError(t, err)

	var jwk16, jwk24, jwk32 jose.Jwk
	jwk16, err = JwkFromSymmetric(key8, jose.AlgA128GCM)
	assert.Error(t, err, ErrInvalidKeyLength)
	jwk16, err = JwkFromSymmetric(key24, jose.AlgA128GCM)
	assert.Error(t, err, ErrInvalidKeyLength)

	jwk16, err = JwkFromSymmetric(key16, jose.AlgA128GCM)
	assert.NoError(t, err)
	jwk24, err = JwkFromSymmetric(key24, jose.AlgA192GCM)
	assert.NoError(t, err)
	jwk32, err = JwkFromSymmetric(key32, jose.AlgA256GCM)
	assert.NoError(t, err)

	var out16, out24, out32 []byte
	out16, err = loadSymmetricBytes(jwk16, nil)
	require.NoError(t, err)
	assert.Equal(t, key16, out16)
	out24, err = loadSymmetricBytes(jwk24, nil)
	require.NoError(t, err)
	assert.Equal(t, key24, out24)
	out32, err = loadSymmetricBytes(jwk32, nil)
	require.NoError(t, err)
	assert.Equal(t, key32, out32)
}

func TestAESKeyUse(t *testing.T) {
	var err error
	key16 := make([]byte, 16)
	_, err = rand.Read(key16)
	require.NoError(t, err)
	var jwk16 jose.Jwk
	jwk16, err = JwkFromSymmetric(key16, jose.AlgA128GCM)
	require.NoError(t, err)
	var aead cipher.AEAD
	aead, err = LoadSymmetricAEAD(jwk16, nil)
	require.NoError(t, err)
	// Seal something
	iv := make([]byte, 12)
	_, err = rand.Read(iv)
	require.NoError(t, err)
	var ciphertext []byte
	ciphertext = aead.Seal(ciphertext, iv, []byte("the boy's not right"), []byte("not secret"))
	// Open and check
	var plaintext []byte
	plaintext, err = aead.Open(plaintext, iv, ciphertext, []byte("not secret"))
	require.NoError(t, err)
	require.Equal(t, plaintext, []byte("the boy's not right"))
	// Negative tests
	_, err = aead.Open(plaintext, iv, ciphertext, []byte("not right"))
	assert.NotNil(t, err)
	ciphertext[0] ^= 1
	_, err = aead.Open(plaintext, iv, ciphertext, []byte("not secret"))
	assert.NotNil(t, err)
	ciphertext[0] ^= 1
	ciphertext[len(ciphertext)-1] ^= 1
	_, err = aead.Open(plaintext, iv, ciphertext, []byte("not secret"))
	assert.NotNil(t, err)
}

func TestIsSubset(t *testing.T) {
	// Setup
	testCases := []struct {
		set      []jose.KeyOps
		subset   []jose.KeyOps
		expected bool
	}{
		{
			set:      []jose.KeyOps{jose.KeyOpsVerify},
			subset:   []jose.KeyOps{jose.KeyOpsVerify},
			expected: true,
		},
		{
			set:      []jose.KeyOps{jose.KeyOpsVerify},
			subset:   []jose.KeyOps{jose.KeyOpsSign},
			expected: false,
		},
		{
			set:      []jose.KeyOps{},
			subset:   []jose.KeyOps{jose.KeyOpsVerify},
			expected: false,
		},
		{
			set:      []jose.KeyOps{jose.KeyOpsVerify},
			subset:   []jose.KeyOps{},
			expected: false,
		},
	}

	// Act + Assert
	for _, test := range testCases {
		result := isSubset(test.set, test.subset)
		assert.Equal(t, test.expected, result)
	}
}

func TestIntersection(t *testing.T) {
	// Setup
	testCases := []struct {
		first    []jose.KeyOps
		second   []jose.KeyOps
		expected []jose.KeyOps
	}{
		{
			first:    []jose.KeyOps{jose.KeyOpsVerify},
			second:   []jose.KeyOps{jose.KeyOpsVerify},
			expected: []jose.KeyOps{jose.KeyOpsVerify},
		},
		{
			first:    []jose.KeyOps{jose.KeyOpsSign},
			second:   []jose.KeyOps{jose.KeyOpsVerify},
			expected: []jose.KeyOps{},
		},
		{
			first:    []jose.KeyOps{jose.KeyOpsSign, jose.KeyOpsVerify},
			second:   []jose.KeyOps{jose.KeyOpsVerify, jose.KeyOpsSign},
			expected: []jose.KeyOps{jose.KeyOpsVerify, jose.KeyOpsSign},
		},
	}

	for _, test := range testCases {
		// Act + Assert
		received := intersection(test.first, test.second)
		require.Equal(t, len(test.expected), len(received))
		for _, expectedOp := range test.expected {
			found := false
			for _, receivedOp := range received {
				if expectedOp == receivedOp {
					found = true
				}
			}
			assert.True(t, found)
		}
	}
}

func TestRsaBitsToAlg(t *testing.T) {
	testCases := []struct {
		input    int
		expected jose.Alg
	}{
		{
			input:    1024,
			expected: jose.AlgPS256,
		},
		{
			input:    2048,
			expected: jose.AlgPS256,
		},
		{
			input:    3072,
			expected: jose.AlgPS256,
		},
		{
			input:    7680,
			expected: jose.AlgPS384,
		},
		{
			input:    15360,
			expected: jose.AlgPS512,
		},
	}
	// Act + Assert
	for _, test := range testCases {
		result := rsaBitsToAlg(test.input)
		assert.Equal(t, test.expected, result)
	}
}
