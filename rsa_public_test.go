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
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"bou.ke/monkey"
	"github.com/ThalesIgnite/gose/jose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)


func TestNewRsaPublicMarshalSucceeds(t *testing.T) {
	// Setup
	require.NotNil(t, rand.Reader)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	require.Nil(t, rsaKey.Validate())
	jwk, err := JwkFromPublicKey(rsaKey.Public(), []jose.KeyOps{jose.KeyOpsVerify}, nil)
	require.NoError(t, err)
	k, err := NewVerificationKey(jwk)
	require.NoError(t, err)

	// Act
	str, err := k.Marshal()

	// Assert
	require.NoError(t, err)
	require.NotEmpty(t, str)
	buf := bytes.NewReader([]byte(str))
	jwkOut, err := LoadJwk(buf, nil)
	require.Equal(t, jwk.Kid(), jwkOut.Kid())
	require.Equal(t, jwk.Kty(), jwkOut.Kty())
	require.Equal(t, jwk.Alg(), jwkOut.Alg())
	require.Equal(t, jwk.Ops(), jwkOut.Ops())

	goodRsaJwk := jwk.(*jose.PublicRsaKey)
	marshalledRsaJwk := jwkOut.(*jose.PublicRsaKey)
	require.Equal(t, goodRsaJwk.N, marshalledRsaJwk.N)
	require.Equal(t, goodRsaJwk.E, marshalledRsaJwk.E)
}

func TestNewRsaPublicMarshalPemSucceeds(t *testing.T) {
	// Setup
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk, err := JwkFromPublicKey(rsaKey.Public(), []jose.KeyOps{jose.KeyOpsVerify}, nil)
	require.NoError(t, err)
	k, err := NewVerificationKey(jwk)
	require.NoError(t, err)

	// Act
	str, err := k.MarshalPem()

	// Assert
	require.NoError(t, err)
	require.NotEmpty(t, str)
	block, overflow := pem.Decode([]byte(str))
	require.Empty(t, overflow)
	require.Equal(t, block.Type, rsaPublicKeyPemType)
	recoveredKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	recoveredRsaKey, ok := recoveredKey.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, recoveredRsaKey.E, rsaKey.E)
	assert.Equal(t, recoveredRsaKey.N.Cmp(rsaKey.N), 0)
}

func TestNewRsaPublicFailsWhenRsaExponentIsInvalid(t *testing.T) {
	// Setup
	var jwk jose.PublicRsaKey
	jwk.SetAlg(jose.AlgPS256)
	jwk.SetOps([]jose.KeyOps{jose.KeyOpsVerify})
	jwk.N.SetBytes([]byte("AABABB"))
	jwk.E.SetBytes([]byte("====="))

	// Act
	k, err := NewVerificationKey(&jwk)

	// Assert
	require.Equal(t, ErrInvalidExponent, err)
	require.Nil(t, k)
}

// TODO: redo the test, as monkey patching doesn't seem to work here
func TestNewVerifierVerifyPSSSucceeds(t *testing.T) {
	// Setup
	var jwk jose.PublicRsaKey
	jwk.SetAlg(jose.AlgPS256)
	jwk.SetOps([]jose.KeyOps{jose.KeyOpsVerify})
	jwk.N.SetBytes([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	jwk.E.SetBytes([]byte("AQAB"))

	defer monkey.Patch(rsa.VerifyPSS,
		func(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sig []byte, opts *rsa.PSSOptions) error {
			return nil
		}).Unpatch()

	k, err := NewVerificationKey(&jwk)

	// Assert
	require.Nil(t, err)
	require.NotNil(t, k)

	// Act
	result := k.Verify(jose.KeyOpsVerify, []byte("1234"), []byte("5678"))

	// Assert
	require.True(t, result)
}

func TestRsaPublicVerifyPkcs15Succeeds(t *testing.T) {
	// Setup
	var jwk jose.PublicRsaKey
	jwk.SetAlg(jose.AlgRS256)
	jwk.SetOps([]jose.KeyOps{jose.KeyOpsVerify})
	jwk.N.SetBytes([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	jwk.E.SetBytes([]byte("AQAB"))

	defer monkey.Patch(rsa.VerifyPKCS1v15,
		func(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error {
			return nil
		}).Unpatch()

	k, err := NewVerificationKey(&jwk)

	// Assert
	require.Nil(t, err)
	require.NotNil(t, k)

	// Act
	result := k.Verify(jose.KeyOpsVerify, []byte("1234"), []byte("5678"))

	// Assert
	require.True(t, result)
}

func TestRsaPublicVerifyFailsWhenPSSCryptoErrors(t *testing.T) {
	// Setup
	var jwk jose.PublicRsaKey
	jwk.SetAlg(jose.AlgPS256)
	jwk.SetOps([]jose.KeyOps{jose.KeyOpsVerify})
	jwk.N.SetBytes([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	jwk.E.SetBytes([]byte("AQAB"))

	defer monkey.Patch(rsa.VerifyPSS,
		func(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sig []byte, options *rsa.PSSOptions) error {
			return errors.New("Expected error")
		}).Unpatch()

	k, err := NewVerificationKey(&jwk)

	// Assert
	require.Nil(t, err)
	require.NotNil(t, k)

	// Act
	result := k.Verify(jose.KeyOpsVerify, []byte("1234"), []byte("5678"))

	// Assert
	require.False(t, result)
}

func TestRsaPublicVerifyFailsWhenPkcs15CryptoErrors(t *testing.T) {
	// Setup
	var jwk jose.PublicRsaKey
	jwk.SetAlg(jose.AlgPS256)
	jwk.SetOps([]jose.KeyOps{jose.KeyOpsVerify})
	jwk.N.SetBytes([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
	jwk.E.SetBytes([]byte("AQAB"))

	defer monkey.Patch(rsa.VerifyPKCS1v15,
		func(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error {
			return errors.New("Expected error")
		}).Unpatch()

	k, err := NewVerificationKey(&jwk)

	// Assert
	require.Nil(t, err)
	require.NotNil(t, k)

	// Act
	result := k.Verify(jose.KeyOpsVerify, []byte("1234"), []byte("5678"))

	// Assert
	require.False(t, result)
}
