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
	"crypto/x509"
	"testing"

	"crypto"

	"github.com/ThalesGroup/gose/jose"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type MockedJwk struct {
	mock.Mock
}

func (jwk *MockedJwk) Alg() jose.Alg {
	args := jwk.Called()
	return args.Get(0).(jose.Alg)
}

func (jwk *MockedJwk) SetAlg(alg jose.Alg) {
	jwk.Called(alg)
}

func (jwk *MockedJwk) Ops() []jose.KeyOps {
	args := jwk.Called()
	return args.Get(0).([]jose.KeyOps)
}

func (jwk *MockedJwk) SetOps(ops []jose.KeyOps) {
	jwk.Called(ops)
}

func (jwk *MockedJwk) Kid() string {
	args := jwk.Called()
	return args.String(0)
}

func (jwk *MockedJwk) SetKid(kid string) {
	jwk.Called(kid)
}

func (jwk *MockedJwk) Kty() string {
	args := jwk.Called()
	return args.String(0)
}

func (jwk *MockedJwk) SetKty(kty string) {
	jwk.Called(kty)
}

func (jwk *MockedJwk) Use() jose.KeyUse {
	args := jwk.Called()
	return args.Get(0).(jose.KeyUse)
}

func (jwk *MockedJwk) SetUse(use jose.KeyUse) {
	jwk.Called(use)
}

func (jwk *MockedJwk) X5C() []*x509.Certificate {
	args := jwk.Called()
	return args.Get(0).([]*x509.Certificate)
}

func (jwk *MockedJwk) SetX5C(certs []*x509.Certificate) {
	jwk.Called(certs)
}

type MockedSigner struct {
	mock.Mock
}

func (signer *MockedSigner) Key() crypto.Signer {
	args := signer.Called()
	return args.Get(0).(crypto.Signer)
}

func (signer *MockedSigner) Algorithm() jose.Alg {
	args := signer.Called()
	return args.Get(0).(jose.Alg)
}

func (signer *MockedSigner) Jwk() (jose.Jwk, error) {
	args := signer.Called()
	return args.Get(0).(jose.Jwk), args.Error(1)
}

func (signer *MockedSigner) Sign(operation jose.KeyOps, payload []byte) (signature []byte, err error) {
	args := signer.Called(operation, payload)
	sig := args.Get(0)
	err = args.Error(1)
	if sig != nil {
		signature = sig.([]byte)
	}
	return
}

func (signer *MockedSigner) Marshal() (string, error) {
	args := signer.Called()
	return args.String(0), args.Error(1)
}

func (signer *MockedSigner) MarshalPem() (string, error) {
	args := signer.Called()
	return args.String(0), args.Error(1)
}

func (signer *MockedSigner) Certificates() []*x509.Certificate {
	args := signer.Called()
	return args.Get(0).([]*x509.Certificate)
}

func (signer *MockedSigner) Kid() string {
	args := signer.Called()
	return args.Get(0).(string)
}

func (signer *MockedSigner) Verifier() (VerificationKey, error) {
	args := signer.Called()
	return args.Get(0).(VerificationKey), args.Error(1)
}

func TestNewSigningKey_Succeeds(t *testing.T) {
	// Setup
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk, err := JwkFromPrivateKey(k, []jose.KeyOps{jose.KeyOpsSign}, nil)
	require.NoError(t, err)

	// Act
	signer, err := NewSigningKey(jwk, []jose.KeyOps{jose.KeyOpsSign})

	// Assert
	require.NoError(t, err)
	require.NotNil(t, signer)
}

func TestNewSigningKey_FailsWhenInvalidOperations(t *testing.T) {
	// Setup
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	testCase := [][]jose.KeyOps{
		{jose.KeyOpsVerify},
		{jose.KeyOpsSign, jose.KeyOpsVerify},
	}
	for _, test := range testCase {
		jwk, err := JwkFromPrivateKey(k, []jose.KeyOps{jose.KeyOpsSign}, nil)
		require.NoError(t, err)

		// Act
		signer, err := NewSigningKey(jwk, test)

		// Assert
		require.Nil(t, signer)
		require.Equal(t, ErrInvalidOperations, err)
	}
}

func TestNewSigningKey_FailsWhenInvalidJwk(t *testing.T) {
	// Setup
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk, err := JwkFromPublicKey(k.Public(), []jose.KeyOps{jose.KeyOpsSign}, nil)
	require.NoError(t, err)

	// Act
	signer, err := NewSigningKey(jwk, []jose.KeyOps{jose.KeyOpsSign})

	// Assert
	require.Error(t, err)
	require.Nil(t, signer)
}