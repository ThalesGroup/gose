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
	"log"
	"testing"

	"github.com/ThalesIgnite/gose/jose"
	"github.com/stretchr/testify/mock"

	"github.com/stretchr/testify/assert"
)

type authenticatedEncryptionKeyMock struct {
	mock.Mock
}

func (encryptor *authenticatedEncryptionKeyMock) GenerateNonce() ([]byte, error) {
	args := encryptor.Called()
	return args.Get(0).([]byte), args.Error(1)
}

func (encryptor *authenticatedEncryptionKeyMock) Seal(operation jose.KeyOps, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error) {
	args := encryptor.Called(operation, nonce, plaintext, aad)
	return args.Get(0).([]byte), args.Get(1).([]byte), args.Error(2)
}

func (encryptor *authenticatedEncryptionKeyMock) Open(operation jose.KeyOps, nonce, ciphertext, aad, tag []byte) (plaintext []byte, err error) {
	args := encryptor.Called(operation, nonce, ciphertext, aad, tag)
	return args.Get(0).([]byte), args.Error(1)
}

func (encryptor *authenticatedEncryptionKeyMock) Algorithm() jose.Alg {
	args := encryptor.Called()
	return args.Get(0).(jose.Alg)
}

func (encryptor *authenticatedEncryptionKeyMock) Kid() string {
	args := encryptor.Called()
	return args.String(0)
}

func (encryptor *authenticatedEncryptionKeyMock) Jwk() (jose.Jwk, error) {
	args := encryptor.Called()
	return args.Get(0).(jose.Jwk), args.Error(1)
}

func (encryptor *authenticatedEncryptionKeyMock) Marshal() (string, error) {
	args := encryptor.Called()
	return args.String(0), args.Error(1)
}

func TestNewJweEncryptorImpl(t *testing.T) {
	keyMock := &authenticatedEncryptionKeyMock{}
	encryptor := NewJweDirectEncryptorImpl(keyMock, false)
	assert.NotNil(t, encryptor)
}

func TestJweDirectEncryptionEncryptorImpl_Encrypt(t *testing.T) {
	keyMock := &authenticatedEncryptionKeyMock{}
	keyMock.On("GenerateNonce").Return([]byte("nonce"), nil).Once()
	keyMock.On("Kid").Return("unique").Once()
	keyMock.On("Algorithm").Return(jose.AlgA256GCM).Once()
	keyMock.On("Seal", jose.KeyOpsEncrypt, []byte("nonce"), []byte("something"), mock.Anything).Return([]byte("encrypted"), []byte("tag"), nil).Once()

	encryptor := NewJweDirectEncryptorImpl(keyMock, false)

	jwe, err := encryptor.Encrypt([]byte("something"), []byte("else"))
	assert.NoError(t, err)
	assert.NotEmpty(t, jwe)

	keyMock.AssertExpectations(t)
}

func TestExampleJweDirectEncryptionEncryptorImpl_EncryptDecrypt(t *testing.T) {
	// First create a key which we use to encrypt and authenticate data.
	generator := &AuthenticatedEncryptionKeyGenerator{}
	cryptor, _, err := generator.Generate(jose.AlgA256GCM, []jose.KeyOps{jose.KeyOpsEncrypt, jose.KeyOpsDecrypt})
	if err != nil {
		panic(err)
	}

	// Now to encrypt and authenticate something .
	toEncrypt := []byte("some_data_to_encrypt")
	aad := []byte("some_data_to_authenticate")

	// Create a JWE cryptor
	jweEncryptor := NewJweDirectEncryptorImpl(cryptor, false)

	// Now encrypt
	jwe, err := jweEncryptor.Encrypt(toEncrypt, aad)
	if err != nil {
		panic(err)
	}

	// print our JWE
	log.Printf("Created JWE: %s", jwe)

	// Now to decrypt
	jweDecryptor := NewJweDirectDecryptorImpl([]AuthenticatedEncryptionKey{cryptor})

	recoveredPlaintext, recoveredAad, err := jweDecryptor.Decrypt(jwe)
	if err != nil {
		panic(err)
	}
	log.Printf("Recovered plaintext \"%s\" and AAD \"%s\"", string(recoveredPlaintext), string(recoveredAad))
}
