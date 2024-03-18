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
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"

	"github.com/ThalesGroup/gose/jose"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJweDirectDecryptorImpl(t *testing.T) {
	keyMock := &authenticatedEncryptionKeyMock{}
	keyMock.On("Kid").Return("unique").Once()
	decryptor := NewJweDirectDecryptorAeadImpl([]AeadEncryptionKey{keyMock})
	require.NotNil(t, decryptor)
	assert.NotNil(t, decryptor.keystore)
}

func TestJweDirectDecryptorImpl_Decrypt_InvalidJweFormat(t *testing.T) {
	keyMock := &authenticatedEncryptionKeyMock{}
	keyMock.On("Kid").Return("unique").Once()
	decryptor := NewJweDirectDecryptorAeadImpl([]AeadEncryptionKey{keyMock})
	require.NotNil(t, decryptor)

	pt, aad, err := decryptor.Decrypt("not a jwe")

	assert.Empty(t, pt)
	assert.Empty(t, aad)
	assert.Equal(t, jose.ErrJweFormat, err)
}

func TestJweDirectDecryptorImpl_Decrypt_ZipCompressionNotSupport(t *testing.T) {
	keyMock := &authenticatedEncryptionKeyMock{}
	keyMock.On("Kid").Return("unique").Once()
	decryptor := NewJweDirectDecryptorAeadImpl([]AeadEncryptionKey{keyMock})
	require.NotNil(t, decryptor)

	fakeJwe := &jose.Jwe{
		Header: jose.JweHeader{
			JwsHeader: jose.JwsHeader{
				Alg: jose.AlgDir,
				Kid: "",
			},
			Enc: jose.EncA256GCM,
			Zip: jose.DeflateZip,
		},
		Iv:         []byte("iv"),
		Ciphertext: []byte("encrypted"),
		Tag:        []byte("tag"),
	}

	err := fakeJwe.MarshalHeader()
	require.NoError(t, err)

	marshalledJwe := fakeJwe.Marshal()

	pt, aad, err := decryptor.Decrypt(marshalledJwe)

	assert.Empty(t, pt)
	assert.Empty(t, aad)
	assert.Equal(t, ErrZipCompressionNotSupported, err)

	keyMock.AssertExpectations(t)
}

func TestJweDirectDecryptorImpl_Decrypt_InvalidKeyId(t *testing.T) {
	keyMock := &authenticatedEncryptionKeyMock{}
	keyMock.On("Kid").Return("unique").Once()
	decryptor := NewJweDirectDecryptorAeadImpl([]AeadEncryptionKey{keyMock})
	require.NotNil(t, decryptor)

	fakeJwe := &jose.Jwe{
		Header: jose.JweHeader{
			JwsHeader: jose.JwsHeader{
				Alg: jose.AlgDir,
				Kid: "",
			},
			Enc: jose.EncA256GCM,
		},
		Iv:         []byte("iv"),
		Ciphertext: []byte("encrypted"),
		Tag:        []byte("tag"),
	}

	err := fakeJwe.MarshalHeader()
	require.NoError(t, err)

	marshalledJwe := fakeJwe.Marshal()

	pt, aad, err := decryptor.Decrypt(marshalledJwe)

	assert.Empty(t, pt)
	assert.Empty(t, aad)
	assert.Equal(t, ErrInvalidKid, err)

	keyMock.AssertExpectations(t)
}

func TestJweDirectDecryptorImpl_Decrypt_UnknownKeyId(t *testing.T) {
	keyMock := &authenticatedEncryptionKeyMock{}
	keyMock.On("Kid").Return("unique").Once()
	decryptor := NewJweDirectDecryptorAeadImpl([]AeadEncryptionKey{keyMock})
	require.NotNil(t, decryptor)

	fakeJwe := &jose.Jwe{
		Header: jose.JweHeader{
			JwsHeader: jose.JwsHeader{
				Alg: jose.AlgDir,
				Kid: "unknown",
			},
			Enc: jose.EncA256GCM,
		},
		Iv:         []byte("iv"),
		Ciphertext: []byte("encrypted"),
		Tag:        []byte("tag"),
	}

	err := fakeJwe.MarshalHeader()
	require.NoError(t, err)

	marshalledJwe := fakeJwe.Marshal()

	pt, aad, err := decryptor.Decrypt(marshalledJwe)

	assert.Empty(t, pt)
	assert.Empty(t, aad)
	assert.Equal(t, ErrUnknownKey, err)

	keyMock.AssertExpectations(t)
}

func TestJweDirectDecryptorImpl_Decrypt_InvalidKeyAlg(t *testing.T) {
	keyMock := &authenticatedEncryptionKeyMock{}
	keyMock.On("Kid").Return("unique").Once()
	keyMock.On("Algorithm").Return(jose.AlgES256).Once()
	decryptor := NewJweDirectDecryptorAeadImpl([]AeadEncryptionKey{keyMock})
	require.NotNil(t, decryptor)

	fakeJwe := &jose.Jwe{
		Header: jose.JweHeader{
			JwsHeader: jose.JwsHeader{
				Alg: jose.AlgDir,
				Kid: "unique",
			},
			Enc: jose.EncA128GCM,
		},
		Iv:         []byte("iv"),
		Ciphertext: []byte("encrypted"),
		Tag:        []byte("tag"),
	}

	err := fakeJwe.MarshalHeader()
	require.NoError(t, err)

	marshalledJwe := fakeJwe.Marshal()

	pt, aad, err := decryptor.Decrypt(marshalledJwe)

	assert.Empty(t, pt)
	assert.Empty(t, aad)
	assert.Equal(t, ErrInvalidEncryption, err)

	keyMock.AssertExpectations(t)
}

func TestJweDirectDecryptorImpl_Decrypt_InvalidJweAlg(t *testing.T) {
	keyMock := &authenticatedEncryptionKeyMock{}
	keyMock.On("Kid").Return("unique").Once()
	keyMock.On("Algorithm").Return(jose.AlgA256GCM).Once()
	decryptor := NewJweDirectDecryptorAeadImpl([]AeadEncryptionKey{keyMock})
	require.NotNil(t, decryptor)

	fakeJwe := &jose.Jwe{
		Header: jose.JweHeader{
			JwsHeader: jose.JwsHeader{
				Alg: jose.AlgRS256,
				Kid: "unique",
			},
			Enc: jose.EncA128GCM,
		},
		Iv:         []byte("iv"),
		Ciphertext: []byte("encrypted"),
		Tag:        []byte("tag"),
	}

	err := fakeJwe.MarshalHeader()
	require.NoError(t, err)

	marshalledJwe := fakeJwe.Marshal()

	pt, aad, err := decryptor.Decrypt(marshalledJwe)

	assert.Empty(t, pt)
	assert.Empty(t, aad)
	assert.Equal(t, ErrInvalidAlgorithm, err)

	keyMock.AssertExpectations(t)
}

func TestJweDirectDecryptorImpl_Decrypt_InvalidJweEnc(t *testing.T) {
	keyMock := &authenticatedEncryptionKeyMock{}
	keyMock.On("Kid").Return("unique").Once()
	keyMock.On("Algorithm").Return(jose.AlgA256GCM).Once()
	decryptor := NewJweDirectDecryptorAeadImpl([]AeadEncryptionKey{keyMock})
	require.NotNil(t, decryptor)

	fakeJwe := &jose.Jwe{
		Header: jose.JweHeader{
			JwsHeader: jose.JwsHeader{
				Alg: jose.AlgDir,
				Kid: "unique",
			},
			Enc: jose.EncA128GCM,
		},
		Iv:         []byte("iv"),
		Ciphertext: []byte("encrypted"),
		Tag:        []byte("tag"),
	}

	err := fakeJwe.MarshalHeader()
	require.NoError(t, err)

	marshalledJwe := fakeJwe.Marshal()

	pt, aad, err := decryptor.Decrypt(marshalledJwe)

	assert.Empty(t, pt)
	assert.Empty(t, aad)
	assert.Equal(t, ErrInvalidAlgorithm, err)

	keyMock.AssertExpectations(t)
}

func TestJweDirectDecryptorImpl_Decrypt_InvalidCiphertextOrTag(t *testing.T) {
	expectedError := errors.New("expected")
	keyMock := &authenticatedEncryptionKeyMock{}
	keyMock.On("Algorithm").Return(jose.AlgA256GCM).Once()
	keyMock.On("Kid").Return("unique").Once()
	keyMock.On("Open", jose.KeyOpsDecrypt, []byte("iv"), []byte("encrypted"), mock.Anything, []byte("tag")).Return([]byte(nil), expectedError).Once()
	decryptor := NewJweDirectDecryptorAeadImpl([]AeadEncryptionKey{keyMock})
	require.NotNil(t, decryptor)

	fakeJwe := &jose.Jwe{
		Header: jose.JweHeader{
			JwsHeader: jose.JwsHeader{
				Alg: jose.AlgDir,
				Kid: "unique",
			},
			Enc: jose.EncA256GCM,
		},
		Iv:         []byte("iv"),
		Ciphertext: []byte("encrypted"),
		Tag:        []byte("tag"),
	}

	err := fakeJwe.MarshalHeader()
	require.NoError(t, err)

	marshalledJwe := fakeJwe.Marshal()

	pt, aad, err := decryptor.Decrypt(marshalledJwe)

	assert.Empty(t, pt)
	assert.Empty(t, aad)
	assert.Equal(t, expectedError, err)

	keyMock.AssertExpectations(t)
}

func TestJweDirectDecryptorImpl_Decrypt(t *testing.T) {
	keyMock := &authenticatedEncryptionKeyMock{}
	keyMock.On("Algorithm").Return(jose.AlgA256GCM).Once()
	keyMock.On("Kid").Return("unique").Once()
	decryptor := NewJweDirectDecryptorAeadImpl([]AeadEncryptionKey{keyMock})
	require.NotNil(t, decryptor)

	fakeJwe := &jose.Jwe{
		Header: jose.JweHeader{
			JwsHeader: jose.JwsHeader{
				Alg: jose.AlgDir,
				Kid: "unique",
			},
			JweCustomHeaderFields: jose.JweCustomHeaderFields{
				OtherAad: &jose.Blob{
					B: []byte("aad"),
				},
			},
			Enc: jose.EncA256GCM,
		},
		Iv:         []byte("iv"),
		Ciphertext: []byte("encrypted"),
		Tag:        []byte("tag"),
	}

	err := fakeJwe.MarshalHeader()
	require.NoError(t, err)
	keyMock.On("Open", jose.KeyOpsDecrypt, []byte("iv"), []byte("encrypted"), fakeJwe.MarshalledHeader, []byte("tag")).Return([]byte("decrypted"), nil).Once()

	marshalledJwe := fakeJwe.Marshal()

	pt, aad, err := decryptor.Decrypt(marshalledJwe)

	assert.Equal(t, []byte("decrypted"), pt)
	assert.Equal(t, []byte("aad"), aad)
	assert.NoError(t, err)

	keyMock.AssertExpectations(t)
}
