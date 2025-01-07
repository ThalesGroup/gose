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
	"crypto/sha256"
	"encoding/base64"
	"github.com/ThalesGroup/gose/jose"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestJweDirectEncryptorBlock(t *testing.T) {
    // vars
	blockSize := 16
	iv := make([]byte, blockSize)
	_, err := rand.Read(iv)
	require.NoError(t, err)
	require.NotEmpty(t, iv)
	expectedAesKid := "aes0"
	expectedHmacKid := "hmac0"
	expectedAlg := jose.AlgA256CBC

	// mocking the block mode cipher for encryption
	mcEnc := &MockBlockMode{
		mode: ModeEncrypt,
	}
	bekEnc := NewAesCbcCryptor(mcEnc, expectedAesKid, expectedAlg)
	hk := NewHmacShaCryptor(expectedHmacKid, sha256.New())
	encryptor := NewJweDirectEncryptorBlock(bekEnc, hk, iv)
	mcEnc.On("BlockSize").Return(len(iv))

	// mocking the block mode cipher for decryption
	mcDec := &MockBlockMode{
		mode: ModeDecrypt,
	}
	mcDec.On("BlockSize").Return(len(iv))
	require.NoError(t, err)
	bekDec := NewAesCbcCryptor(mcDec, expectedAesKid, expectedAlg)
	decryptor := NewJweDirectDecryptorBlock(bekDec, hk)

	// running tests
	t.Run("testEncryptDecrypt", func(t *testing.T) {
		testEncryptDecrypt(t, encryptor, decryptor, iv)
	})
}

func testEncryptDecrypt(t *testing.T, cryptor *JweDirectEncryptorBlock, decryptor *JweDirectDecryptorBlock, expectedIV []byte) {
	// **********
	// ENCRYPTION
	// **********
	marshalledJwe, err := cryptor.Encrypt([]byte(mockExpectedCleartext), nil)
	require.NoError(t, err)
	require.NotEmpty(t, marshalledJwe)

	// verify the structure
	splits := strings.Split(marshalledJwe,  ".")
	require.Equal(t, 5, len(splits))

	// For direct encryption, the encrypted key is nil
	// we expected an empty string for the second part of the JWE
	require.Empty(t, splits[1])

	// other parts should not be empty
	require.NotEmpty(t, splits[0])
	require.NotEmpty(t, splits[2])
	require.NotEmpty(t, splits[3])
	require.NotEmpty(t, splits[4])

	// verify IV
	iv, err := base64.RawURLEncoding.DecodeString(splits[2])
	require.NoError(t, err)
	require.Equal(t, expectedIV, iv)

	// verify ciphertext
	ciphertext, err := base64.RawURLEncoding.DecodeString(splits[3])
	require.NoError(t, err)
	require.Contains(t, string(ciphertext), mockExpectedCiphertext)

	// **********
	// DECRYPTION
	// **********
	plaintext, _, err := decryptor.Decrypt(marshalledJwe)
	require.NoError(t, err)

	// decryption
	require.NotEmpty(t, plaintext)
	require.Equal(t, mockExpectedCleartext, string(plaintext))
}




