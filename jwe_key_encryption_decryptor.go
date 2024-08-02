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
	"crypto/aes"
	"crypto/cipher"
	"github.com/ThalesGroup/gose/jose"
)

// JweRsaKeyEncryptionDecryptorImpl implements RSA Key Encryption CEK mode.
type JweRsaKeyEncryptionDecryptorImpl struct {
	keystore AsymmetricDecryptionKeyStore
}

// Decrypt decrypts the given JWE returning the contained plaintext and any additional authentic associated data.
func (d *JweRsaKeyEncryptionDecryptorImpl) Decrypt(jwe string) (plaintext, aad []byte, err error) {
	var jweStruct jose.Jwe
	if err = jweStruct.Unmarshal(jwe); err != nil {
		return
	}

	// We do not support zip compression
	if jweStruct.Header.Zip != "" {
		err = ErrZipCompressionNotSupported
		return
	}

	var key AsymmetricDecryptionKey
	key, err = d.keystore.Get(jweStruct.Header.Kid)
	if err != nil {
		return
	}

	// Check alg is as expected
	if jweStruct.Header.Alg != key.Algorithm() {
		err = ErrInvalidAlgorithm
		return
	}

	// Check the content encryption is a support algorithm
	switch jweStruct.Header.Enc {
	case jose.EncA128GCM, jose.EncA192GCM, jose.EncA256GCM:
		// All good.
	default:
		err = ErrInvalidEncryption
		return
	}

	// First decrypt the content encryption key.
	var cekBytes []byte
	cekBytes, err = key.Decrypt(jose.KeyOpsDecrypt, jweStruct.EncryptedKey)
	if err != nil {
		return
	}
	var block cipher.Block
	block, err = aes.NewCipher(cekBytes)
	if err != nil {
		return
	}

	var aead cipher.AEAD
	aead, err = cipher.NewGCM(block)
	if err != nil {
		return
	}

	// Decrypt the JWE payload.
	ctAndTag := make([]byte, len(jweStruct.Ciphertext) + len(jweStruct.Tag))
	copy(ctAndTag[:len(jweStruct.Ciphertext)], jweStruct.Ciphertext)
	copy(ctAndTag[len(jweStruct.Ciphertext):], jweStruct.Tag)
	plaintext, err = aead.Open(nil, jweStruct.Iv, ctAndTag, jweStruct.MarshalledHeader)
	if err != nil {
		return
	}

	if jweStruct.Header.OtherAad != nil {
		aad = jweStruct.Header.OtherAad.Bytes()
	}
	return
}

// NewJweRsaKeyEncryptionDecryptorImpl creates an instance of JweRsaKeyEncryptionDecryptorImpl with the given keystore.
func NewJweRsaKeyEncryptionDecryptorImpl(keystore AsymmetricDecryptionKeyStore) *JweRsaKeyEncryptionDecryptorImpl {
	return &JweRsaKeyEncryptionDecryptorImpl{
		keystore: keystore,
	}
}

