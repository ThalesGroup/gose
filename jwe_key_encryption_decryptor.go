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
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"github.com/ThalesGroup/gose/jose"
	"slices"
)

var supportedEncryptionAlgs = []jose.Enc{jose.EncA256GCM, jose.EncA128GCM, jose.EncA192GCM}

// JweRsaKeyEncryptionDecryptorImpl implements RSA Key Encryption CEK mode.
type JweRsaKeyEncryptionDecryptorImpl struct {
	keystore AsymmetricDecryptionKeyStore
}

// Decrypt decrypts the given JWE returning the contained plaintext and any additional authentic
// associated data.
// This method follow recommendations of https://datatracker.ietf.org/doc/html/rfc7516#section-5.2
func (d *JweRsaKeyEncryptionDecryptorImpl) Decrypt(jweRaw string, oaepHash crypto.Hash) (plaintext, aad []byte, err error) {
	// deserialize jwe
	var jwe jose.JweRfc7516Compact
	if err = jwe.Unmarshal(jweRaw); err != nil {
		return nil, nil, fmt.Errorf("error unmarshalling the jwe: %w", err)
	}

	// We do not support zip compression
	if jwe.ProtectedHeader.Zip != "" {
		err = ErrZipCompressionNotSupported
		return
	}

	// check CEK encryption is supported
	if ! slices.Contains(supportedEncryptionAlgs, jwe.ProtectedHeader.Enc) {
		return nil, nil, ErrInvalidEncryption
	}

	// load key from keystore info before CEK decryption
	var key AsymmetricDecryptionKey
	key, err = d.keystore.Get(jwe.ProtectedHeader.Kid)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting key from keystore: %w", err)
	}

	// Check alg is as expected
	if jwe.ProtectedHeader.Alg != key.Algorithm() {
		return nil, nil, ErrInvalidAlgorithm
	}

	// Decrypt CEK
	var cek []byte
	if cek, err = key.Decrypt(jose.KeyOpsDecrypt, oaepHash, jwe.EncryptedKey); err != nil {
		return
	}

	// decrypt cipher text with cek
	var block cipher.Block
	if block, err = aes.NewCipher(cek); err != nil {
		return nil, nil, fmt.Errorf("error creating AES cipher: %w", err)
	}
	var aead cipher.AEAD
	if aead, err = cipher.NewGCM(block); err != nil {
		return nil, nil, fmt.Errorf("error creating GCM AEAD: %w", err)
	}
	// concatenate ciphertext and tag for authenticated decryption
	// [ciphertext + tag] is the result of the encryption and needs to be provided for decryption
	ctAndTag := make([]byte, len(jwe.Ciphertext) + len(jwe.AuthenticationTag))
	copy(ctAndTag[:len(jwe.Ciphertext)], jwe.Ciphertext)
	copy(ctAndTag[len(jwe.Ciphertext):], jwe.AuthenticationTag)
	// retrieve aad
	if aad, err = jwe.ProtectedHeader.MarshalProtectedHeader(); err != nil {
		return nil, nil, fmt.Errorf("error getting AAD: %w", err)
	}
	plaintext, err = aead.Open(nil, jwe.InitializationVector, ctAndTag, aad)
	if err != nil {
		return
	}

	return
}

// NewJweRsaKeyEncryptionDecryptorImpl creates an instance of JweRsaKeyEncryptionDecryptorImpl with the given keystore.
func NewJweRsaKeyEncryptionDecryptorImpl(keystore AsymmetricDecryptionKeyStore) *JweRsaKeyEncryptionDecryptorImpl {
	return &JweRsaKeyEncryptionDecryptorImpl{
		keystore: keystore,
	}
}

