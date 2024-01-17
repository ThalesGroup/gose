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

import "github.com/ThalesGroup/gose/jose"

var _ JweDecryptor = (*JweDirectDecryptorAeadImpl)(nil)

// JweDirectDecryptorAeadImpl is a concrete implementation of the JweDirectDecryptor interface.
type JweDirectDecryptorAeadImpl struct {
	keystore map[string]AeadEncryptionKey
}

// Decrypt and verify the given JWE returning both the plaintext and AAD.
func (decryptor *JweDirectDecryptorAeadImpl) Decrypt(jwe string) (plaintext, aad []byte, err error) {

	var jweStruct jose.Jwe
	if err = jweStruct.Unmarshal(jwe); err != nil {
		return
	}

	// We do not support zip conpression
	if jweStruct.Header.Zip != "" {
		err = ErrZipCompressionNotSupported
		return
	}

	// If there's no key ID specified fail.
	if len(jweStruct.Header.Kid) == 0 {
		err = ErrInvalidKid
		return
	}

	var key AeadEncryptionKey
	var exists bool
	if key, exists = decryptor.keystore[jweStruct.Header.Kid]; !exists {
		err = ErrUnknownKey
		return
	}

	enc, ok := gcmAlgToEncMap[key.Algorithm()]
	if !ok {
		err = ErrInvalidEncryption
		return
	}

	// Check alg is as expected, it's a direct encryption.
	if jweStruct.Header.Alg != jose.AlgDir || jweStruct.Header.Enc != enc {
		err = ErrInvalidAlgorithm
		return
	}

	if plaintext, err = key.Open(jose.KeyOpsDecrypt, jweStruct.Iv, jweStruct.Ciphertext, jweStruct.MarshalledHeader, jweStruct.Tag); err != nil {
		return
	}

	if jweStruct.Header.OtherAad != nil {
		aad = jweStruct.Header.OtherAad.Bytes()
	}

	return
}

// NewJweDirectDecryptorAeadImpl create a new instance of a JweDirectDecryptorAeadImpl.
func NewJweDirectDecryptorAeadImpl(keys []AeadEncryptionKey) *JweDirectDecryptorAeadImpl {
	// Create map out of our list of keys. The map is keyed in Kid.
	decryptor := &JweDirectDecryptorAeadImpl{
		keystore: map[string]AeadEncryptionKey{},
	}
	for _, key := range keys {
		decryptor.keystore[key.Kid()] = key
	}
	return decryptor
}
