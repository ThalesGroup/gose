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
	"encoding/binary"
	"fmt"
	"github.com/ThalesGroup/gose/jose"
)

type JweDirectDecryptorBlock struct {
	aesKey  BlockEncryptionKey
	jweVerifier JweHmacVerifierImpl
}

// Decrypt and verify the given JWE returning the plaintext.
// never return a non nil aad. aad is just here to satisfy the JweDecryptor interface
func (decryptor *JweDirectDecryptorBlock) Decrypt(marshalledJwe string) (plaintext, aad []byte, err error) {
	// The following steps respect the RFC7516 decryption instructions :
	// https://datatracker.ietf.org/doc/html/rfc7516
	// The message decryption process is the reverse of the encryption
	//   process.  The order of the steps is not significant in cases where
	//   there are no dependencies between the inputs and outputs of the
	//   steps.  If any of these steps fail, the encrypted content cannot be
	//   validated.
	var jwe jose.JweRfc7516Compact
	if err = jwe.Unmarshal(marshalledJwe); err != nil {
		return nil, nil, fmt.Errorf("error unmarshalling the jwe: %v", err)
	}
	// check the algorithm in header
	if jwe.ProtectedHeader.Alg != decryptor.aesKey.Algorithm() {
		return nil, nil, fmt.Errorf("error checking the JWE protected header's algorthim. algorithm is '%v' but expected is '%v'", jwe.ProtectedHeader.Alg, decryptor.aesKey.Algorithm())
	}
	// check the keys for direct encryption
	if jwe.ProtectedHeader.Kid != decryptor.aesKey.Kid() {
		return nil, nil, fmt.Errorf("error checking the Key ID for decryption. ID is '%v' but expected is '%v'", jwe.ProtectedHeader.Kid, decryptor.aesKey.Kid())
	}

	// INTEGRITY CHECK before decryption
	integrity, err := decryptor.jweVerifier.VerifyCompact(jwe);
	if err != nil {
		return nil, nil, err
	}
	if ! integrity {
		return nil, nil, fmt.Errorf("error corrupted jwe : integrity check failed")
	}

	// decryption
	if jwe.ProtectedHeader.Zip != "" {
		err = ErrZipCompressionNotSupported
		return
	}
	plaintextBlock := decryptor.aesKey.Open(jwe.Ciphertext)

	// get the size of the final plaintext
	//input, err := jwe.ProtectedHeader.OtherAad.MarshalJSON()
	data := jwe.ProtectedHeader.OtherAad.B
	plaintextLength := binary.BigEndian.Uint64(data)
	plaintext = make([]byte, plaintextLength)
	copy(plaintext, plaintextBlock[:plaintextLength])

	return plaintext, nil, nil
}

// NewJweDirectDecryptorBlock create a new instance of a JweDirectDecryptorBlock.
func NewJweDirectDecryptorBlock(aesKey BlockEncryptionKey, hmacKey HmacKey) *JweDirectDecryptorBlock {
	// Create map out of our list of keys. The map is keyed in Kid.
	decryptor := &JweDirectDecryptorBlock{
		aesKey:  aesKey,
		jweVerifier: JweHmacVerifierImpl{hmacKey: hmacKey},
	}
	return decryptor
}
