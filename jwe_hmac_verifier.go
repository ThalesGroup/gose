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
	"bytes"
	"fmt"
	"github.com/ThalesGroup/gose/jose"
)

// JweHmacVerifierImpl implements the JWE Verification API
type JweHmacVerifierImpl struct {
	hmacKey HmacKey
}

func computeAL(aad []byte) []byte {
	// AL = AAD length
	//  is the octet string representing the number of bits in AAD expressed as a big-endian 64-bit unsigned integer
	return uintToBytesBigEndian(uint64(len(aad)))
}

func (verifier *JweHmacVerifierImpl) VerifyCompact(jwe jose.JweRfc7516Compact) (result bool, err error){
	// AAD
	//  = ASCII(BASE64URL(UTF8(JWE Protected Header)))
	var aad []byte
	if aad, err = jwe.ProtectedHeader.MarshalProtectedHeader(); err != nil {
		return false, fmt.Errorf("error marshalling the JWE Header: %v", err)
	}
	// Input HMAC computation
	// Concatenate the AAD, the Initialization Vector, the ciphertext and the AL value.
	inputHmac := concatByteArrays([][]byte{aad, jwe.InitializationVector, jwe.Ciphertext, computeAL(aad)})
	// compute the hash of it
	outputHmac := verifier.hmacKey.Hash(inputHmac)
	return bytes.Compare(outputHmac, jwe.AuthenticationTag) == 0, nil
}

func (verifier *JweHmacVerifierImpl) ComputeHash(aad []byte, iv []byte, ciphertext []byte) []byte {
	// Encrypt Plaintext to Create Ciphertext
	// Input HMAC computation
	// Concatenate the AAD, the Initialization Vector, the ciphertext and the AL value.
	inputHmac := concatByteArrays([][]byte{aad, iv, ciphertext, computeAL(aad)})
	// compute the hash of it
	return verifier.hmacKey.Hash(inputHmac)
}

// NewJweHmacVerifier creates a JWT Verifier for a given truststore
func NewJweHmacVerifier(hmacKey HmacKey) *JweHmacVerifierImpl {
	return &JweHmacVerifierImpl{hmacKey: hmacKey}
}
