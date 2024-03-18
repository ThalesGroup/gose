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
	"github.com/ThalesGroup/gose/jose"
)

var (
	gcmAlgToEncMap = map[jose.Alg]jose.Enc{
		jose.AlgA128GCM: jose.EncA128GCM,
		jose.AlgA192GCM: jose.EncA192GCM,
		jose.AlgA256GCM: jose.EncA256GCM,
	}
)

// JweDirectEncryptorAead implementation of JweDirectEncryptionEncryptor interface.
type JweDirectEncryptorAead struct {
	key        AeadEncryptionKey
	externalIV bool
}

// Encrypt encrypt and authenticate the given plaintext and AAD returning a compact JWE.
func (encryptor *JweDirectEncryptorAead) Encrypt(plaintext, aad []byte) (string, error) {
	var nonce []byte
	var err error
	if !encryptor.externalIV {
		nonce, err = encryptor.key.GenerateNonce()
		if err != nil {
			return "", err
		}
	}

	var blob *jose.Blob
	var customHeaderFields jose.JweCustomHeaderFields
	if len(aad) > 0 {
		blob = &jose.Blob{B: aad}
		customHeaderFields = jose.JweCustomHeaderFields{
			OtherAad: blob,
		}
	}

	jwe := &jose.Jwe{
		Header: jose.JweHeader{
			JwsHeader: jose.JwsHeader{
				Alg: jose.AlgDir,
				Kid: encryptor.key.Kid(),
			},
			Enc:                   gcmAlgToEncMap[encryptor.key.Algorithm()],
			JweCustomHeaderFields: customHeaderFields,
		},
		EncryptedKey: []byte{},
		Iv:           nonce,
		Plaintext:    plaintext,
	}
	if err = jwe.MarshalHeader(); err != nil {
		return "", err
	}

	if jwe.Ciphertext, jwe.Tag, err = encryptor.key.Seal(jose.KeyOpsEncrypt, jwe.Iv, jwe.Plaintext, jwe.MarshalledHeader); err != nil {
		return "", err
	}
	if encryptor.externalIV {
		/*
			If using an externally-generated IV this will have been returned in the tag field
			So we trim the tag field and update the IV field
		*/
		var throwawayNonceToGetLength []byte
		if throwawayNonceToGetLength, err = encryptor.key.GenerateNonce(); nil != err {
			return "", err
		}
		jwe.Iv = jwe.Tag[len(jwe.Tag)-len(throwawayNonceToGetLength):]
		jwe.Tag = jwe.Tag[:len(jwe.Tag)-len(throwawayNonceToGetLength)]
	}
	return jwe.Marshal(), nil
}

// NewJweDirectEncryptorAead construct an instance of a JweDirectEncryptorAead.
func NewJweDirectEncryptorAead(key AeadEncryptionKey, externalIV bool) *JweDirectEncryptorAead {
	return &JweDirectEncryptorAead{
		key:        key,
		externalIV: externalIV,
	}
}
