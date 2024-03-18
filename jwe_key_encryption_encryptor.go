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
	"crypto/rand"
	"crypto/rsa"
	"github.com/ThalesGroup/gose/jose"
)

// JweRsaKeyEncryptionEncryptorImpl implements RSA Key Encryption CEK mode.
type JweRsaKeyEncryptionEncryptorImpl struct {
	recipientJwk jose.Jwk
	recipientKey *rsa.PublicKey
	cekAlg jose.Alg
}

// Encrypt encrypts the given plaintext into a compact JWE. Optional authenticated data can be included which is appended
// to the JWE protected header.
func (e *JweRsaKeyEncryptionEncryptorImpl) Encrypt(plaintext, aad []byte) (string, error) {
	keyGenerator := &AuthenticatedEncryptionKeyGenerator{}
	cek, jwk, err := keyGenerator.Generate(e.cekAlg, []jose.KeyOps{jose.KeyOpsDecrypt, jose.KeyOpsEncrypt})
	if err != nil {
		return "", err
	}
	cekJwk := jwk.(*jose.OctSecretKey)

	nonce, err := cek.GenerateNonce()
	if err != nil {
		return "", err
	}

	var blob *jose.Blob
	var customHeaderFields jose.JweCustomHeaderFields
	if len(aad) > 0 {
		blob = &jose.Blob{B: aad}
		customHeaderFields = jose.JweCustomHeaderFields{
			OtherAad: blob,
		}
	}

	encryptedKey, err := rsa.EncryptOAEP(crypto.SHA1.New(), rand.Reader, e.recipientKey, cekJwk.K.Bytes(), nil)
	if err != nil {
		return "", err
	}

	jwe := &jose.Jwe{
		Header: jose.JweHeader{
			JwsHeader: jose.JwsHeader{
				Alg: jose.AlgRSAOAEP,
				Kid: e.recipientJwk.Kid(),
			},
			Enc:                   gcmAlgToEncMap[cekJwk.Alg()],
			JweCustomHeaderFields: customHeaderFields,
		},
		EncryptedKey: encryptedKey,
		Iv:           nonce,
		Plaintext:    plaintext,
	}
	if err = jwe.MarshalHeader(); err != nil {
		return "", err
	}

	if jwe.Ciphertext, jwe.Tag, err = cek.Seal(jose.KeyOpsEncrypt, jwe.Iv, jwe.Plaintext, jwe.MarshalledHeader); err != nil {
		return "", err
	}
	return jwe.Marshal(), nil
}

// NewJweRsaKeyEncryptionEncryptorImpl returns an instance of JweRsaKeyEncryptionEncryptorImpl configured with the given
// JWK.
func NewJweRsaKeyEncryptionEncryptorImpl(recipient jose.Jwk, contentEncryptionAlg jose.Alg) (*JweRsaKeyEncryptionEncryptorImpl, error) {
	if _, ok := authenticatedEncryptionAlgs[contentEncryptionAlg]; !ok {
		return nil, ErrInvalidAlgorithm
	}
	if !isSubset(recipient.Ops(), []jose.KeyOps{jose.KeyOpsEncrypt})  {
		return nil, ErrInvalidOperations
	}
	kek, err := LoadPublicKey(recipient, validEncryptionOpts)
	if err != nil {
		return nil, err
	}
	rsaKek, ok := kek.(*rsa.PublicKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}
	return &JweRsaKeyEncryptionEncryptorImpl{
		recipientKey: rsaKek,
		recipientJwk: recipient,
		cekAlg: contentEncryptionAlg,
	}, nil
}
