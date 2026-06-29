// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"

	"github.com/ThalesGroup/gose/jose"
)

// JweMlKemEncryptorImpl encrypts plaintext into a compact JWE using ML-KEM direct key agreement.
//
// Construction (draft-ietf-jose-pqc-kem-05):
//  1. KEM encapsulate using recipient public key → (kemCt, sharedSecret)
//  2. Build protected header including ek (integrity-protected by AES-GCM AAD)
//  3. CEK = KMAC(K=sharedSecret, X=be32(len(alg))||alg||be32(keyLenBits), L=cekLen, S="")
//  4. Encrypt plaintext with AES-GCM(CEK, IV, AAD=marshalledHeader)
//  5. Produce compact JWE; EncryptedKey field is empty (direct key agreement)
type JweMlKemEncryptorImpl struct {
	recipientKey EncapsPubMlKemKey
	randomSource io.Reader
}

// Encrypt encrypts plaintext into a compact JWE string.
// aad is stored in the protected header under the custom "_thales_aad" field and authenticated
// as part of the header; it is recovered verbatim by JweMlKemDecryptorImpl.Decrypt.
func (e *JweMlKemEncryptorImpl) Encrypt(plaintext, aad []byte) (string, error) {
	alg := e.recipientKey.Algorithm()
	enc, ok := mlkemAlgToEnc[alg]
	if !ok {
		return "", fmt.Errorf("jwe mlkem: unsupported algorithm %q", alg)
	}
	cekLen, _ := mlkemCekSize[alg]

	// Step 1: KEM encapsulate.
	kemCt, sharedSecret, err := e.recipientKey.Encapsulate()
	if err != nil {
		return "", fmt.Errorf("jwe mlkem: encapsulation failed: %w", err)
	}
	// Scrub the KEM shared secret once we are done with it.
	defer clear(sharedSecret)

	// Step 2: Build protected header with ek (integrity-protected by AES-GCM AAD).
	ekBlob := &jose.Blob{}
	ekBlob.SetBytes(kemCt)
	header := &jose.JweProtectedHeader{
		JwsHeader: jose.JwsHeader{
			Alg: alg,
			Kid: e.recipientKey.Kid(),
		},
		Enc: enc,
		Ek:  ekBlob,
	}
	if aad != nil {
		header.OtherAad = &jose.Blob{}
		header.OtherAad.SetBytes(aad)
	}

	// Step 3: Marshal header → AAD and KDF context (same bytes for both).
	marshalledHeader, err := header.MarshalProtectedHeader()
	if err != nil {
		return "", fmt.Errorf("jwe mlkem: failed to marshal JWE header: %w", err)
	}

	// Step 4: Derive CEK via KMAC.
	cek := deriveMlKemCEK(alg, sharedSecret, cekLen)
	defer clear(cek)

	// Step 5: Generate IV and encrypt with AES-GCM.
	iv := make([]byte, ivSize)
	if _, err = io.ReadFull(e.randomSource, iv); err != nil {
		return "", fmt.Errorf("jwe mlkem: failed to generate IV: %w", err)
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return "", fmt.Errorf("jwe mlkem: failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("jwe mlkem: failed to create GCM: %w", err)
	}
	// Seal appends ciphertext || tag; split them for JWE compact fields.
	sealed := gcm.Seal(nil, iv, plaintext, marshalledHeader)
	tagOffset := len(sealed) - gcm.Overhead()
	ct := sealed[:tagOffset]
	tag := sealed[tagOffset:]

	// Step 6: Marshal compact JWE. EncryptedKey is empty (direct key agreement mode).
	jweData := &jose.JweRfc7516Compact{
		ProtectedHeader:      *header,
		EncryptedKey:         nil,
		InitializationVector: iv,
		Ciphertext:           ct,
		AuthenticationTag:    tag,
	}
	result, err := jweData.Marshal()
	if err != nil {
		return "", fmt.Errorf("jwe mlkem: failed to marshal JWE: %w", err)
	}
	return result, nil
}

// NewJweMlKemEncryptorImpl creates a JweMlKemEncryptorImpl for the given recipient public key.
// randomSource is used for IV generation; pass crypto/rand.Reader in production.
func NewJweMlKemEncryptorImpl(recipientKey EncapsPubMlKemKey, randomSource io.Reader) (*JweMlKemEncryptorImpl, error) {
	if _, ok := mlkemAlgToEnc[recipientKey.Algorithm()]; !ok {
		return nil, fmt.Errorf("jwe mlkem: unsupported algorithm %q", recipientKey.Algorithm())
	}
	return &JweMlKemEncryptorImpl{
		recipientKey: recipientKey,
		randomSource: randomSource,
	}, nil
}
