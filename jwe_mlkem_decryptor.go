// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/ThalesGroup/gose/jose"
)

// JweMlKemDecryptorImpl decrypts a compact JWE produced by JweMlKemEncryptorImpl.
//
// Decryption (draft-reddy-cose-jose-pqc-kem):
//  1. Parse compact JWE; validate alg and presence of kem-ct header
//  2. Look up DecapsPrivMlKemKey by kid from keystore
//  3. KEM decapsulate kem-ct → sharedSecret
//  4. Re-marshal protected header → marshalledHeader (same bytes as encryption-time AAD)
//  5. CEK = KMAC(K=sharedSecret, X=marshalledHeader, L=cekLen, S="")
//  6. Decrypt AES-GCM(CEK, IV, ciphertext||tag, AAD=marshalledHeader) → plaintext
type JweMlKemDecryptorImpl struct {
	keystore DecapsPrivMlKemKeyStore
}

// Decrypt decrypts a compact JWE string and returns the plaintext and any additional
// authenticated data stored in the "_thales_aad" header field.
func (d *JweMlKemDecryptorImpl) Decrypt(jweRaw string) (plaintext, aad []byte, err error) {
	// Step 1: Parse compact JWE.
	var jwe jose.JweRfc7516Compact
	if err = jwe.Unmarshal(jweRaw); err != nil {
		return nil, nil, fmt.Errorf("jwe mlkem: failed to parse JWE: %w", err)
	}

	if jwe.ProtectedHeader.Zip != "" {
		return nil, nil, ErrZipCompressionNotSupported
	}

	alg := jwe.ProtectedHeader.Alg
	cekLen, ok := mlkemCekSize[alg]
	if !ok {
		return nil, nil, fmt.Errorf("jwe mlkem: unsupported algorithm %q", alg)
	}

	// Step 2: Validate kem-ct is present and non-empty.
	if jwe.ProtectedHeader.KemCt == nil || len(jwe.ProtectedHeader.KemCt.Bytes()) == 0 {
		return nil, nil, fmt.Errorf("jwe mlkem: missing kem-ct header parameter")
	}

	// Step 3: Look up decapsulation key by kid.
	privKey, err := d.keystore.Get(jwe.ProtectedHeader.Kid)
	if err != nil {
		return nil, nil, fmt.Errorf("jwe mlkem: key not found (kid=%q): %w", jwe.ProtectedHeader.Kid, err)
	}
	if privKey.Algorithm() != alg {
		return nil, nil, ErrInvalidAlgorithm
	}

	// Step 4: KEM decapsulate.
	sharedSecret, err := privKey.Decapsulate(jwe.ProtectedHeader.KemCt.Bytes())
	if err != nil {
		return nil, nil, fmt.Errorf("jwe mlkem: decapsulation failed: %w", err)
	}
	// The KEM shared secret is highly sensitive; scrub it after use.
	defer clear(sharedSecret)

	// Step 5: Re-marshal the protected header to recover the exact AAD / KDF context.
	// Go's encoding/json marshals struct fields in declaration order, so re-marshalling
	// the parsed struct produces the same bytes as the original (provided no unknown fields).
	marshalledHeader, err := jwe.ProtectedHeader.MarshalProtectedHeader()
	if err != nil {
		return nil, nil, fmt.Errorf("jwe mlkem: failed to marshal header for KDF: %w", err)
	}

	// Step 6: Derive CEK via KMAC.
	cek := deriveMlKemCEK(alg, sharedSecret, marshalledHeader, cekLen)
	defer clear(cek)

	// Step 7: Decrypt with AES-GCM.
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, nil, fmt.Errorf("jwe mlkem: failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("jwe mlkem: failed to create GCM: %w", err)
	}
	// Open expects ciphertext || tag concatenated.
	ctAndTag := make([]byte, len(jwe.Ciphertext)+len(jwe.AuthenticationTag))
	copy(ctAndTag, jwe.Ciphertext)
	copy(ctAndTag[len(jwe.Ciphertext):], jwe.AuthenticationTag)

	plaintext, err = gcm.Open(nil, jwe.InitializationVector, ctAndTag, marshalledHeader)
	if err != nil {
		return nil, nil, fmt.Errorf("jwe mlkem: authenticated decryption failed: %w", err)
	}

	// Return any application AAD that was stored in the protected header.
	if jwe.ProtectedHeader.OtherAad != nil {
		aad = jwe.ProtectedHeader.OtherAad.Bytes()
	}
	return plaintext, aad, nil
}

// NewJweMlKemDecryptorImpl creates a JweMlKemDecryptorImpl backed by the given key store.
func NewJweMlKemDecryptorImpl(keystore DecapsPrivMlKemKeyStore) *JweMlKemDecryptorImpl {
	return &JweMlKemDecryptorImpl{keystore: keystore}
}
