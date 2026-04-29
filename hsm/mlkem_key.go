// Copyright 2026 Thales Group
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

package hsm

import (
	"fmt"

	"github.com/ThalesGroup/crypto11"
	"github.com/ThalesGroup/gose"
	"github.com/ThalesGroup/gose/jose"
	"github.com/miekg/pkcs11"
)

// sharedSecretTemplate returns the PKCS#11 attribute template used when deriving
// an ML-KEM shared secret on the HSM. The key is a transient (non-token) AES-256
// session object with CKA_EXTRACTABLE=true so that Bytes() can retrieve the raw
// shared secret for use in the software KMAC KDF step.
func sharedSecretTemplate() crypto11.AttributeSet {
	a := crypto11.NewAttributeSet()
	_ = a.Set(crypto11.CkaClass, pkcs11.CKO_SECRET_KEY)
	_ = a.Set(crypto11.CkaKeyType, pkcs11.CKK_AES)
	_ = a.Set(crypto11.CkaValueLen, 32)
	_ = a.Set(crypto11.CkaToken, false)
	_ = a.Set(crypto11.CkaSensitive, false)
	_ = a.Set(crypto11.CkaExtractable, true)
	return a
}

// paramSetToAlg maps a crypto11 MLKEMParameterSet to the gose JWE algorithm.
var paramSetToAlg = map[crypto11.MLKEMParameterSet]jose.Alg{
	crypto11.MLKEM512:  jose.AlgMLKEM512KMAC128,
	crypto11.MLKEM768:  jose.AlgMLKEM768KMAC256,
	crypto11.MLKEM1024: jose.AlgMLKEM1024KMAC256,
}

// --- EncapsPubMlKemHsmKey ---

// EncapsPubMlKemHsmKey wraps a crypto11.MLKEMEncapsulator (HSM ML-KEM public key) and
// implements gose.EncapsPubMlKemKey. The shared secret is derived on the HSM and then
// extracted as raw bytes for use in the software KMAC KDF step.
type EncapsPubMlKemHsmKey struct {
	kid string
	alg jose.Alg
	enc crypto11.MLKEMEncapsulator
}

// Kid returns the key identifier.
func (k *EncapsPubMlKemHsmKey) Kid() string { return k.kid }

// Algorithm returns the JWE algorithm for this key.
func (k *EncapsPubMlKemHsmKey) Algorithm() jose.Alg { return k.alg }

// Encapsulate performs ML-KEM encapsulation on the HSM, extracts the shared secret bytes,
// and returns (kemCiphertext, sharedSecret). The sharedSecret is passed to the KMAC KDF
// by JweMlKemEncryptorImpl — it does not leave the HSM in any other form.
func (k *EncapsPubMlKemHsmKey) Encapsulate() (kemCiphertext, sharedSecret []byte, err error) {
	ct, ss, err := k.enc.Encapsulate(sharedSecretTemplate())
	if err != nil {
		return nil, nil, fmt.Errorf("hsm mlkem: encapsulation failed: %w", err)
	}
	ssBytes, err := ss.Bytes()
	if err != nil {
		return nil, nil, fmt.Errorf("hsm mlkem: failed to extract shared secret: %w", err)
	}
	return ct, ssBytes, nil
}

// Jwk is not supported for HSM keys; public key bytes are not exported by this implementation.
func (k *EncapsPubMlKemHsmKey) Jwk() (jose.Jwk, error) {
	return nil, fmt.Errorf("hsm mlkem: JWK export not supported for HSM encapsulation keys")
}

// Marshal is not supported for HSM keys.
func (k *EncapsPubMlKemHsmKey) Marshal() (string, error) {
	return "", fmt.Errorf("hsm mlkem: JWK export not supported for HSM encapsulation keys")
}

// Ensure interface compliance at compile time.
var _ gose.EncapsPubMlKemKey = (*EncapsPubMlKemHsmKey)(nil)

// --- DecapsPrivMlKemHsmKey ---

// DecapsPrivMlKemHsmKey wraps a crypto11.MLKEMKeyPair (HSM ML-KEM private key) and
// implements gose.DecapsPrivMlKemKey. The decapsulation is performed on the HSM;
// only the shared secret bytes are extracted for use in the software KMAC KDF step.
type DecapsPrivMlKemHsmKey struct {
	kid     string
	alg     jose.Alg
	keyPair crypto11.MLKEMKeyPair
}

// Kid returns the key identifier.
func (k *DecapsPrivMlKemHsmKey) Kid() string { return k.kid }

// Algorithm returns the JWE algorithm for this key.
func (k *DecapsPrivMlKemHsmKey) Algorithm() jose.Alg { return k.alg }

// Decapsulate performs ML-KEM decapsulation on the HSM and returns the shared secret bytes.
// The private key never leaves the HSM; only the derived shared secret is extracted.
func (k *DecapsPrivMlKemHsmKey) Decapsulate(kemCiphertext []byte) (sharedSecret []byte, err error) {
	ss, err := k.keyPair.Decapsulate(kemCiphertext, sharedSecretTemplate())
	if err != nil {
		return nil, fmt.Errorf("hsm mlkem: decapsulation failed: %w", err)
	}
	ssBytes, err := ss.Bytes()
	if err != nil {
		return nil, fmt.Errorf("hsm mlkem: failed to extract shared secret: %w", err)
	}
	return ssBytes, nil
}

// Encapsulator returns the matching HSM public (encapsulation) key.
func (k *DecapsPrivMlKemHsmKey) Encapsulator() (gose.EncapsPubMlKemKey, error) {
	return &EncapsPubMlKemHsmKey{
		kid: k.kid,
		alg: k.alg,
		enc: k.keyPair,
	}, nil
}

// Ensure interface compliance at compile time.
var _ gose.DecapsPrivMlKemKey = (*DecapsPrivMlKemHsmKey)(nil)

// NewDecapsPrivMlKemHsmKey creates a DecapsPrivMlKemHsmKey from a crypto11.MLKEMKeyPair.
// kid identifies the key (typically the hex-encoded CKA_ID); it must match the kid stored
// in encrypted JWE tokens so the decryptor can look up the correct key.
func NewDecapsPrivMlKemHsmKey(keyPair crypto11.MLKEMKeyPair, kid string) (*DecapsPrivMlKemHsmKey, error) {
	alg, ok := paramSetToAlg[keyPair.ParameterSet()]
	if !ok {
		return nil, fmt.Errorf("hsm mlkem: unsupported ML-KEM parameter set %d", keyPair.ParameterSet())
	}
	return &DecapsPrivMlKemHsmKey{
		kid:     kid,
		alg:     alg,
		keyPair: keyPair,
	}, nil
}
