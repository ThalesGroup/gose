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

package gose

import (
	"crypto/mlkem"
	"fmt"

	"github.com/ThalesGroup/gose/jose"
)

// EncapsPubMlKemKeyImpl is the software implementation of EncapsPubMlKemKey backed by crypto/mlkem.
// "Encaps" = encapsulation (public side of the KEM), "Pub" = public key.
//
// Supported variants: ML-KEM-768 and ML-KEM-1024 (Go standard library crypto/mlkem, available since Go 1.24).
// ML-KEM-512 is defined in FIPS 203 but is absent from Go's standard library; it is only reachable
// via the HSM path (DecapsPrivMlKemHsmKey using PKCS#11).
type EncapsPubMlKemKeyImpl struct {
	jwk    jose.Jwk
	ek768  *mlkem.EncapsulationKey768
	ek1024 *mlkem.EncapsulationKey1024
}

// Kid returns the key identifier.
func (k *EncapsPubMlKemKeyImpl) Kid() string {
	return k.jwk.Kid()
}

// Algorithm returns the JWE algorithm this key is intended for.
func (k *EncapsPubMlKemKeyImpl) Algorithm() jose.Alg {
	return k.jwk.Alg()
}

// Encapsulate generates a fresh (kemCiphertext, sharedSecret) pair using the recipient's ML-KEM public key.
// The caller (JweMlKemEncryptorImpl) is responsible for passing sharedSecret through KMAC before use as a CEK.
func (k *EncapsPubMlKemKeyImpl) Encapsulate() (kemCiphertext, sharedSecret []byte, err error) {
	if k.ek768 != nil {
		ss, ct := k.ek768.Encapsulate()
		return ct, ss, nil
	}
	ss, ct := k.ek1024.Encapsulate()
	return ct, ss, nil
}

// Jwk returns the public key as a jose.EncapsPubMlKemKey JWK.
func (k *EncapsPubMlKemKeyImpl) Jwk() (jose.Jwk, error) {
	pub := &jose.EncapsPubMlKemKey{}
	pub.SetKid(k.jwk.Kid())
	pub.SetAlg(k.jwk.Alg())
	pub.SetOps([]jose.KeyOps{jose.KeyOpsEncrypt})
	if k.ek768 != nil {
		pub.Crv = jose.CrvMLKEM768
		pub.X.SetBytes(k.ek768.Bytes())
	} else {
		pub.Crv = jose.CrvMLKEM1024
		pub.X.SetBytes(k.ek1024.Bytes())
	}
	return pub, nil
}

// Marshal serializes the key to its compact JWK string representation.
func (k *EncapsPubMlKemKeyImpl) Marshal() (string, error) {
	jwk, err := k.Jwk()
	if err != nil {
		return "", err
	}
	return JwkToString(jwk)
}

// NewEncapsPubMlKemKeyImpl constructs an EncapsPubMlKemKeyImpl from a jose.EncapsPubMlKemKey JWK.
// The JWK must include key_ops containing "encrypt".
// Only CrvMLKEM768 and CrvMLKEM1024 are supported; CrvMLKEM512 requires the HSM path.
func NewEncapsPubMlKemKeyImpl(jwk *jose.EncapsPubMlKemKey) (*EncapsPubMlKemKeyImpl, error) {
	if !isSubset(jwk.Ops(), validEncryptionOps) {
		return nil, ErrInvalidOperations
	}
	impl := &EncapsPubMlKemKeyImpl{jwk: jwk}
	switch jwk.Crv {
	case jose.CrvMLKEM768:
		ek, err := mlkem.NewEncapsulationKey768(jwk.X.Bytes())
		if err != nil {
			return nil, fmt.Errorf("mlkem: invalid ML-KEM-768 encapsulation key: %w", err)
		}
		impl.ek768 = ek
	case jose.CrvMLKEM1024:
		ek, err := mlkem.NewEncapsulationKey1024(jwk.X.Bytes())
		if err != nil {
			return nil, fmt.Errorf("mlkem: invalid ML-KEM-1024 encapsulation key: %w", err)
		}
		impl.ek1024 = ek
	case jose.CrvMLKEM512:
		return nil, fmt.Errorf("mlkem: ML-KEM-512 is not supported by the software implementation (use HSM path): %w", ErrInvalidKeyType)
	default:
		return nil, ErrInvalidKeyType
	}
	return impl, nil
}
