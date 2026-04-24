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

// DecapsPrivMlKemKeyImpl is the software implementation of DecapsPrivMlKemKey backed by crypto/mlkem.
// "Decaps" = decapsulation (private side of the KEM), "Priv" = private key.
//
// Supported variants: ML-KEM-768 and ML-KEM-1024 (Go standard library crypto/mlkem, available since Go 1.24).
// ML-KEM-512 is only reachable via the HSM path (DecapsPrivMlKemHsmKey using PKCS#11).
type DecapsPrivMlKemKeyImpl struct {
	jwk    jose.Jwk
	dk768  *mlkem.DecapsulationKey768
	dk1024 *mlkem.DecapsulationKey1024
}

// Kid returns the key identifier.
func (k *DecapsPrivMlKemKeyImpl) Kid() string {
	return k.jwk.Kid()
}

// Algorithm returns the JWE algorithm this key is intended for.
func (k *DecapsPrivMlKemKeyImpl) Algorithm() jose.Alg {
	return k.jwk.Alg()
}

// Decapsulate recovers the shared secret from the given KEM ciphertext.
// The caller (JweMlKemDecryptorImpl) is responsible for passing sharedSecret through KMAC before use as a CEK.
func (k *DecapsPrivMlKemKeyImpl) Decapsulate(kemCiphertext []byte) (sharedSecret []byte, err error) {
	if k.dk768 != nil {
		ss, err := k.dk768.Decapsulate(kemCiphertext)
		if err != nil {
			return nil, fmt.Errorf("mlkem: decapsulation failed: %w", err)
		}
		return ss, nil
	}
	ss, err := k.dk1024.Decapsulate(kemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("mlkem: decapsulation failed: %w", err)
	}
	return ss, nil
}

// Encapsulator returns the matching public (encapsulation) key.
func (k *DecapsPrivMlKemKeyImpl) Encapsulator() (EncapsPubMlKemKey, error) {
	var pubJwk jose.EncapsPubMlKemKey
	pubJwk.SetKid(k.jwk.Kid())
	pubJwk.SetAlg(k.jwk.Alg())
	pubJwk.SetOps([]jose.KeyOps{jose.KeyOpsEncrypt})
	if k.dk768 != nil {
		pubJwk.Crv = jose.CrvMLKEM768
		pubJwk.X.SetBytes(k.dk768.EncapsulationKey().Bytes())
	} else {
		pubJwk.Crv = jose.CrvMLKEM1024
		pubJwk.X.SetBytes(k.dk1024.EncapsulationKey().Bytes())
	}
	return NewEncapsPubMlKemKeyImpl(&pubJwk)
}

// NewDecapsPrivMlKemKeyImpl constructs a DecapsPrivMlKemKeyImpl from a jose.DecapsPrivMlKemKey JWK.
// The JWK must include key_ops containing "decrypt" and a non-empty D (seed) field.
// Only CrvMLKEM768 and CrvMLKEM1024 are supported; CrvMLKEM512 requires the HSM path.
func NewDecapsPrivMlKemKeyImpl(jwk *jose.DecapsPrivMlKemKey) (*DecapsPrivMlKemKeyImpl, error) {
	if !isSubset(jwk.Ops(), validDecryptionOps) {
		return nil, ErrInvalidOperations
	}
	if len(jwk.D.Bytes()) == 0 {
		return nil, ErrInvalidKey
	}
	impl := &DecapsPrivMlKemKeyImpl{jwk: jwk}
	switch jwk.Crv {
	case jose.CrvMLKEM768:
		dk, err := mlkem.NewDecapsulationKey768(jwk.D.Bytes())
		if err != nil {
			return nil, fmt.Errorf("mlkem: invalid ML-KEM-768 decapsulation key seed: %w", err)
		}
		impl.dk768 = dk
	case jose.CrvMLKEM1024:
		dk, err := mlkem.NewDecapsulationKey1024(jwk.D.Bytes())
		if err != nil {
			return nil, fmt.Errorf("mlkem: invalid ML-KEM-1024 decapsulation key seed: %w", err)
		}
		impl.dk1024 = dk
	case jose.CrvMLKEM512:
		return nil, fmt.Errorf("mlkem: ML-KEM-512 is not supported by the software implementation (use HSM path): %w", ErrInvalidKeyType)
	default:
		return nil, ErrInvalidKeyType
	}
	return impl, nil
}

// GenerateMlKemKeyPair generates a fresh ML-KEM key pair for the given curve and returns
// (DecapsPrivMlKemKeyImpl, EncapsPubMlKemKeyImpl). kid and alg are applied to both keys.
func GenerateMlKemKeyPair(crv jose.Crv, kid string, alg jose.Alg) (*DecapsPrivMlKemKeyImpl, *EncapsPubMlKemKeyImpl, error) {
	privJwk := &jose.DecapsPrivMlKemKey{}
	privJwk.SetKid(kid)
	privJwk.SetAlg(alg)
	privJwk.SetOps([]jose.KeyOps{jose.KeyOpsDecrypt})
	privJwk.Crv = crv

	impl := &DecapsPrivMlKemKeyImpl{jwk: privJwk}

	switch crv {
	case jose.CrvMLKEM768:
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			return nil, nil, fmt.Errorf("mlkem: key generation failed: %w", err)
		}
		impl.dk768 = dk
		privJwk.D.SetBytes(dk.Bytes())
		privJwk.X.SetBytes(dk.EncapsulationKey().Bytes())
	case jose.CrvMLKEM1024:
		dk, err := mlkem.GenerateKey1024()
		if err != nil {
			return nil, nil, fmt.Errorf("mlkem: key generation failed: %w", err)
		}
		impl.dk1024 = dk
		privJwk.D.SetBytes(dk.Bytes())
		privJwk.X.SetBytes(dk.EncapsulationKey().Bytes())
	case jose.CrvMLKEM512:
		return nil, nil, fmt.Errorf("mlkem: ML-KEM-512 is not supported by the software implementation (use HSM path): %w", ErrInvalidKeyType)
	default:
		return nil, nil, ErrInvalidKeyType
	}

	pub, err := impl.Encapsulator()
	if err != nil {
		return nil, nil, err
	}
	return impl, pub.(*EncapsPubMlKemKeyImpl), nil
}
