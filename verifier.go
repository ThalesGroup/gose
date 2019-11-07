// Copyright 2019 Thales e-Security, Inc
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
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math"

	"github.com/thalesignite/gose/jose"
	"github.com/sirupsen/logrus"
)

//RsaVerificationKeyImpl implements RSA verification API
type RsaVerificationKeyImpl struct {
	key   rsa.PublicKey
	ops   []jose.KeyOps
	alg   jose.Alg
	opts  crypto.SignerOpts
	id    string
	certs []*x509.Certificate
}

const rsaPublicKeyPemType = "RSA PUBLIC KEY"

var (
	validVerificationOps = []jose.KeyOps{
		jose.KeyOpsVerify,
	}

	pssAlgs = map[jose.Alg]bool{
		jose.AlgPS256: true,
		jose.AlgPS384: true,
		jose.AlgPS512: true,
	}
)

//Kid returns the key's id
func (verifier *RsaVerificationKeyImpl) Kid() string {
	return verifier.id
}

//Algorithm returns algorithm
func (verifier *RsaVerificationKeyImpl) Algorithm() jose.Alg {
	return verifier.alg
}

//Jwk returns the public JWK
func (verifier *RsaVerificationKeyImpl) Jwk() (jose.Jwk, error) {
	jwk, err := JwkFromPublicKey(&verifier.key, verifier.ops, verifier.certs)
	if err != nil {
		return nil, err
	}
	jwk.SetAlg(verifier.alg)
	return jwk, nil
}

//Marshal returns the key marshalled to a JWK string, or error
func (verifier *RsaVerificationKeyImpl) Marshal() (string, error) {
	jwk, err := verifier.Jwk()
	if err != nil {
		return "", err
	}
	return JwkToString(jwk)
}

//MarshalPem returns the key marshalled to a PEM string, or error
func (verifier *RsaVerificationKeyImpl) MarshalPem() (string, error) {
	derEncoded, err := x509.MarshalPKIXPublicKey(&verifier.key)
	if err != nil {
		return "", err
	}

	block := pem.Block{
		Type:  rsaPublicKeyPemType,
		Bytes: derEncoded,
	}
	output := bytes.Buffer{}
	if err := pem.Encode(&output, &block); err != nil {
		return "", err
	}
	return string(output.Bytes()), nil
}

//Verify data matches signature
func (verifier *RsaVerificationKeyImpl) Verify(operation jose.KeyOps, data []byte, signature []byte) bool {
	ops := intersection(validVerificationOps, verifier.ops)
	if !isSubset(ops, []jose.KeyOps{operation}) {
		return false
	}
	digester := verifier.opts.HashFunc().New()
	if _, err := digester.Write(data); err != nil {
		logrus.Panicf("%s", err)
	}
	digest := digester.Sum(nil)
	var err error
	if _, ok := pssAlgs[verifier.alg]; ok {
		err = rsa.VerifyPSS(&verifier.key, verifier.opts.HashFunc(), digest, signature, verifier.opts.(*rsa.PSSOptions))
	} else {
		err = rsa.VerifyPKCS1v15(&verifier.key, verifier.opts.HashFunc(), digest, signature)
	}
	return err == nil
}

//Certificates for verification key
func (verifier *RsaVerificationKeyImpl) Certificates() []*x509.Certificate {
	return verifier.certs
}

//NewVerificationKey for jwk or error
func NewVerificationKey(jwk jose.Jwk) (VerificationKey, error) {
	/* Check jwk can be used to verify */
	ops := validVerificationOps
	if len(jwk.Ops()) > 0 {
		ops = intersection(validVerificationOps, jwk.Ops())
		if len(ops) == 0 {
			return nil, ErrInvalidOperations
		}
	}
	certs := jwk.X5C()
	switch v := jwk.(type) {
	case *jose.PublicRsaKey:
		if jwk.Alg() == jose.AlgPS256 || jwk.Alg() == jose.AlgPS384 || jwk.Alg() == jose.AlgPS512 ||
			jwk.Alg() == jose.AlgRS256 || jwk.Alg() == jose.AlgRS384 || jwk.Alg() == jose.AlgRS512 {
			if v.E.Int().Int64() > math.MaxInt32 {
				return nil, ErrInvalidExponent
			}
			var result RsaVerificationKeyImpl
			result.key.N = v.N.Int()
			result.key.E = int(v.E.Int().Int64())
			result.opts = algToOptsMap[jwk.Alg()]
			result.id = jwk.Kid()
			result.certs = certs
			result.ops = ops
			result.alg = v.Alg()
			return &result, nil
		}
		return nil, ErrUnsupportedKeyType
	case *jose.PublicEcKey:
		if !(jwk.Alg() == jose.AlgES256 || jwk.Alg() == jose.AlgES384 || jwk.Alg() == jose.AlgES512) {
			return nil, ErrUnsupportedKeyType
		}
		var result ECVerificationKeyImpl
		result.key.X = v.X.Int()
		result.key.Y = v.Y.Int()

		result.opts = algToOptsMap[jwk.Alg()].(*ECDSAOptions)
		result.key.Curve = result.opts.curve
		result.id = jwk.Kid()
		result.certs = certs
		result.ops = ops
		result.alg = v.Alg()
		return &result, nil
		// TODO: add symmetric verification.
	default:
		return nil, ErrUnsupportedKeyType
	}
}
