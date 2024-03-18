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
	"crypto/x509"
	"math"

	"github.com/ThalesGroup/gose/jose"
)

var (
	validVerificationOps = []jose.KeyOps{
		jose.KeyOpsVerify,
	}
)

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
	switch v := jwk.(type) {
	case *jose.PublicRsaKey:
		if jwk.Alg() == "" {
			// fallback to alg from first certificate
			if certs := jwk.X5C(); len(certs) > 0 {
				switch certs[0].SignatureAlgorithm {
				case x509.SHA256WithRSA:
					jwk.SetAlg(jose.AlgRS256)
				case x509.SHA384WithRSA:
					jwk.SetAlg(jose.AlgRS384)
				case x509.SHA512WithRSA:
					jwk.SetAlg(jose.AlgRS512)
				case x509.SHA256WithRSAPSS:
					jwk.SetAlg(jose.AlgPS256)
				case x509.SHA384WithRSAPSS:
					jwk.SetAlg(jose.AlgPS384)
				case x509.SHA512WithRSAPSS:
					jwk.SetAlg(jose.AlgPS512)
				default:
				}
			}
		}
		if jwk.Alg() == jose.AlgPS256 || jwk.Alg() == jose.AlgPS384 || jwk.Alg() == jose.AlgPS512 ||
			jwk.Alg() == jose.AlgRS256 || jwk.Alg() == jose.AlgRS384 || jwk.Alg() == jose.AlgRS512 {
			if v.E.Int().Int64() > math.MaxInt32 {
				return nil, ErrInvalidExponent
			}
			var result RsaPublicKeyImpl
			result.key.N = v.N.Int()
			result.key.E = int(v.E.Int().Int64())
			result.jwk = jwk
			result.jwk.SetOps(ops)
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
		result.key.Curve = algToOptsMap[jwk.Alg()].(*ECDSAOptions).curve
		result.jwk = jwk

		return &result, nil
		// TODO: add symmetric verification.
	default:
		return nil, ErrUnsupportedKeyType
	}
}
