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
	"testing"

	"github.com/thalesignite/gose/jose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type generatorFunc func(alg jose.Alg) (SigningKey, error)

func Test_JwtGenerateVerify(t *testing.T) {
	rsaGenerator := &RsaSigningKeyGenerator{}
	ecGenerator := &ECDSASigningKeyGenerator{}

	rsaGeneratorFunc := func(alg jose.Alg) (SigningKey, error) {
		return rsaGenerator.Generate(alg, 2048, []jose.KeyOps{jose.KeyOpsSign})
	}
	ecGeneratorFunc := func(alg jose.Alg) (SigningKey, error) {
		return ecGenerator.Generate(alg, []jose.KeyOps{jose.KeyOpsSign})
	}
	cases := []struct {
		alg       jose.Alg
		generator generatorFunc
	}{
		// RSxxx
		{
			alg:       jose.AlgRS256,
			generator: rsaGeneratorFunc,
		},
		{
			alg:       jose.AlgRS384,
			generator: rsaGeneratorFunc,
		},
		{
			alg:       jose.AlgRS512,
			generator: rsaGeneratorFunc,
		},
		// PSxxx
		{
			alg:       jose.AlgPS256,
			generator: rsaGeneratorFunc,
		},
		{
			alg:       jose.AlgPS384,
			generator: rsaGeneratorFunc,
		},
		{
			alg:       jose.AlgPS512,
			generator: rsaGeneratorFunc,
		},
		// ESxxx
		{
			alg:       jose.AlgES256,
			generator: ecGeneratorFunc,
		},
		{
			alg:       jose.AlgES384,
			generator: ecGeneratorFunc,
		},
		{
			alg:       jose.AlgES512,
			generator: ecGeneratorFunc,
		},
	}

	for _, testCase := range cases {
		// Setup
		signingKey, err := testCase.generator(testCase.alg)
		require.NoError(t, err)
		verificationKey, err := signingKey.Verifier()
		require.NoError(t, err)
		jwk, err := verificationKey.Jwk()
		require.NoError(t, err)

		jwtSigner := NewJwtSigner("issuer", signingKey)

		claims := jose.SettableJwtClaims{
			Audiences: jose.Audiences{Aud: []string{"audience"}},
			Subject:   "subject",
		}

		untyped := map[string]interface{}{
			"name": "John Doe",
		}

		ks, err := NewTrustKeyStore(map[string]jose.Jwk{jwtSigner.Issuer(): jwk})
		require.NoError(t, err)
		jwtVerifier := NewJwtVerifier(ks)

		// Act, Assert
		jwt, err := jwtSigner.Sign(&claims, untyped)
		require.NoError(t, err)
		_, recoveredClaims, err := jwtVerifier.Verify(jwt, []string{"audience"})
		require.NoError(t, err)
		assert.Equal(t, claims.Audiences.Aud, recoveredClaims.Audiences.Aud)
		assert.Equal(t, claims.Subject, recoveredClaims.Subject)
		assert.NotZero(t, recoveredClaims.IssuedAt)
		assert.Equal(t, jwtSigner.Issuer(), recoveredClaims.Issuer)

		var name string
		err = recoveredClaims.UnmarshalCustomClaim("name", &name)
		require.NoError(t, err)

		assert.Equal(t, "John Doe", name)
	}
}

func Test_JwtVerifyKAT(t *testing.T) {
	// Known Answer Tests were generated using https://jwt.io
	// Setup
	testCases := []struct {
		jwk string
		jwt string
	}{
		{
			jwk: `{"crv":"P-256","kid":"12345","key_ops":["verify"],"kty":"EC","alg":"ES256","x":"EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84","y":"kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY"}`,
			jwt: `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQ1In0.eyJpc3MiOiJ0ZXN0Iiwic3ViIjoiMTIzNDU2Nzg5MCIsImF1ZCI6Imdvc2UiLCJqdGkiOiIzMWM4NzY3ZC02NzMyLTRkYjQtYjQ4OC0yMWNmMzRlNTQxMmQiLCJleHAiOjI1MTQ5ODA5OTd9.TMtlay5iUSPZ2IQHXM7qK313meUYMTtrvvTzWT1BadapM_S92MAPDtHIJ8A--jUCvPoJ-wIdGlS-mThpsWkpng`,
		},
	}

	// Act/Assert
	for _, test := range testCases {
		// Load JWK
		reader := bytes.NewReader([]byte(test.jwk))
		jwk, err := jose.UnmarshalJwk(reader)
		require.NoError(t, err)
		// Create a KeyStore
		ks, err := NewTrustKeyStore(map[string]jose.Jwk{
			"test": jwk,
		})
		require.NoError(t, err)
		// Create a verifier
		verifier := NewJwtVerifier(ks)
		// Do the deed
		_, _, err = verifier.Verify(test.jwt, []string{"gose"})
		require.NoError(t, err)
	}
}
