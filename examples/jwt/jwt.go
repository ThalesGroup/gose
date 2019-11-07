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

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ThalesIgnite/gose"
	"github.com/ThalesIgnite/gose/jose"
	"os"
	"time"
)

const (
	houseNumberClaim = "house_number"
	streetClaim = "street"
)

var (
	signingOperations = []jose.KeyOps{jose.KeyOpsSign}
)

func fail(err error) {
	fmt.Println(err.Error())
	os.Exit(1)
}

func main() {
	// First create a signing key to sign a JWT. We use a generator to create our key.
	generator := &gose.RsaSigningKeyGenerator{}
	signingKey, err := generator.Generate(jose.AlgRS256, 2048, signingOperations)
	if err != nil {
		fail(err)
	}

	// Create a private key JWK and marshal to a string.
	jwk, err := signingKey.Jwk()
	if err != nil {
		fail(err)
	}
	marshalled, err := gose.JwkToString(jwk)
	if err != nil {
		fail(err)
	}
	fmt.Printf("Created signing key JWK: %s\n", marshalled)

	// Create a JWT signer specifying the issuer string and our previously generated signing key
	jwtSigner := gose.NewJwtSigner("issuer", signingKey)

	// Define the claims we want to include in our JWT. Settable claims are standard JWT claims a caller can set such as
	// the subject (sub), audience/s (aud), expiration (exp) and not before (nbf) fields.
	now := time.Now().Unix()
	standardClaims := &jose.SettableJwtClaims{
		Subject: "my subject",
		Audiences: jose.Audiences{Aud:[]string{"my audience"}},
		Expiration: now + 60, // expiration in 60 seconds
		NotBefore: now,
	}
	// Custom or non-standard claims can also be specified
	customClaims := map[string]interface{}{
		houseNumberClaim: 29,
		streetClaim: "Acacia Road",
	}
	jwt, err := jwtSigner.Sign(standardClaims, customClaims)
	if err != nil {
		fail(err)
	}
	fmt.Printf("Created signed JWT: %s\n", jwt)

	// We can get the public key for use during JWT verification.
	verificationKey, err := signingKey.Verifier()
	if err != nil {
		fail(err)
	}
	jwk, err = verificationKey.Jwk()
	if err != nil {
		fail(err)
	}
	marshalled, err = gose.JwkToString(jwk)
	if err != nil {
		fail(err)
	}
	fmt.Printf("Created verification key JWK: %s\n", marshalled)

	// JWT verification requires the use of a trust store. A trust store is a set of public JWKs and their issuer identifier.
	// A key store can be loaded from a remote JWKS via the use of gose.NewJwksKeyStore("issuer", "jwks_url") which will
	// load the JWKS via an HTTP GET request and cache keys and fetch them as required.
	keyStore, err := gose.NewTrustKeyStore(map[string]jose.Jwk{"issuer": jwk})
	if err != nil {
		fail(err)
	}
	// Create our verifier using our key store.
	jwtVerifier := gose.NewJwtVerifier(keyStore)

	// Finally verify our JWT specifying acceptable audience claim entries.
	kid, claims, err := jwtVerifier.Verify(jwt, []string{"my audience"})
	if err != nil {
		fail(err)
	}
	fmt.Printf("Successfully verified JWT signed with key %s\n", kid)

	// We can now look at the claims includes in the JWT
	fmt.Printf("JWT Subject: %s\n", claims.SettableJwtClaims.Subject)
	fmt.Printf("JWT Audiences: %v\n", claims.SettableJwtClaims.Audiences.Aud)
	fmt.Printf("JWT Expiry: %d\n", claims.SettableJwtClaims.Expiration)
	fmt.Printf("JWT Not Before: %d\n", claims.SettableJwtClaims.NotBefore)
	// Automatic claims are those specified by the JWT signer including the issued at (iat), issuer (iss) and the unique
	// JWT ID (jti).
	fmt.Printf("JWT Issued At: %d\n", claims.AutomaticJwtClaims.IssuedAt)
	fmt.Printf("JWT Issuer: %s\n", claims.AutomaticJwtClaims.Issuer)
	fmt.Printf("JWT unique ID: %s\n", claims.AutomaticJwtClaims.JwtID)

	// We can then access any custom claims we expect to be present.
	rawClaim, exists := claims.UntypedClaims[houseNumberClaim]
	if !exists {
		fail(errors.New("missing house number claim"))
	}
	var houseNumber int
	err = json.Unmarshal(rawClaim, &houseNumber)
	if err != nil {
		fail(err)
	}
	fmt.Printf("JWT custom claim house number: %d\n", houseNumber)
	rawClaim, exists = claims.UntypedClaims[streetClaim]
	if !exists {
		fail(errors.New("missing street claim"))
	}
	var street string
	err = json.Unmarshal(rawClaim, &street)
	if err != nil {
		fail(err)
	}
	fmt.Printf("JWT custom claim street: %s\n", street)
}
