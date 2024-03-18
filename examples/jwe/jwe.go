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

package main

import (
	"fmt"
	"github.com/ThalesGroup/gose"
	"github.com/ThalesGroup/gose/jose"
	"os"
)

var (
	keyOps = []jose.KeyOps{jose.KeyOpsDecrypt, jose.KeyOpsEncrypt}
)

const (
	secretData        = "This is a really secret thing"
	authenticatedData = "This data is authenticated and publicly readable"
)

func fail(err error) {
	fmt.Println(err.Error())
	os.Exit(1)
}

func main() {
	// Firstly we create an encryption key for encrypting data using a Direct Encryption JWE encryption scheme.
	generator := gose.AuthenticatedEncryptionKeyGenerator{}
	var jwk jose.Jwk
	key, jwk, err := generator.Generate(jose.AlgA256GCM, keyOps)
	if err != nil {
		fail(err)
	}
	marshalled, err := gose.JwkToString(jwk)
	if err != nil {
		fail(err)
	}
	fmt.Printf("Created encryption key JWK: %s\n", marshalled)

	// Create an encryptor using our key.
	encryptor := gose.NewJweDirectEncryptorAead(key, false)

	// Our encryptor accepts both secret data ti be encrypted as well as additional data to be included in the JWE as an
	// authenticated and non-repudiable value. The aad value is included in the JWE header in the _thales_aad field.
	jwe, err := encryptor.Encrypt([]byte(secretData), []byte(authenticatedData))
	if err != nil {
		fail(err)
	}
	fmt.Printf("Created JWE: %s\n", jwe)

	// Now we create a decryptor to decrypt and verify the authenticity of a previously created JWE.
	key, err = gose.NewAesGcmCryptorFromJwk(jwk, []jose.KeyOps{jose.KeyOpsDecrypt})
	if err != nil {
		fail(err)
	}
	decryptor := gose.NewJweDirectDecryptorAeadImpl([]gose.AeadEncryptionKey{key})

	// Decrypt a JWE blob verifying it's authenticity in the process.
	plaintext, aad, err := decryptor.Decrypt(jwe)
	if err != nil {
		fail(err)
	}

	fmt.Printf("Decrypted JWE plaintext: %s\n", string(plaintext))
	fmt.Printf("JWE Authenticated Data: %s\n", string(aad))
}
