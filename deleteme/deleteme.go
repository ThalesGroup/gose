package main

import (
	"crypto"
	"crypto/rand"
	"github.com/ThalesGroup/crypto11"
	"github.com/ThalesGroup/gose"
	"github.com/ThalesGroup/gose/hsm"
	"github.com/ThalesGroup/gose/jose"
	"log"
)

func main() {
	keyLabel := []byte("rsa0")
	plaintext := []byte("hello world")
	log.Printf("Original plaintext: %s", plaintext)
	// load pkcs11 context
	ctx, err := crypto11.ConfigureFromFile("config")
	if err != nil {
		panic(err)
	}
	defer ctx.Close()

	var rsaKeyPair crypto11.SignerDecrypter
	if rsaKeyPair, err = ctx.FindRSAKeyPair(nil, keyLabel); err != nil {
		panic(err)
	}

	// ENCRYPTION
	// get public key
	pubkey := rsaKeyPair.Public()

	// generate jwk from public key
	var pubJwk jose.Jwk
	if pubJwk, err = gose.JwkFromPublicKey(pubkey, []jose.KeyOps{jose.KeyOpsEncrypt}, nil); err != nil {
		panic(err)
	}

	// encrypt plaintext
	var encryptor *gose.JweRsaKeyEncryptionEncryptorImpl
	if encryptor, err = gose.NewJweRsaKeyEncryptionEncryptorImpl(pubJwk, rand.Reader); err != nil {
		panic(err)
	}
	ciphertext, err := encryptor.Encrypt(plaintext, crypto.SHA256)

	log.Printf("Plaintext '%s' was encrypted to: '%s'", plaintext, ciphertext)

	// DECRYPTION
	//get rsa private key
	var privKey *hsm.AsymmetricDecryptionKey
	if privKey, err = hsm.NewAsymmetricDecryptionKey(ctx, rsaKeyPair, string(keyLabel)); err != nil {
		panic(err)
	}
	// create key store from private key
	store, err := gose.NewAsymmetricDecryptionKeyStoreImpl(map[string]gose.AsymmetricDecryptionKey{string(keyLabel): privKey})

	rsaKeyPair.Public()
	decryptor := gose.NewJweRsaKeyEncryptionDecryptorImpl(store)
	result, _, err := decryptor.Decrypt(ciphertext, crypto.SHA256)

	log.Printf("Decrypter ciphertext is: %s", result)


}
