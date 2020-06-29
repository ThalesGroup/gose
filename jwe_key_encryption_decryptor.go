package gose

import (
	"crypto/aes"
	"crypto/cipher"
	"github.com/ThalesIgnite/gose/jose"
)

// JweRsaKeyEncryptionEncryptorImpl implements RSA Key Encryption CEK mode.
type JweRsaKeyEncryptionDecryptorImpl struct {
	keystore map[string]AsymmetricDecryptionKey
}

func (d *JweRsaKeyEncryptionDecryptorImpl) Decrypt(jwe string) (plaintext, aad []byte, err error) {
	var jweStruct jose.Jwe
	if err = jweStruct.Unmarshal(jwe); err != nil {
		return
	}

	// We do not support zip compression
	if jweStruct.Header.Zip != "" {
		err = ErrZipCompressionNotSupported
		return
	}
	// TODO: Remove
	jweStruct.Header.Kid = "1"

	// If there's no key ID specified fail.
	if len(jweStruct.Header.Kid) == 0 {
		err = ErrInvalidKid
		return
	}

	var key AsymmetricDecryptionKey
	var exists bool
	if key, exists = d.keystore[jweStruct.Header.Kid]; !exists {
		err = ErrUnknownKey
		return
	}

	// Check alg is as expected
	if jweStruct.Header.Alg != key.Algorithm() {
		err = ErrInvalidAlgorithm
		return
	}

	// Check the content encryption is a support algorithm
	switch jweStruct.Header.Enc {
	case jose.EncA128GCM, jose.EncA192GCM, jose.EncA256GCM:
		// All good.
	default:
		err = ErrInvalidEncryption
		return
	}

	// First decrypt the content encryption key.
	var cekBytes []byte
	cekBytes, err = key.Decrypt(jose.KeyOpsDecrypt, jweStruct.EncryptedKey)
	if err != nil {
		return
	}
	var block cipher.Block
	block, err = aes.NewCipher(cekBytes)
	if err != nil {
		return
	}

	var aead cipher.AEAD
	aead, err = cipher.NewGCM(block)
	if err != nil {
		return
	}

	// Decrypt the JWE payload.
	ctAndTag := make([]byte, len(jweStruct.Ciphertext) + len(jweStruct.Tag))
	copy(ctAndTag[:len(jweStruct.Ciphertext)], jweStruct.Ciphertext)
	copy(ctAndTag[len(jweStruct.Ciphertext):], jweStruct.Tag)
	plaintext, err = aead.Open(nil, jweStruct.Iv, ctAndTag, jweStruct.MarshalledHeader)
	if err != nil {
		return
	}

	if jweStruct.Header.OtherAad != nil {
		aad = jweStruct.Header.OtherAad.Bytes()
	}
	return
}

func NewJweRsaKeyEncryptionDecryptorImpl(keystore map[string]AsymmetricDecryptionKey) *JweRsaKeyEncryptionDecryptorImpl {
	return &JweRsaKeyEncryptionDecryptorImpl{
		keystore: keystore,
	}
}

