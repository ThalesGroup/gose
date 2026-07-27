// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"crypto/cipher"
	"github.com/eclipse-keypont/gose/jose"
)

// AesCbcCryptor provides AES CBC encryption and decryption functions.
// It implements BlockEcryptionKey
type AesCbcCryptor struct {
	kid  string
	alg  jose.Alg
	blockCipher cipher.BlockMode
}

// NewAesCbcCryptor create a new instance of an AesCbcCryptor from the supplied parameters.
// It implements AeadEncryptionKey
func NewAesCbcCryptor(blockCipher cipher.BlockMode, kid string, alg jose.Alg) BlockEncryptionKey {
	return &AesCbcCryptor{
		kid:  kid,
		alg:  alg,
		blockCipher: blockCipher,
	}
}

func (cryptor *AesCbcCryptor) trimSize(input []byte) (res []byte) {
	blockSize := cryptor.blockCipher.BlockSize()
	if len(input) % blockSize != 0 {
		multiplier := len(input) / blockSize
		res = make([]byte, (multiplier + 1)*blockSize)
		copy(res, input)
		return
	}
	return input
}

func (cryptor *AesCbcCryptor) Kid() string {
	return cryptor.kid
}

func (cryptor *AesCbcCryptor) Algorithm() jose.Alg {
	return cryptor.alg
}

func getDestinationSize(inputLength int, blockSize int) int {
	var finalSize int
	if multiplier := inputLength / blockSize; multiplier > 0 {
		finalSize = multiplier*blockSize + blockSize
	} else {
		finalSize = blockSize
	}
	return finalSize
}

func (cryptor *AesCbcCryptor) Seal(plaintext []byte) []byte {
	src := cryptor.trimSize(plaintext)
	dstSize := getDestinationSize(len(plaintext), cryptor.blockCipher.BlockSize())
	dst := make([]byte, dstSize)
	cryptor.blockCipher.CryptBlocks(dst, src)
	return dst
}

func (cryptor *AesCbcCryptor) Open(ciphertext []byte) []byte {
	dstSize := getDestinationSize(len(ciphertext), cryptor.blockCipher.BlockSize())
	dst := make([]byte, dstSize)
	cryptor.blockCipher.CryptBlocks(dst, ciphertext)
	return dst
}



