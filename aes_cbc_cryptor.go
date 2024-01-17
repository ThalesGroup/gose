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
	"crypto/cipher"
	"github.com/ThalesGroup/gose/jose"
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



