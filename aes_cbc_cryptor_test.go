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
	"crypto/rand"
	"github.com/ThalesGroup/gose/jose"
	"github.com/stretchr/testify/require"
	"testing"
)



func TestAesCbcCryptor(t *testing.T) {
	var err error
	iv := make([]byte, 16)
	_, err = rand.Read(iv)
	require.NoError(t, err)

	expectedKid := "aes0"
	expectedAlg := jose.AlgA256CBC

	// mocking the block mode cipher
	mc1 := &MockBlockMode{}
	mc1.On("BlockSize").Return(len(iv))
	require.NoError(t, err)
	c1 := NewAesCbcCryptor(mc1, expectedKid, expectedAlg)

	t.Run("testKid", func(t *testing.T) {
		testKid(t, expectedKid, c1)
	})

	t.Run("testAlgorithm", func(t *testing.T) {
		testAlgorithm(t, expectedAlg, c1)
	})

	t.Run("testSeal", func(t *testing.T) {
		// mocking the block mode cipher for encryption
		mc2 := &MockBlockMode{
			mode: ModeEncrypt,
		}
		mc2.On("BlockSize").Return(len(iv))
		require.NoError(t, err)
		c2 := NewAesCbcCryptor(mc2, expectedKid, expectedAlg)
		testSeal(t, c2)
	})

	t.Run("testOpen", func(t *testing.T) {
		// mocking the block mode cipher for decryption
		mc3 := &MockBlockMode{
			mode: ModeDecrypt,
		}
		mc3.On("BlockSize").Return(len(iv))
		require.NoError(t, err)
		c3 := NewAesCbcCryptor(mc3, expectedKid, expectedAlg)
		testOpen(t, c3)
	})
}


func testKid(t *testing.T, expectedKid string, cryptor BlockEncryptionKey){
	kid := cryptor.Kid()
	require.Equal(t, expectedKid, kid)
}

func testAlgorithm(t *testing.T, expectedAlg jose.Alg, cryptor BlockEncryptionKey){
	alg := cryptor.Algorithm()
	require.Equal(t, expectedAlg, alg)
}

func testSeal(t *testing.T, cryptor BlockEncryptionKey){
	small := []byte("ping")
	cSmall := cryptor.Seal(small)
	require.Equal(t, 0, len(cSmall)%16)
	require.NotEqual(t, small, cSmall)
	require.Contains(t, string(cSmall), mockExpectedCiphertext)

	big := []byte("pingpingpingpingpingpingpingpingpingping")
	cBig := cryptor.Seal(big)
	require.Equal(t, 0, len(cBig)%16)
	require.NotEqual(t, big, cBig)
	require.Contains(t, string(cBig), mockExpectedCiphertext)
}

func testOpen(t *testing.T, cryptor BlockEncryptionKey){
	small := []byte("ping")
	cSmall := cryptor.Open(small)
	require.Equal(t, 0, len(cSmall)%16)
	require.NotEqual(t, small, cSmall)
	require.Contains(t, string(cSmall), mockExpectedCleartext)

	big := []byte("pingpingpingpingpingpingpingpingpingping")
	cBig := cryptor.Open(big)
	require.Equal(t, 0, len(cBig)%16)
	require.NotEqual(t, big, cBig)
	require.Contains(t, string(cBig), mockExpectedCleartext)
}
