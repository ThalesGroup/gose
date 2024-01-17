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
	"hash"
)

// HmacShaCryptor provides HMAC SHA functions.
// It implements the HmacKey interface.
// The hash SHA mechanism is held directly by the key corresponding to the key id (kid).
// It means that if the key provides SHA-256 mechanism, then the Hash is SHA-256
type HmacShaCryptor struct {
	kid  string
	hash hash.Hash
}

func (h HmacShaCryptor) Kid() string {
	return h.kid
}

// Hash returns the result from the SHA operation executed by the provided key
func (h HmacShaCryptor) Hash(input []byte) []byte {
	// preprocess the size of the final output
	outputSize := h.hash.Size()
	// Sum() concatenates the input with the hash result
	appendedOutput := h.hash.Sum(input)
	// extract the hash result from the hash output
	res := make([]byte, outputSize)
	copy(res, appendedOutput[len(input):])
	return res
}

// NewHmacShaCryptor create a new instance of an HmacShaCryptor from the supplied parameters.
// It implements HmacKey
func NewHmacShaCryptor(kid string, hash hash.Hash) HmacKey {
	return &HmacShaCryptor{
		kid:  kid,
		hash: hash,
	}
}
