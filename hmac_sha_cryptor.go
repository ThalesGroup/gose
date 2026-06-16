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

// Hash returns the HMAC of input using the underlying hash key.
//
// The supplied hash.Hash is consumed by this single operation: the caller is
// expected to provide a freshly initialised HMAC (one per encrypt/decrypt), so
// we feed the whole input with Write and finalise with Sum. This must not call
// Sum(input): the hash.Hash contract appends the digest to its argument rather
// than hashing it, which would compute HMAC of an empty message.
func (h HmacShaCryptor) Hash(input []byte) []byte {
	if _, err := h.hash.Write(input); err != nil {
		panic(err)
	}
	return h.hash.Sum(nil)
}

// NewHmacShaCryptor create a new instance of an HmacShaCryptor from the supplied parameters.
// It implements HmacKey
func NewHmacShaCryptor(kid string, hash hash.Hash) HmacKey {
	return &HmacShaCryptor{
		kid:  kid,
		hash: hash,
	}
}
