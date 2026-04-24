// Copyright 2026 Thales Group
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
	"crypto/sha3"

	"github.com/ThalesGroup/gose/jose"
)

// mlkemAlgToEnc maps each ML-KEM JWE algorithm to its content encryption algorithm.
// The CEK length is determined by the KMAC output length, which matches the enc key size.
var mlkemAlgToEnc = map[jose.Alg]jose.Enc{
	jose.AlgMLKEM512KMAC128:  jose.EncA128GCM, // KMAC128 → 128-bit CEK → A128GCM
	jose.AlgMLKEM768KMAC256:  jose.EncA256GCM, // KMAC256 → 256-bit CEK → A256GCM
	jose.AlgMLKEM1024KMAC256: jose.EncA256GCM, // KMAC256 → 256-bit CEK → A256GCM
}

// mlkemCekSize maps each ML-KEM JWE algorithm to its CEK size in bytes.
var mlkemCekSize = map[jose.Alg]int{
	jose.AlgMLKEM512KMAC128:  16, // 128 bits
	jose.AlgMLKEM768KMAC256:  32, // 256 bits
	jose.AlgMLKEM1024KMAC256: 32, // 256 bits
}

// deriveMlKemCEK derives a content encryption key from an ML-KEM shared secret using KMAC
// as specified in draft-reddy-cose-jose-pqc-kem.
//
// Parameters per NIST SP 800-185:
//   - K (key):        sharedSecret from KEM encapsulation/decapsulation
//   - X (data):       marshalledHeader — the base64url-encoded JWE protected header,
//                     which binds the KEM ciphertext and algorithm to the derived key
//   - L (outputLen):  CEK size in bytes (16 or 32)
//   - S (customization): empty string, as specified by the draft
func deriveMlKemCEK(alg jose.Alg, sharedSecret, marshalledHeader []byte, outputLen int) []byte {
	if alg == jose.AlgMLKEM512KMAC128 {
		return kmac128(sharedSecret, marshalledHeader, outputLen)
	}
	return kmac256(sharedSecret, marshalledHeader, outputLen)
}

// kmac128 computes KMAC128(K=key, X=data, L=outputLen bytes, S="") per NIST SP 800-185.
// Built on top of cSHAKE128 from the Go standard library (crypto/sha3, Go 1.26+).
func kmac128(key, data []byte, outputLen int) []byte {
	// KMAC128(K, X, L, S) = cSHAKE128(bytepad(encode_string(K), 168) || X || right_encode(L*8), L, "KMAC", S="")
	h := sha3.NewCSHAKE128([]byte("KMAC"), nil)
	h.Write(bytepad(encodeString(key), 168))
	h.Write(data)
	h.Write(rightEncode(uint64(outputLen * 8)))
	out := make([]byte, outputLen)
	h.Read(out) //nolint:errcheck // XOF Read never returns an error
	return out
}

// kmac256 computes KMAC256(K=key, X=data, L=outputLen bytes, S="") per NIST SP 800-185.
// Built on top of cSHAKE256 from the Go standard library (crypto/sha3, Go 1.26+).
func kmac256(key, data []byte, outputLen int) []byte {
	// KMAC256(K, X, L, S) = cSHAKE256(bytepad(encode_string(K), 136) || X || right_encode(L*8), L, "KMAC", S="")
	h := sha3.NewCSHAKE256([]byte("KMAC"), nil)
	h.Write(bytepad(encodeString(key), 136))
	h.Write(data)
	h.Write(rightEncode(uint64(outputLen * 8)))
	out := make([]byte, outputLen)
	h.Read(out) //nolint:errcheck // XOF Read never returns an error
	return out
}

// --- NIST SP 800-185 encoding primitives ---

// leftEncode encodes x as a left-encoded byte string per NIST SP 800-185 Section 2.3.
// The length of the encoding (in bytes) is prepended as a single byte.
func leftEncode(x uint64) []byte {
	if x == 0 {
		return []byte{1, 0}
	}
	var buf [8]byte
	n := 7
	for ; n >= 0 && x > 0; n-- {
		buf[n] = byte(x)
		x >>= 8
	}
	b := buf[n+1:]
	result := make([]byte, 1+len(b))
	result[0] = byte(len(b))
	copy(result[1:], b)
	return result
}

// rightEncode encodes x as a right-encoded byte string per NIST SP 800-185 Section 2.3.
// The length of the encoding (in bytes) is appended as a single byte.
func rightEncode(x uint64) []byte {
	if x == 0 {
		return []byte{0, 1}
	}
	var buf [8]byte
	n := 7
	for ; n >= 0 && x > 0; n-- {
		buf[n] = byte(x)
		x >>= 8
	}
	b := buf[n+1:]
	result := make([]byte, len(b)+1)
	copy(result, b)
	result[len(b)] = byte(len(b))
	return result
}

// encodeString encodes a byte string S as left_encode(len(S)*8) || S per NIST SP 800-185 Section 2.3.
func encodeString(s []byte) []byte {
	return append(leftEncode(uint64(len(s))*8), s...)
}

// bytepad pads X to the next multiple of w bytes, prepended with left_encode(w),
// per NIST SP 800-185 Section 2.3.
func bytepad(x []byte, w int) []byte {
	z := append(leftEncode(uint64(w)), x...)
	for len(z)%w != 0 {
		z = append(z, 0)
	}
	return z
}
