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
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ThalesGroup/gose/jose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mlKemTestKeyStore is a minimal in-memory DecapsPrivMlKemKeyStore for tests.
type mlKemTestKeyStore struct {
	keys map[string]DecapsPrivMlKemKey
}

func (s *mlKemTestKeyStore) Get(kid string) (DecapsPrivMlKemKey, error) {
	if k, ok := s.keys[kid]; ok {
		return k, nil
	}
	return nil, ErrUnknownKey
}

// --- Key generation ---

func TestGenerateMlKemKeyPair_768(t *testing.T) {
	priv, pub, err := GenerateMlKemKeyPair(jose.CrvMLKEM768, "test-768", jose.AlgMLKEM768KMAC256)
	require.NoError(t, err)
	require.NotNil(t, priv)
	require.NotNil(t, pub)
	assert.Equal(t, "test-768", priv.Kid())
	assert.Equal(t, "test-768", pub.Kid())
	assert.Equal(t, jose.AlgMLKEM768KMAC256, priv.Algorithm())
	assert.Equal(t, jose.AlgMLKEM768KMAC256, pub.Algorithm())
}

func TestGenerateMlKemKeyPair_1024(t *testing.T) {
	priv, pub, err := GenerateMlKemKeyPair(jose.CrvMLKEM1024, "test-1024", jose.AlgMLKEM1024KMAC256)
	require.NoError(t, err)
	require.NotNil(t, priv)
	require.NotNil(t, pub)
	assert.Equal(t, "test-1024", priv.Kid())
	assert.Equal(t, "test-1024", pub.Kid())
}

func TestGenerateMlKemKeyPair_512_Unsupported(t *testing.T) {
	_, _, err := GenerateMlKemKeyPair(jose.CrvMLKEM512, "test-512", jose.AlgMLKEM512KMAC128)
	require.Error(t, err)
}

// --- JWK round-trip ---

func TestMlKemJwkRoundTrip_768(t *testing.T) {
	priv, pub, err := GenerateMlKemKeyPair(jose.CrvMLKEM768, "kid-jwk", jose.AlgMLKEM768KMAC256)
	require.NoError(t, err)

	// Marshal public key to JWK and back.
	pubJwk, err := pub.Jwk()
	require.NoError(t, err)
	pubJSON, err := json.Marshal(pubJwk)
	require.NoError(t, err)

	var decoded jose.EncapsPubMlKemKey
	require.NoError(t, json.Unmarshal(pubJSON, &decoded))
	assert.Equal(t, jose.CrvMLKEM768, decoded.Crv)
	assert.Equal(t, "kid-jwk", decoded.Kid())

	// Ensure reloaded public key can encapsulate.
	reloaded, err := NewEncapsPubMlKemKeyImpl(&decoded)
	require.NoError(t, err)
	kemCt, _, err := reloaded.Encapsulate()
	require.NoError(t, err)
	require.NotEmpty(t, kemCt)

	// Ensure the private key can decapsulate the reloaded encapsulation.
	_, err = priv.Decapsulate(kemCt)
	require.NoError(t, err)
}

// --- Encrypt / Decrypt round-trips ---

func testRoundTrip(t *testing.T, crv jose.Crv, alg jose.Alg, plaintext, aad []byte) {
	t.Helper()
	priv, pub, err := GenerateMlKemKeyPair(crv, "rt-key", alg)
	require.NoError(t, err)

	enc, err := NewJweMlKemEncryptorImpl(pub, rand.Reader)
	require.NoError(t, err)

	jweStr, err := enc.Encrypt(plaintext, aad)
	require.NoError(t, err)
	require.NotEmpty(t, jweStr)

	store := &mlKemTestKeyStore{keys: map[string]DecapsPrivMlKemKey{"rt-key": priv}}
	dec := NewJweMlKemDecryptorImpl(store)

	gotPlaintext, gotAad, err := dec.Decrypt(jweStr)
	require.NoError(t, err)
	// gcm.Open returns nil for empty plaintext; treat nil and []byte{} as equivalent.
	assert.Equal(t, string(plaintext), string(gotPlaintext))
	assert.Equal(t, string(aad), string(gotAad))
}

func TestJweMlKemRoundTrip_768(t *testing.T) {
	testRoundTrip(t, jose.CrvMLKEM768, jose.AlgMLKEM768KMAC256, []byte("hello ML-KEM-768"), nil)
}

func TestJweMlKemRoundTrip_1024(t *testing.T) {
	testRoundTrip(t, jose.CrvMLKEM1024, jose.AlgMLKEM1024KMAC256, []byte("hello ML-KEM-1024"), nil)
}

func TestJweMlKemRoundTrip_WithAAD(t *testing.T) {
	testRoundTrip(t,
		jose.CrvMLKEM768, jose.AlgMLKEM768KMAC256,
		[]byte("sensitive payload"),
		[]byte(`{"context":"k8s-kms"}`),
	)
}

func TestJweMlKemRoundTrip_EmptyPlaintext(t *testing.T) {
	testRoundTrip(t, jose.CrvMLKEM768, jose.AlgMLKEM768KMAC256, []byte{}, nil)
}

// --- Compact JWE structure ---

func TestJweMlKem_CompactStructure(t *testing.T) {
	_, pub, err := GenerateMlKemKeyPair(jose.CrvMLKEM768, "struct-key", jose.AlgMLKEM768KMAC256)
	require.NoError(t, err)

	enc, err := NewJweMlKemEncryptorImpl(pub, rand.Reader)
	require.NoError(t, err)

	jweStr, err := enc.Encrypt([]byte("test"), nil)
	require.NoError(t, err)

	parts := strings.Split(jweStr, ".")
	require.Equal(t, 5, len(parts), "compact JWE must have 5 dot-separated parts")

	// Decode and inspect the protected header.
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header jose.JweProtectedHeader
	require.NoError(t, json.Unmarshal(headerBytes, &header))

	assert.Equal(t, jose.AlgMLKEM768KMAC256, header.Alg)
	assert.Equal(t, jose.EncA256GCM, header.Enc)
	assert.Equal(t, "struct-key", header.Kid)
	require.NotNil(t, header.KemCt, "kem-ct must be present in header")
	assert.NotEmpty(t, header.KemCt.Bytes())

	// EncryptedKey must be empty (direct key agreement mode).
	assert.Empty(t, parts[1], "EncryptedKey must be empty for direct key agreement")

	// IV must be 12 bytes.
	iv, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	assert.Equal(t, 12, len(iv))

	// Ciphertext and tag must be non-empty.
	assert.NotEmpty(t, parts[3])
	assert.NotEmpty(t, parts[4])
}

// --- Failure cases ---

func TestJweMlKemDecrypt_WrongKey(t *testing.T) {
	_, pub, err := GenerateMlKemKeyPair(jose.CrvMLKEM768, "key-A", jose.AlgMLKEM768KMAC256)
	require.NoError(t, err)

	privB, _, err := GenerateMlKemKeyPair(jose.CrvMLKEM768, "key-A", jose.AlgMLKEM768KMAC256)
	require.NoError(t, err)

	enc, err := NewJweMlKemEncryptorImpl(pub, rand.Reader)
	require.NoError(t, err)
	jweStr, err := enc.Encrypt([]byte("secret"), nil)
	require.NoError(t, err)

	store := &mlKemTestKeyStore{keys: map[string]DecapsPrivMlKemKey{"key-A": privB}}
	dec := NewJweMlKemDecryptorImpl(store)
	_, _, err = dec.Decrypt(jweStr)
	require.Error(t, err, "decryption with the wrong private key must fail")
}

func TestJweMlKemDecrypt_TamperedCiphertext(t *testing.T) {
	priv, pub, err := GenerateMlKemKeyPair(jose.CrvMLKEM768, "tamper-key", jose.AlgMLKEM768KMAC256)
	require.NoError(t, err)

	enc, err := NewJweMlKemEncryptorImpl(pub, rand.Reader)
	require.NoError(t, err)
	jweStr, err := enc.Encrypt([]byte("untampered"), nil)
	require.NoError(t, err)

	// Flip a byte in the ciphertext field (part index 3).
	parts := strings.Split(jweStr, ".")
	ctBytes, err := base64.RawURLEncoding.DecodeString(parts[3])
	require.NoError(t, err)
	ctBytes[0] ^= 0xFF
	parts[3] = base64.RawURLEncoding.EncodeToString(ctBytes)
	tampered := strings.Join(parts, ".")

	store := &mlKemTestKeyStore{keys: map[string]DecapsPrivMlKemKey{"tamper-key": priv}}
	dec := NewJweMlKemDecryptorImpl(store)
	_, _, err = dec.Decrypt(tampered)
	require.Error(t, err, "decryption of tampered ciphertext must fail")
}

func TestJweMlKemDecrypt_UnknownKid(t *testing.T) {
	_, pub, err := GenerateMlKemKeyPair(jose.CrvMLKEM768, "known-key", jose.AlgMLKEM768KMAC256)
	require.NoError(t, err)

	enc, err := NewJweMlKemEncryptorImpl(pub, rand.Reader)
	require.NoError(t, err)
	jweStr, err := enc.Encrypt([]byte("data"), nil)
	require.NoError(t, err)

	store := &mlKemTestKeyStore{keys: map[string]DecapsPrivMlKemKey{}} // empty store
	dec := NewJweMlKemDecryptorImpl(store)
	_, _, err = dec.Decrypt(jweStr)
	require.ErrorIs(t, err, ErrUnknownKey)
}

// --- KMAC determinism ---

func TestKMAC256_Deterministic(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	data := []byte("context")
	out1 := kmac256(key, data, 32)
	out2 := kmac256(key, data, 32)
	assert.Equal(t, out1, out2)
	assert.Len(t, out1, 32)
}

func TestKMAC128_Deterministic(t *testing.T) {
	key := bytes.Repeat([]byte{0xCD}, 32)
	data := []byte("context")
	out1 := kmac128(key, data, 16)
	out2 := kmac128(key, data, 16)
	assert.Equal(t, out1, out2)
	assert.Len(t, out1, 16)
}

func TestKMAC_DifferentKeysProduceDifferentOutputs(t *testing.T) {
	data := []byte("same context")
	out1 := kmac256(bytes.Repeat([]byte{0x01}, 32), data, 32)
	out2 := kmac256(bytes.Repeat([]byte{0x02}, 32), data, 32)
	assert.NotEqual(t, out1, out2)
}
