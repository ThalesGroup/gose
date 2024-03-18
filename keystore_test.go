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
	"testing"

	"github.com/ThalesGroup/gose/jose"
	"github.com/stretchr/testify/assert"
)

func BenchmarkNewTrustKeyStore(b *testing.B) {
	// Setup
	b.Helper()
	keys := map[string]jose.Jwk{
		"issuer": &jose.PublicRsaKey{},
	}
	for _, key := range keys {
		key.SetKid("123456")
	}
	for i := 0; i < b.N; i++ {
		_, _ = NewTrustKeyStore(keys)

	}
}

func TestNewTrustKeyStore(t *testing.T) {
	// Setup
	keys := map[string]jose.Jwk{
		"issuer": &jose.PublicRsaKey{},
	}
	for _, key := range keys {
		key.SetKid("123456")
	}
	// Act
	store, err := NewTrustKeyStore(keys)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, store)
}

func TestNewTrustKeyStoreNoKid(t *testing.T) {
	// Setup
	keys := map[string]jose.Jwk{
		"issuer": &jose.PublicRsaKey{},
	}

	// Act
	store, err := NewTrustKeyStore(keys)

	// Assert
	assert.Error(t, err, ErrInvalidKey)
	assert.Nil(t, store)
}

func TestAddExisting(t *testing.T) {
	// Setup
	keys := map[string]jose.Jwk{
		"issuer": &jose.PublicRsaKey{},
	}
	for _, key := range keys {
		key.SetKid("123456")
	}
	// Act
	store, err := NewTrustKeyStore(keys)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, store)

	for issuer, jwk := range keys {
		err = store.Add(issuer, jwk)
	}

	// Assert
	assert.NoError(t, err)

}

func TestRemove(t *testing.T) {
	// Setup
	keys := map[string]jose.Jwk{
		"issuer": &jose.PublicRsaKey{},
	}
	for _, key := range keys {
		key.SetKid("123456")
	}
	// Act
	store, err := NewTrustKeyStore(keys)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, store)

	for issuer, jwk := range keys {
		result := store.Remove(issuer, jwk.Kid())
		assert.True(t, result)
	}

}

func TestRemoveNoKey(t *testing.T) {
	// Setup
	keys := map[string]jose.Jwk{
		"issuer": &jose.PublicRsaKey{},
	}
	for _, key := range keys {
		key.SetKid("123456")
	}
	// Act
	store, err := NewTrustKeyStore(keys)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, store)

	result := store.Remove("invalid", "98765")
	assert.False(t, result)

}

func TestGet(t *testing.T) {
	// Setup
	keys := map[string]jose.Jwk{
		"issuer": &jose.PublicRsaKey{},
	}
	for _, key := range keys {
		key.SetKid("123456")
		key.SetAlg(jose.AlgRS512)
		key.SetOps(validVerificationOps)
	}
	// Act
	store, err := NewTrustKeyStore(keys)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, store)

	key, err := store.Get("issuer", "123456")
	assert.NotNil(t, key)
	assert.Nil(t, err)

}

func TestGetFail(t *testing.T) {
	// Setup
	keys := map[string]jose.Jwk{
		"issuer": &jose.PublicRsaKey{},
	}
	for _, key := range keys {
		key.SetKid("123456")
		key.SetAlg(jose.AlgRS512)
		key.SetOps(validVerificationOps)
	}
	// Act
	store, err := NewTrustKeyStore(keys)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, store)

	key, err := store.Get("unknown", "98765")
	assert.Nil(t, key)
	assert.Nil(t, key)

}
