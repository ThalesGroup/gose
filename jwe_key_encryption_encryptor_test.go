package gose

import (
	"github.com/ThalesIgnite/gose/jose"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewJweRsaKeyEncryptionEncryptorImpl_UnsupportedContentEncryptionAlg(t *testing.T) {
	_, err := NewJweRsaKeyEncryptionEncryptorImpl(nil, jose.AlgES256)
	assert.Equal(t, ErrInvalidAlgorithm, err)
}

func TestNewJweRsaKeyEncryptionEncryptorImpl_InvalidJwk(t *testing.T) {
	t.Fail()
}

func TestNewJweRsaKeyEncryptionEncryptorImpl_InvalidKeyOps(t *testing.T) {
	t.Fail()
}
