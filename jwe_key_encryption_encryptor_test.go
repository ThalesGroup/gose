package gose

import (
	"github.com/ThalesIgnite/gose/jose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewJweRsaKeyEncryptionEncryptorImpl_UnsupportedContentEncryptionAlg(t *testing.T) {
	_, err := NewJweRsaKeyEncryptionEncryptorImpl(nil, jose.AlgES256)
	assert.Equal(t, ErrInvalidAlgorithm, err)
}

func TestNewJweRsaKeyEncryptionEncryptorImpl_InvalidJwk(t *testing.T) {
	generator := &ECDSASigningKeyGenerator{}
	k, err := generator.Generate(jose.AlgES256, []jose.KeyOps{jose.KeyOpsSign, jose.KeyOpsDecrypt})
	require.NoError(t, err)
	verifier, err := k.Verifier()
	require.NoError(t, err)
	jwk, err := verifier.Jwk()
	require.NoError(t, err)
	_, err = NewJweRsaKeyEncryptionEncryptorImpl(jwk, jose.AlgA256GCM)
	assert.Equal(t, ErrInvalidKeyType, err)
}