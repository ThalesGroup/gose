package gose

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/ThalesGroup/gose/jose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log"
	"strings"
	"testing"
)

const jwkRSAOAEPEncryptionRaw = `
{
	"kty":"RSA",
	"kid": "1",
    "key_ops": ["encrypt"],
	"alg": "RSA-OAEP",
	"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
	"e":"AQAB"
}`

func generateEncryptor(t *testing.T) *JweRsaKeyEncryptionEncryptorImpl {
	b := make([]byte, 16)
	random := rand.Reader
	res, _ := random.Read(b)
	log.Print(res)

	buf := bytes.NewReader([]byte(jwkRSAOAEPEncryptionRaw))
	jwkRSAOAEPEncryption, err := LoadJwk(buf, nil)
	require.NoError(t, err)


	rsaOAEPEncryptor, err := NewJweRsaKeyEncryptionEncryptorImpl(jwkRSAOAEPEncryption, rand.Reader)
	require.NoError(t, err)

	return rsaOAEPEncryptor
}

func TestNewJweRsaKeyEncryptionEncryptorImpl(t *testing.T) {
	rsaOAEPEncryptor := generateEncryptor(t)

	assert.Equal(t, jose.AlgRSAOAEP, rsaOAEPEncryptor.rsaAlg)
	assert.Equal(t, "1", rsaOAEPEncryptor.rsaPublicKid)
	assert.NotNil(t, rsaOAEPEncryptor.rsaPublicKey)
	assert.NotNil(t, rsaOAEPEncryptor.randomSource)
}

func TestNewJweRsaKeyEncryptionEncryptorImpl_InvalidJwk(t *testing.T) {
	generator := &ECDSASigningKeyGenerator{}
	k, err := generator.Generate(jose.AlgES256, []jose.KeyOps{jose.KeyOpsSign, jose.KeyOpsDecrypt})
	require.NoError(t, err)
	verifier, err := k.Verifier()
	require.NoError(t, err)
	jwk, err := verifier.Jwk()
	require.NoError(t, err)
	_, err = NewJweRsaKeyEncryptionEncryptorImpl(jwk, rand.Reader)
	assert.Equal(t, ErrInvalidKeyType, err)
}


func TestRSAOAEPJWEEncrypt(t *testing.T) {
	rsaOAEPEncryptor := generateEncryptor(t)
	jwe, err := rsaOAEPEncryptor.Encrypt([]byte("plaintext"), crypto.SHA256)
	require.NoError(t, err)
	require.NotEmpty(t, jwe)

	// verify structure
	splits := strings.Split(jwe,  ".")
	require.Equal(t, 5, len(splits))

	// protected header
	require.NotEmpty(t, splits[0])
	protectedHeaderRaw, err := base64.RawURLEncoding.DecodeString(splits[0])
	require.NoError(t, err)
	var protectedHeader jose.JweProtectedHeader
	err = json.Unmarshal(protectedHeaderRaw, &protectedHeader)
	require.NoError(t, err)
	assert.Equal(t, jose.AlgRSAOAEP, protectedHeader.Alg)
	assert.Equal(t, "1", protectedHeader.Kid)
	assert.Equal(t, jose.EncA256GCM, protectedHeader.Enc)

	// encrypted CEK
	require.NotEmpty(t, splits[0])

	// iv
	encodedIV := splits[2]
	require.NotEmpty(t, encodedIV)
	iv, err := base64.RawURLEncoding.DecodeString(encodedIV)
	require.NoError(t, err)
	assert.Equal(t, 12, len(iv))

	// ciphertext
	require.NotEmpty(t, splits[3])

	// tag
	require.NotEmpty(t, splits[4])
}