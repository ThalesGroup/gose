package hsm

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"github.com/ThalesGroup/crypto11"
	"github.com/ThalesGroup/gose"
	"github.com/ThalesGroup/gose/jose"
)

// AsymmetricDecryptionKey implements RSA OAEP using SHA1 decryption.
// This structure is made to provide a management of pkcs11-handled asymmetric key pairs
type AsymmetricDecryptionKey struct {
	kid []byte
	keylabel []byte
	ctx *crypto11.Context
	key crypto11.SignerDecrypter
}

// Kid the unique identifier of this key.
func (a *AsymmetricDecryptionKey) Kid() string {
	return string(a.kid)
}

// Certificates associated x509 certificates.
func (a *AsymmetricDecryptionKey) Certificates() []*x509.Certificate {
	// TODO: lookup certificates
	cert, err := a.ctx.FindCertificate(a.kid, a.keylabel, nil)
	if err != nil {
		// TODO: return an error via an interface signature change in next major version.
		panic(err)
	}
	return []*x509.Certificate{cert}
}

// Algorithm return jose.AlgRSAOAEP the fixed algorithm that AsymmetricDecryptionKey implements.
func (a *AsymmetricDecryptionKey) Algorithm() jose.Alg {
	return jose.AlgRSAOAEP
}

// Decrypt the given ciphertext data returning the derived plaintext.
func (a *AsymmetricDecryptionKey) Decrypt(_ jose.KeyOps, hash crypto.Hash, bytes []byte) ([]byte, error) {
	randReader, err := a.ctx.NewRandomReader()
	if err != nil {
		return nil, err
	}

	return a.key.Decrypt(randReader, bytes, &rsa.OAEPOptions {
		Hash: hash,
		Label: nil,
	})
}

// Encryptor get the matching AsymmetricEncryptionKey for this decryptor.
func (a *AsymmetricDecryptionKey) Encryptor() (gose.AsymmetricEncryptionKey, error) {
	jwk, err := gose.JwkFromPublicKey(a.key.Public(), []jose.KeyOps{jose.KeyOpsEncrypt}, a.Certificates())
	if err != nil {
		return nil, err
	}
	return gose.NewRsaPublicKeyImpl(jwk)
}

var _ gose.AsymmetricDecryptionKey = (*AsymmetricDecryptionKey)(nil)

// NewAsymmetricDecryptionKey creates an instance with the given pkcs11
// key handler.
// 'keyid' or 'keylabel' can be nil, but nut both. Provide at least one or both.
func NewAsymmetricDecryptionKey(pkcs11Context *crypto11.Context, key crypto11.SignerDecrypter, kid []byte, keylabel []byte) (*AsymmetricDecryptionKey, error) {
	return &AsymmetricDecryptionKey{
		kid: kid,
		keylabel: keylabel,
		ctx: pkcs11Context,
		key: key,
	}, nil
}
