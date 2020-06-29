package hsm

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"github.com/ThalesIgnite/crypto11"
	"github.com/ThalesIgnite/gose"
	"github.com/ThalesIgnite/gose/jose"
)

type AsymmetricDecryptionKey struct {
	kid string
	ctx *crypto11.Context
	key crypto11.SignerDecrypter
}

func (a *AsymmetricDecryptionKey) Kid() string {
	return a.kid
}

func (a *AsymmetricDecryptionKey) Jwk() (jose.Jwk, error) {
	// We do not allow the export of private keys from an HSM
	return nil, gose.ErrUnsupportedKeyType
}

func (a *AsymmetricDecryptionKey) Marshal() (string, error) {
	// We do not allow the export of private keys from an HSM
	return "", gose.ErrUnsupportedKeyType
}

func (a *AsymmetricDecryptionKey) MarshalPem() (string, error) {
	// We do not allow the export of private keys from an HSM
	return "", gose.ErrUnsupportedKeyType
}

func (a *AsymmetricDecryptionKey) Certificates() []*x509.Certificate {
	// TODO: lookup certificates
	cert, err := a.ctx.FindCertificate([]byte(a.kid), nil, nil)
	if err != nil {
		// :thinking:
		return nil
	}
	return []*x509.Certificate{cert}
}

func (a *AsymmetricDecryptionKey) Algorithm() jose.Alg {
	return jose.AlgRSAOAEP
}

func (a *AsymmetricDecryptionKey) Decrypt(_ jose.KeyOps, bytes []byte) ([]byte, error) {
	randReader, err := a.ctx.NewRandomReader()
	if err != nil {
		return nil, err
	}

	return a.key.Decrypt(randReader, bytes, &rsa.OAEPOptions {
		Hash: crypto.SHA1,
		Label: nil,
	})
}

func (a *AsymmetricDecryptionKey) Encryptor() (gose.AsymmetricEncryptionKey, error) {
	jwk, err := gose.JwkFromPublicKey(a.key.Public(), []jose.KeyOps{jose.KeyOpsEncrypt}, a.Certificates())
	if err != nil {
		return nil, err
	}
	return gose.NewRsaPublicKeyImpl(jwk)
}

var _ gose.AsymmetricDecryptionKey = (*AsymmetricDecryptionKey)(nil)
