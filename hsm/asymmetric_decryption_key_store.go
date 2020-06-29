package hsm

import (
	"github.com/ThalesIgnite/crypto11"
	"github.com/ThalesIgnite/gose"
)

type AsymmetricDecryptionKeyStore struct {
	ctx *crypto11.Context
}

func (a *AsymmetricDecryptionKeyStore) Get(kid string) (k gose.AsymmetricDecryptionKey, err error) {
	keyPair, err := a.ctx.FindKeyPair([]byte(kid), nil)
	if err != nil {
		return nil, err
	}
	rsaKeyPair, ok := keyPair.(crypto11.SignerDecrypter)
	if !ok {
		return nil, gose.ErrInvalidKeyType
	}
	return &AsymmetricDecryptionKey{
		kid: kid,
		ctx: a.ctx,
		key: rsaKeyPair,
	}, nil
}

func NewAsymmetricDecryptionKeyStore(ctx *crypto11.Context) (*AsymmetricDecryptionKeyStore) {
	return &AsymmetricDecryptionKeyStore {
		ctx: ctx,
	}
}
