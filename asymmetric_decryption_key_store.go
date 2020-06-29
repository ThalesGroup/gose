package gose

type AsymmetricDecryptionKeyStoreImpl struct {
	keys map[string]AsymmetricDecryptionKey
}

func (a *AsymmetricDecryptionKeyStoreImpl) Get(kid string) (k AsymmetricDecryptionKey, err error) {
	// Find returns the key with matching kid or, if there's only a single key, return that.
	if key, ok := a.keys[kid]; ok {
		return key, nil
	}
	if len(a.keys) == 1 {
		for _, key := range a.keys {
			return key, nil
		}
	}
	return nil, ErrUnknownKey
}

func NewAsymmetricDecryptionKeyStoreImpl(keys map[string]AsymmetricDecryptionKey) (*AsymmetricDecryptionKeyStoreImpl, error) {
	return &AsymmetricDecryptionKeyStoreImpl{
		keys: keys,
	}, nil
}