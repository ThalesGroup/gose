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

// AsymmetricDecryptionKeyStoreImpl implements the AsymmetricDecryptionKeyStore interface providing AsymmetricDecryptionKey
// lookup capabilities.
type AsymmetricDecryptionKeyStoreImpl struct {
	keys map[string]AsymmetricDecryptionKey
}

// Get returns a matching AsymmetricDecryptionKey fpr the given Key ID or an error (ErrUnknownKey) if the requested key
// cannot be found.
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

// NewAsymmetricDecryptionKeyStoreImpl creates a AsymmetricDecryptionKeyStoreImpl instances with the given keys.
func NewAsymmetricDecryptionKeyStoreImpl(keys map[string]AsymmetricDecryptionKey) (*AsymmetricDecryptionKeyStoreImpl, error) {
	return &AsymmetricDecryptionKeyStoreImpl{
		keys: keys,
	}, nil
}