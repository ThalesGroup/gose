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

package hsm

import (
	"encoding/hex"
	"fmt"

	"github.com/ThalesGroup/crypto11"
	"github.com/ThalesGroup/gose"
)

// DecapsPrivMlKemHsmKeyStore implements gose.DecapsPrivMlKemKeyStore by looking up
// ML-KEM private keys on a PKCS#11 HSM token via crypto11.
// The kid passed to Get is used as the CKA_ID (as a byte slice) for the HSM lookup.
type DecapsPrivMlKemHsmKeyStore struct {
	ctx *crypto11.Context
}

// Get returns the DecapsPrivMlKemHsmKey for the given kid, or an error if not found.
// kid must be the hex-encoded CKA_ID of the ML-KEM key pair on the token, matching the
// format returned by GetKekKeyIdString() in the k8s-kms-plugin (hex.EncodeToString(ckaId)).
func (s *DecapsPrivMlKemHsmKeyStore) Get(kid string) (gose.DecapsPrivMlKemKey, error) {
	id, err := hex.DecodeString(kid)
	if err != nil {
		return nil, fmt.Errorf("hsm mlkem keystore: kid %q is not valid hex: %w", kid, err)
	}
	keyPair, err := s.ctx.FindMLKEMKeyPair(id, nil)
	if err != nil {
		return nil, err
	}
	return NewDecapsPrivMlKemHsmKey(keyPair, kid)
}

// Ensure interface compliance at compile time.
var _ gose.DecapsPrivMlKemKeyStore = (*DecapsPrivMlKemHsmKeyStore)(nil)

// NewDecapsPrivMlKemHsmKeyStore creates a DecapsPrivMlKemHsmKeyStore backed by the given
// crypto11.Context. The context must be connected to an HSM token that has ML-KEM key pairs.
func NewDecapsPrivMlKemHsmKeyStore(ctx *crypto11.Context) *DecapsPrivMlKemHsmKeyStore {
	return &DecapsPrivMlKemHsmKeyStore{ctx: ctx}
}
