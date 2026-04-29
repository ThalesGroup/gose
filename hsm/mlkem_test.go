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
	"testing"

	"github.com/ThalesGroup/crypto11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubMLKEMKeyPair implements crypto11.MLKEMKeyPair with a fixed parameter set.
// Only ParameterSet() is exercised by the constructor under test.
type stubMLKEMKeyPair struct {
	paramSet crypto11.MLKEMParameterSet
}

func (s *stubMLKEMKeyPair) ParameterSet() crypto11.MLKEMParameterSet { return s.paramSet }
func (s *stubMLKEMKeyPair) Encapsulate(_ crypto11.AttributeSet) ([]byte, *crypto11.MLKEMSharedSecret, error) {
	return nil, nil, nil
}
func (s *stubMLKEMKeyPair) Decapsulate(_ []byte, _ crypto11.AttributeSet) (*crypto11.MLKEMSharedSecret, error) {
	return nil, nil
}
func (s *stubMLKEMKeyPair) Delete() error { return nil }

func TestNewDecapsPrivMlKemHsmKey_UnknownParameterSet(t *testing.T) {
	const unknownParamSet crypto11.MLKEMParameterSet = 0xFFFF

	_, err := NewDecapsPrivMlKemHsmKey(&stubMLKEMKeyPair{paramSet: unknownParamSet}, "test-kid")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported ML-KEM parameter set")
}

func TestDecapsPrivMlKemHsmKeyStore_Get_InvalidHexKid(t *testing.T) {
	store := &DecapsPrivMlKemHsmKeyStore{ctx: nil}

	_, err := store.Get("not-valid-hex!")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not valid hex")
}
