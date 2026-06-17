// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

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
