package gose

import (
	"github.com/stretchr/testify/mock"
)

const (
	ModeEncrypt = iota // blockModeCloser is in encrypt mode
	ModeDecrypt        // blockModeCloser is in decrypt mode

)

const (
	mockExpectedCleartext = "decrypted"
	mockExpectedCiphertext = "encrypted"
)

type MockBlockMode struct {
	mock.Mock
	mode int
}

func (mbm *MockBlockMode) BlockSize() int {
	args := mbm.Called()
	return args.Get(0).(int)
}

// In order to simulate a behavior tangible for tests, i.e encrypt or decrypt according to the mode, we simply return a
// string that inform us if we properly were in the encrypt or decrypt mode
func (mbm *MockBlockMode) CryptBlocks(dst, src []byte) {
	switch mbm.mode {
	case ModeDecrypt:
		copy(dst, mockExpectedCleartext)
	case ModeEncrypt:

		copy(dst, mockExpectedCiphertext)
	default:
		panic("unexpected mode")
	}
}
