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

package jose

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBigNum_MarshalJSON(t *testing.T) {
	// Setup
	var val BigNum
	val.SetBytes([]byte{1, 0, 1})

	// Act
	marshalled, err := json.Marshal(&val)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, `"AQAB"`, string(marshalled))

	val.SetBytes([]byte{})
	marshalled, err = json.Marshal(&val)

	assert.Nil(t, marshalled)
	assert.IsType(t, &json.MarshalerError{}, err)
	assert.Equal(t,
		"json: error calling MarshalJSON for type *jose.BigNum: invalid Blob format, may not be empty",
		err.Error())

}

func TestBigNum_UnmarshalJSON(t *testing.T) {
	// Setup
	var val BigNum
	var expected big.Int
	expected.SetInt64(65537)

	// Act
	err := json.Unmarshal([]byte(`"AQAB"`), &val)

	// Assert
	assert.NoError(t, err)
	assert.True(t, expected.Cmp(val.Int()) == 0)

	// Act/Assert
	assert.Equal(t, ErrBlobEmpty, json.Unmarshal([]byte(`""`), &val))
}
