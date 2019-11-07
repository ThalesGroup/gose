// Copyright 2019 Thales e-Security, Inc
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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJwks_UnmarshalJSON(t *testing.T) {
	// Setup
	const input = `{
	"keys": [ 
	{
		"kty": "RSA",
		"n": "BBBB",
		"e": "AQAB",
		"kid": "1"
	},
	{
		"kty": "RSA",
		"n": "BBBB",
		"e": "AQAB",
		"kid": "2"
	}]
}
`
	var jwks Jwks

	// Act
	err := json.Unmarshal([]byte(input), &jwks)

	// Assert

	assert.NoError(t, err)
	require.Len(t, jwks.Keys, 2)
	assert.Equal(t, "1", jwks.Keys[0].Kid())
	assert.Equal(t, "2", jwks.Keys[1].Kid())
}

func TestJwks_MarshalJSON(t *testing.T) {
	// Setup
	var rsa PrivateRsaKey
	rsa.SetKid("1")
	rsa.N.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.D.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.P.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.Q.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.Dp.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.Dq.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.Qi.SetBytes([]byte{0, 1, 2, 3, 4})
	rsa.E.SetBytes([]byte{1, 0, 1})

	jwks := Jwks{
		Keys: []Jwk{
			&rsa,
			&rsa,
		},
	}

	// Act
	marshalled, err := json.Marshal(&jwks)

	// Assert
	assert.NoError(t, err)
	assert.NotEmpty(t, marshalled)
}
