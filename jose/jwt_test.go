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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJwt_Verify(t *testing.T) {
	testCases := []struct {
		jwt      Jwt
		expected error
	}{
		// Invalid header typ field.
		{
			jwt: Jwt{
				Header: JwsHeader{
					Typ: "invalid",
				},
			},

			expected: ErrJwtFormat,
		},
		// Invalid header cty field.
		{
			jwt: Jwt{
				Header: JwsHeader{
					Typ: JwtType,
					Cty: "invalid",
				},
			},

			expected: ErrJwtFormat,
		},
		// Invalid untyped claims name.
		{
			jwt: Jwt{
				Header: JwsHeader{
					Typ: JwtType,
				},
				Claims: JwtClaims{
					UntypedClaims: UntypedClaims{
						"sub": json.RawMessage{},
					},
				},
			},
			expected: ErrJwkReservedClaimName,
		},
		// Happy day scenario.
		{
			jwt: Jwt{
				Header: JwsHeader{
					Typ: JwtType,
				},
				Claims: JwtClaims{
					UntypedClaims: UntypedClaims{
						"name": json.RawMessage("John Doe"),
					},
				},
			},
			expected: nil,
		},
	}

	// Act/Assert
	for i, test := range testCases {
		t.Run(fmt.Sprintf("%d", i+1),
			func(t *testing.T) {
				err := test.jwt.Verify()
				assert.Equal(t, test.expected, err)
			})
	}
}

func TestJwt_MarshalBody(t *testing.T) {
	// Setup
	testCases := []struct {
		jwt Jwt
		err error
	}{
		// Invalid 'typ' field case
		{
			jwt: Jwt{
				Header: JwsHeader{
					Typ: "Wrong",
				},
			},
			err: ErrJwtFormat,
		},
		// Invalid 'cty' field case
		{
			jwt: Jwt{
				Header: JwsHeader{
					Typ: JwtType,
					Cty: "Wrong",
				},
			},
			err: ErrJwtFormat,
		},
		// Happy days scenarios
		{
			jwt: Jwt{
				Header: JwsHeader{
					Typ: JwtType,
				},
				Claims: JwtClaims{
					AutomaticJwtClaims: AutomaticJwtClaims{
						Issuer:   "test",
						IssuedAt: 123456789,
						JwtID:    "123456789",
					},
					SettableJwtClaims: SettableJwtClaims{
						Audiences: Audiences{
							Aud: []string{"aud1"},
						},
					},
					UntypedClaims: UntypedClaims{
						"name": json.RawMessage(`"John Doe"`),
					},
				},
			},
			err: nil,
		},
		{
			jwt: Jwt{
				Header: JwsHeader{
					Typ: JwtType,
					Cty: JwtType,
				},
				Claims: JwtClaims{
					AutomaticJwtClaims: AutomaticJwtClaims{
						Issuer:   "test",
						IssuedAt: 123456789,
						JwtID:    "123456789",
					},
					SettableJwtClaims: SettableJwtClaims{
						Audiences: Audiences{
							Aud: []string{"aud1"},
						},
					},
					UntypedClaims: UntypedClaims{
						"name": json.RawMessage(`"John Doe"`),
					},
				},
			},
			err: nil,
		},
	}

	// Act/Assert
	for i, test := range testCases {
		t.Run(fmt.Sprintf("%d", i+1),
			func(t *testing.T) {
				dest, err := test.jwt.MarshalBody()
				assert.Equal(t, test.err, err)
				if test.err == nil {
					assert.Regexp(t, "^[A-Za-z0-9_-]+.[A-Za-z0-9_-]+$", dest)
				} else {
					assert.Empty(t, dest)
				}
			})
	}
}

func TestJwt_Unmarshal(t *testing.T) {
	// Note test JWT serializations generated at https://jwt.io/#debugger
	// Setup
	testCases := []struct {
		Input    string
		Expected Jwt
	}{
		{
			Input: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiaXNzIjoiaXNzdWVyMSIsImV4cCI6MTUxNjIzOTA0MCwibmJmIjoxNTE2MjM5MDM4LCJhdWQiOiJvbmUifQ.TLHUIM0WqqIyHnai0Dy-EtJYX13WOXuWxYrd1A7T2V9cDGfqVlxddLzG0hAZJ9MvYfkoJsW0bQHey_qQNGN5hUluysHc68jtEaSgZqPqeZe64M3a7wVmbeNc6wMAVH_KX48ohTUDZ1tVC53hAdoph87JG6GRxTVvN6Fvk6bLbq8",
			Expected: Jwt{
				Header: JwsHeader{
					Alg: AlgRS256,
					Typ: JwtType,
				},
				Claims: JwtClaims{
					AutomaticJwtClaims: AutomaticJwtClaims{
						Issuer:   "issuer1",
						IssuedAt: 1516239022,
					},
					SettableJwtClaims: SettableJwtClaims{
						Subject:    "1234567890",
						NotBefore:  1516239038,
						Expiration: 1516239040,
						Audiences: Audiences{
							Aud: []string{"one"},
						},
					},
					UntypedClaims: UntypedClaims{
						"name":  json.RawMessage(`"John Doe"`),
						"admin": json.RawMessage("true"),
					},
				},
			},
		},
		{
			Input: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiaXNzIjoiaXNzdWVyMSIsImV4cCI6MTUxNjIzOTA0MCwibmJmIjoxNTE2MjM5MDM4LCJhdWQiOlsib25lIiwidHdvIl19.Og8U8-Oq1zwZwlgJ69tAMMj_F0VlUKJJxv25mRsQn-zHgdpt1besO7sJGDyNN6hS60S35RP3J1c5klVNbLipALegfiYk7gdbghXu9AJ_2GdUCjokyouslMKH5fOIbgDIyQZy20VGEIexUohyZ3rVv_8Ql8PISKZn6fVQv64FucU",
			Expected: Jwt{
				Header: JwsHeader{
					Alg: AlgRS256,
					Typ: JwtType,
				},
				Claims: JwtClaims{
					AutomaticJwtClaims: AutomaticJwtClaims{
						Issuer:   "issuer1",
						IssuedAt: 1516239022,
					},
					SettableJwtClaims: SettableJwtClaims{
						Subject:    "1234567890",
						NotBefore:  1516239038,
						Expiration: 1516239040,
						Audiences: Audiences{
							Aud: []string{"one", "two"},
						},
					},
					UntypedClaims: UntypedClaims{
						"name":  json.RawMessage(`"John Doe"`),
						"admin": json.RawMessage("true"),
					},
				},
			},
		},
	}

	// Act/assert
	for i, test := range testCases {
		t.Run(fmt.Sprintf("%d", i+1),
			func(t *testing.T) {
				var jwt Jwt
				_, err := jwt.Unmarshal(test.Input)
				require.NoError(t, err)
				assert.Equal(t, test.Expected.Header.Alg, jwt.Header.Alg)
				assert.Equal(t, test.Expected.Header.Typ, jwt.Header.Typ)
				assert.Equal(t, test.Expected.Claims.AutomaticJwtClaims.IssuedAt, jwt.Claims.AutomaticJwtClaims.IssuedAt)
				assert.Equal(t, test.Expected.Claims.AutomaticJwtClaims.Issuer, jwt.Claims.AutomaticJwtClaims.Issuer)
				assert.Equal(t, test.Expected.Claims.SettableJwtClaims.Subject, jwt.Claims.SettableJwtClaims.Subject)
				require.Equal(t, len(test.Expected.Claims.SettableJwtClaims.Audiences.Aud), len(jwt.Claims.SettableJwtClaims.Audiences.Aud))
				for j := range test.Expected.Claims.SettableJwtClaims.Audiences.Aud {
					assert.Equal(t, test.Expected.Claims.SettableJwtClaims.Audiences.Aud[j], jwt.Claims.SettableJwtClaims.Audiences.Aud[j])
				}
				assert.Equal(t, test.Expected.Claims.SettableJwtClaims.Expiration, jwt.Claims.SettableJwtClaims.Expiration)
				assert.Equal(t, test.Expected.Claims.SettableJwtClaims.NotBefore, jwt.Claims.SettableJwtClaims.NotBefore)

				assert.Equal(t, len(test.Expected.Claims.UntypedClaims), len(jwt.Claims.UntypedClaims))
				for k, expected := range test.Expected.Claims.UntypedClaims {
					got, exists := jwt.Claims.UntypedClaims[k]
					require.True(t, exists)
					assert.Equal(t, expected, got)
				}
			})
	}
}

func TestJwt_Roundtrip(t *testing.T) {
	// Setup
	expected := Jwt{
		Header: JwsHeader{
			Alg: AlgRS256,
			Typ: JwtType,
		},
		Claims: JwtClaims{
			AutomaticJwtClaims: AutomaticJwtClaims{
				Issuer:   "issuer1",
				IssuedAt: 1516239022,
			},
			SettableJwtClaims: SettableJwtClaims{
				Subject:    "1234567890",
				NotBefore:  1516239038,
				Expiration: 1516239040,
				Audiences: Audiences{
					Aud: []string{"one"},
				},
			},
			UntypedClaims: UntypedClaims{
				"name":  json.RawMessage(`"John Doe"`),
				"admin": json.RawMessage("true"),
			},
		},
		Signature: []byte("123455"),
	}

	// Act
	body, err := expected.MarshalBody()
	require.NoError(t, err)
	marhsalled := MarshalJws(body, expected.Signature)
	var unmarshalled Jwt
	_, err = unmarshalled.Unmarshal(string(marhsalled))
	require.NoError(t, err)

	// Assert
	assert.Equal(t, expected, unmarshalled)

}

func TestJwtClaims_UnmarshalCustomClaim(t *testing.T) {
	claims := JwtClaims{
		UntypedClaims: UntypedClaims{
			"name": json.RawMessage([]byte("1")),
		},
	}

	var stringName string
	err := claims.UnmarshalCustomClaim("name", &stringName)
	assert.Error(t, err)
	var intName int
	err = claims.UnmarshalCustomClaim("name", &intName)
	require.NoError(t, err)
	assert.Equal(t, 1, intName)
}
