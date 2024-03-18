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

import (
	"testing"
	"time"

	"crypto/x509"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/ThalesGroup/gose/jose"
)

const (
	/* The below jwt contains the following generated @ https://jwt.io/:
		header:
			- typ: JWT
		    - alg: PS256/ES256
			- kid: 12345
		claims:
			- sub: 1234567890,
	 		- aud: test,
	 		- jti: 31c8767d-6732-4db4-b488-21cf34e5412d,
			- iat: 1514977397,
	 		- exp: 1514980997,
		    - nbf: 1514980997
	*/
	rsaValidJwtPayload         = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCIsICJraWQiOiIxMjM0NSJ9Cg.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoidGVzdCIsImp0aSI6IjMxYzg3NjdkLTY3MzItNGRiNC1iNDg4LTIxY2YzNGU1NDEyZCIsImlhdCI6MTUxNDk3NzM5NywibmJmIjoxNTE0OTc3Mzk3LCJleHAiOjE1MTQ5ODA5OTd9Cg"
	rsaValidJwtSignature       = "q0BpUU1b3rMraJR0dWGdpEffEBjmDhwT9O1AnSjvDGM"
	rsaValidJwt                = rsaValidJwtPayload + "." + rsaValidJwtSignature
	rsaValidJwtAlg             = jose.AlgPS256
	validJwtKid                = "12345"
	validJwtSub                = "1234567890"
	validJwtAud                = "test"
	validJwtJti                = "31c8767d-6732-4db4-b488-21cf34e5412d"
	validJwtIat          int64 = 1514977397
	validJwtNbf          int64 = 1514977397
	validJwtExp          int64 = 1514980997
)

func unixStartTime() time.Time {
	return time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
}

type MockedTrustKeyStore struct {
	mock.Mock
}

func (store *MockedTrustKeyStore) Add(issuer string, jwk jose.Jwk) error {
	args := store.Called(issuer, jwk)
	return args.Error(0)
}

func (store *MockedTrustKeyStore) Remove(issuer, kid string) bool {
	args := store.Called(issuer, kid)
	return args.Bool(0)
}

func (store *MockedTrustKeyStore) Get(issuer, kid string) (VerificationKey, error) {
	args := store.Called(issuer, kid)
	return args.Get(0).(VerificationKey), args.Error(1)
}

type MockedVerificationKey struct {
	mock.Mock
}

func (key *MockedVerificationKey) Algorithm() jose.Alg {
	return key.Called().Get(0).(jose.Alg)
}

func (key *MockedVerificationKey) Kid() string {
	return key.Called().Get(0).(string)
}

func (key *MockedVerificationKey) Jwk() (jose.Jwk, error) {
	args := key.Called()
	return args.Get(0).(jose.Jwk), args.Error(1)
}

func (key *MockedVerificationKey) Marshal() (string, error) {
	args := key.Called()
	return args.String(0), args.Error(1)
}

func (key *MockedVerificationKey) MarshalPem() (string, error) {
	args := key.Called()
	return args.String(0), args.Error(1)
}

func (key *MockedVerificationKey) Certificates() []*x509.Certificate {
	return key.Called().Get(0).([]*x509.Certificate)
}

func (key *MockedVerificationKey) Verify(operation jose.KeyOps, data []byte, signature []byte) bool {
	args := key.Called(operation, data, signature)
	return args.Bool(0)
}

func TestNewJwtVerifier(t *testing.T) {
	// Setup
	ks := MockedTrustKeyStore{}

	// Act
	verifier := NewJwtVerifier(&ks)

	// Assert
	require.NotNil(t, verifier)
	assert.Equal(t, &ks, verifier.store)
}

//
//func TestJwtVerifierImpl_Verify(t *testing.T) {
//	// Setup
//	defer monkey.Patch(time.Now, func() time.Time {
//		return unixStartTime().Add(time.Duration(validJwtNbf) * time.Second)
//	}).Unpatch()
//	key := MockedVerificationKey{}
//	signatureBytes, err := base64.RawURLEncoding.DecodeString(rsaValidJwtSignature)
//	require.NoError(t, err)
//	key.On("Verify", jose.KeyOpsVerify, []byte(rsaValidJwtPayload), signatureBytes).Return(true)
//	key.On("Algorithm").Return(rsaValidJwtAlg)
//	key.On("Kid").Return(validJwtKid)
//	ks := MockedTrustKeyStore{}
//	ks.On("Get", mock.Anything, validJwtKid).Return(&key, nil)
//	verifier := NewJwtVerifier(&ks)
//
//	// Act
//	kid, claimSet, err := verifier.Verify(rsaValidJwt, []string{"test"})
//
//	// Assert
//	require.NoError(t, err)
//	require.NotNil(t, claimSet)
//	assert.Equal(t, validJwtKid, kid)
//	assert.Equal(t, validJwtAud, claimSet.Audiences.Aud[0])
//	assert.Equal(t, validJwtSub, claimSet.Subject)
//	assert.NotEmpty(t, validJwtJti, claimSet.JwtID)
//	assert.Equal(t, validJwtIat, claimSet.IssuedAt)
//	assert.Equal(t, validJwtExp, claimSet.Expiration)
//	assert.Equal(t, validJwtNbf, claimSet.NotBefore)
//}
//
//func TestJwtVerifierImpl_Verify_FailsWithInvalidSignature(t *testing.T) {
//	// Setup
//	defer monkey.Patch(time.Now, func() time.Time {
//		return unixStartTime().Add(time.Duration(validJwtNbf) * time.Second)
//	}).Unpatch()
//	key := MockedVerificationKey{}
//	signatureBytes, err := base64.RawURLEncoding.DecodeString(rsaValidJwtSignature)
//	require.NoError(t, err)
//	key.On("Verify", jose.KeyOpsVerify, []byte(rsaValidJwtPayload), signatureBytes).Return(false)
//	key.On("Algorithm").Return(rsaValidJwtAlg)
//	ks := MockedTrustKeyStore{}
//	ks.On("Verifier", validJwtKid).Return(&key)
//	ks.On("Get", mock.Anything, validJwtKid).Return(&key, nil)
//	verifier := NewJwtVerifier(&ks)
//
//	// Act
//	_, claimSet, err := verifier.Verify(rsaValidJwt, []string{"test"})
//
//	// Assert
//	require.Equal(t, ErrInvalidSignature, err)
//	require.Nil(t, claimSet)
//}
//
//func TestJwtVerifierImpl_Verify_FailsWithNbfViolation(t *testing.T) {
//	// Setup
//	defer monkey.Patch(time.Now, func() time.Time {
//		return unixStartTime().Add(time.Duration(validJwtNbf-10) * time.Second)
//	}).Unpatch()
//	key := MockedVerificationKey{}
//	signatureBytes, err := base64.RawURLEncoding.DecodeString(rsaValidJwtSignature)
//	require.NoError(t, err)
//	key.On("Verify", jose.KeyOpsVerify, []byte(rsaValidJwtPayload), signatureBytes).Return(true)
//	key.On("Algorithm").Return(rsaValidJwtAlg)
//	ks := MockedTrustKeyStore{}
//	ks.On("Verifier", validJwtKid).Return(&key)
//	ks.On("Get", mock.Anything, validJwtKid).Return(&key, nil)
//	verifier := NewJwtVerifier(&ks)
//
//	// Act
//	kid, claimSet, err := verifier.Verify(rsaValidJwt, []string{"test"})
//
//	// Assert
//	require.Equal(t, ErrInvalidJwtTimeframe, err)
//	require.Empty(t, kid)
//	require.Nil(t, claimSet)
//}
//
//func TestJwtVerifierImpl_Verify_FailsWithExpViolation(t *testing.T) {
//	// Setup
//	defer monkey.Patch(time.Now, func() time.Time {
//		return unixStartTime().Add(time.Duration(validJwtExp+10) * time.Second)
//	}).Unpatch()
//	key := MockedVerificationKey{}
//	signatureBytes, err := base64.RawURLEncoding.DecodeString(rsaValidJwtSignature)
//	require.NoError(t, err)
//	key.On("Verify", jose.KeyOpsVerify, []byte(rsaValidJwtPayload), signatureBytes).Return(true)
//	key.On("Algorithm").Return(rsaValidJwtAlg)
//	ks := MockedTrustKeyStore{}
//	ks.On("Verifier", validJwtKid).Return(&key)
//	ks.On("Get", mock.Anything, validJwtKid).Return(&key, nil)
//	verifier := NewJwtVerifier(&ks)
//
//	// Act
//	kid, claimSet, err := verifier.Verify(rsaValidJwt, []string{"test"})
//
//	// Assert
//	require.Equal(t, ErrInvalidJwtTimeframe, err)
//	require.Empty(t, kid)
//	require.Nil(t, claimSet)
////}
//
//func TestJwtVerifierImpl_Verify_FailsWithNoKnownAudience(t *testing.T) {
//	testcases := []struct {
//		audiences []string
//		seen      []string
//	}{
//		{
//			audiences: []string{"unknown"},
//			seen:      []string{"test"},
//		},
//		{
//			audiences: []string{},
//			seen:      []string{},
//		},
//	}
//	// Setup
//	defer monkey.Patch(time.Now, func() time.Time {
//		return unixStartTime().Add(time.Duration(validJwtNbf) * time.Second)
//	}).Unpatch()
//	key := MockedVerificationKey{}
//	signatureBytes, err := base64.RawURLEncoding.DecodeString(rsaValidJwtSignature)
//	require.NoError(t, err)
//	key.On("Verify", jose.KeyOpsVerify, []byte(rsaValidJwtPayload), signatureBytes).Return(false)
//	key.On("Algorithm").Return(rsaValidJwtAlg)
//	ks := MockedTrustKeyStore{}
//	ks.On("Verifier", validJwtKid).Return(&key)
//	ks.On("Get", mock.Anything, validJwtKid).Return(&key, nil)
//	verifier := NewJwtVerifier(&ks)
//
//	for _, test := range testcases {
//		// Act
//		_, _, err := verifier.Verify(rsaValidJwt, test.audiences)
//
//		// Assert
//		ee := &InvalidFormat{fmt.Sprintf("no expected audience | expected %s | seen %s", test.audiences, test.seen)}
//		assert.Equal(t, ee, err)
//	}
//}
