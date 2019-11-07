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

package gose

import (
	"bytes"
	"errors"
	"github.com/thalesignite/gose/jose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"net/http"
	"testing"
)

const (
	// Extracted from https://www.googleapis.com/oauth2/v3/certs
	jwks = `
{
  "keys": [
    {
      "kid": "60f4060e58d75fd3f70beff88c794a775327aa31",
      "e": "AQAB",
      "kty": "RSA",
      "alg": "RS256",
      "n": "vFfCjiB67cRoJE-zyhZJyjDAUbdAd18Jt69ZkD4JTT8SJ6WviOR6Z5PV_mfF_LwxXy7UalFUZ4zCtWEyoHudcZV9s835-QPNPA2gZ55ChKNSlV3PJXnATf_87Ll50ewuIoe3eKzUFWBrPPB9-Q6SiRGN3STb2PTOXKgTnaUPi0fPwD5ZzhZOXTY67M0l-cX53WMliLguHpDUqbmlK_w4fBNXVWwlPtEhZag-FIavt3kH4hcNEj1hC-cju0_RHE7Dx6t3HFF3aGnsnqRPauAXIrVctLTQJVWDrpObRLOnpqDcoD4Y-cN2PaqLTK0vTnBTIAiP4sazDNCEOl-Zy1ul_w",
      "use": "sig"
    },
    {
      "kid": "df8d9ee403bcc7185ad51041194bd3433742d9aa",
      "e": "AQAB",
      "kty": "RSA",
      "alg": "RS256",
      "n": "nQgOafNApTMwKerFuGXDj8HZ7hUSFPUV4_SzYj79SF5giP0IfF6Ksnb5Jy0pQ_MXQ6XNuh6eZqCfAPXUwHtoxE29jpe6L6DGKPLTr8RTbNhdIsorc1yXiPcail58gftq1fmegZw0KO6QtBpKYnBWoZw4PJkuP8ZdGanA0btsZRRRYVmSOKuYDNHfVJlcrD4cqAOL3BPjWQIrZszwTVmw0FjiU9KfGtU0rDYnas-mZv1qfetZkTA3YPTqSspCNZDbGCVXpJnr4pai0E7lxFgDNDN2IDk955Pf8eG8oNCfqkHXfnWDrTlXP7SSrYmEaBPcmMKOHdjyrYPk0lWI8-urXw",
      "use": "sig"
    }
  ]
}`
)

type httpClientMock struct {
	mock.Mock
}

func (client *httpClientMock) Get(url string) (resp *http.Response, err error) {
	args := client.Called(url)
	return args.Get(0).(*http.Response), args.Error(1)
}

func TestJwksTrustStore_Add(t *testing.T) {
	store := NewJwksKeyStore("", "")
	err := store.Add("", &jose.PublicRsaKey{})
	assert.Error(t, err, "read-only trust store")
}

func TestJwksTrustStore_Remove(t *testing.T) {
	store := NewJwksKeyStore("", "")
	removed := store.Remove("", "")
	assert.False(t, removed)
}

func TestJwksTrustStore_Get(t *testing.T) {
	mockedClient := &httpClientMock{}
	mockedClient.On("Get", "https://www.googleapis.com/oauth2/v3/certs").Return(
		&http.Response{
			StatusCode: http.StatusOK,
			Body: ioutil.NopCloser(bytes.NewReader([]byte(jwks))),
		}, nil).Once()
	store := NewJwksKeyStore("https://accounts.google.com", "https://www.googleapis.com/oauth2/v3/certs")
	store.client = mockedClient
	key := store.Get("https://accounts.google.com", "60f4060e58d75fd3f70beff88c794a775327aa31")
	assert.NotNil(t, key)
	require.Len(t, store.keys, 2)
	assert.NotNil(t, store.Get("https://accounts.google.com", "df8d9ee403bcc7185ad51041194bd3433742d9aa"))
	mockedClient.AssertExpectations(t)
}

func TestJwksTrustStore_GetHttpClientError(t *testing.T) {
	mockedClient := &httpClientMock{}
	mockedClient.On("Get", "https://www.googleapis.com/oauth2/v3/certs").Return(
		(*http.Response)(nil), errors.New("expected")).Times(2)
	store := NewJwksKeyStore("https://accounts.google.com", "https://www.googleapis.com/oauth2/v3/certs")
	store.client = mockedClient
	for i := 0; i < 2; i++ {
		key := store.Get("https://accounts.google.com", "invalid")
		assert.Nil(t, key)
		require.Len(t, store.keys, 0)
	}
	mockedClient.AssertExpectations(t)
}

func TestJwksTrustStore_GetHttpError(t *testing.T) {
	mockedClient := &httpClientMock{}
	mockedClient.On("Get", "https://www.googleapis.com/oauth2/v3/certs").Return(
		&http.Response{
			StatusCode: http.StatusForbidden,
			Body: ioutil.NopCloser(bytes.NewReader([]byte(jwks))),
		}, nil).Times(2)
	store := NewJwksKeyStore("https://accounts.google.com", "https://www.googleapis.com/oauth2/v3/certs")
	store.client = mockedClient
	for i := 0; i < 2; i++ {
		key := store.Get("https://accounts.google.com", "invalid")
		assert.Nil(t, key)
		require.Len(t, store.keys, 0)
	}
	mockedClient.AssertExpectations(t)
}

func TestJwksTrustStore_GetInvalidJwksEncoding(t *testing.T) {
	mockedClient := &httpClientMock{}
	mockedClient.On("Get", "https://www.googleapis.com/oauth2/v3/certs").Return(
		&http.Response{
			StatusCode: http.StatusOK,
			Body: ioutil.NopCloser(bytes.NewReader([]byte("invalid"))),
		}, nil).Times(2)
	store := NewJwksKeyStore("https://accounts.google.com", "https://www.googleapis.com/oauth2/v3/certs")
	store.client = mockedClient
	for i := 0; i < 2; i++ {
		key := store.Get("https://accounts.google.com", "invalid")
		assert.Nil(t, key)
		require.Len(t, store.keys, 0)
	}
	mockedClient.AssertExpectations(t)
}
