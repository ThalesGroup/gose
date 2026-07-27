// SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
// SPDX-License-Identifier: MIT

package gose

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/eclipse-keypont/gose/jose"
)

// Interface wrapper to allow mocking of http client.
type httpClient interface {
	Do(req *http.Request) (resp *http.Response, err error)
}

// JwksTrustStore is an implementation of the TrustStore interface and can be used for accessing VerificationKeys.
type JwksTrustStore struct {
	lock         sync.Mutex
	url          string
	inputIssuers string //csv of issuers
	issuers      []string
	keys         []VerificationKey
	client       httpClient
}

// Add this method is not supported on a JwksTrustStore instance and will always return an error.
func (store *JwksTrustStore) Add(issuer string, jwk jose.Jwk) error {
	return errors.New("read-only trust store")
}

// Remove this method is not supported on a JwksTrustStore instance and will always return false.
func (store *JwksTrustStore) Remove(issuer, kid string) bool {
	return false
}

// Get returns a verification key for the given issuer and key id. If no key is found nil is returned.
func (store *JwksTrustStore) Get(ctx context.Context, issuer, kid string) (vk VerificationKey, err error) {
	store.lock.Lock()
	defer store.lock.Unlock()

	foundIssuer := false

	//lazy instantiation of the issuer list
	if len(store.issuers) == 0 {
		store.issuers = strings.Split(store.inputIssuers, ",")
	}

	//search our list for the provided issuer
	for _, issuerInStore := range store.issuers {
		if issuerInStore == issuer {
			foundIssuer = true
			break
		}
	}

	//is the provided issuer in our list?
	if foundIssuer {

		for _, key := range store.keys {
			if key.Kid() == kid {
				vk = key
				return
			}
		}
		// Not found. Refresh the keys
		var response *http.Response
		var req *http.Request
		if req, err = http.NewRequestWithContext(ctx, http.MethodGet, store.url, nil); err != nil {
			err = fmt.Errorf("error creating request for JWKS from %s: %v", store.url, err)
			return
		}
		response, err = store.client.Do(req)
		if err != nil {
			err = fmt.Errorf("error encountered retrieving JWKS from %s: %v", store.url, err)
			return
		}
		if response.StatusCode != http.StatusOK {
			err = fmt.Errorf("error encountered retrieving JWKS from %s: %d %s", store.url, response.StatusCode, response.Status)
			return
		}
		decoder := json.NewDecoder(response.Body)
		var jwks jose.Jwks
		if err = decoder.Decode(&jwks); err != nil {
			err = fmt.Errorf("error encountered retrieving JWKS from %s: invalid encoding", store.url)
			return
		}
		keys := make([]VerificationKey, 0, len(jwks.Keys))
		for _, jwk := range jwks.Keys {
			vk, err = NewVerificationKey(jwk)
			if err != nil {
				err = fmt.Errorf("failed to load verification key from JWK: %v", err)
				return
			}
			keys = append(keys, vk)
		}
		// Replace the keys for our store.
		store.keys = keys

		// Try and find key in newly cached keys
		for _, key := range store.keys {
			if key.Kid() == kid {
				vk = key
				return key, nil
			}
		}
	}
	// No such currently valid key or issuer
	return
}

// NewJwksKeyStore creates a new instance of a TrustStore and can be used to load verification keys.
func NewJwksKeyStore(issuerList, url string) *JwksTrustStore {
	return &JwksTrustStore{
		url:          url,
		inputIssuers: issuerList,
		client: &http.Client{
			Timeout: time.Second * 30,
		},
	}
}
