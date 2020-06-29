package gose

import (
	"bytes"
	"github.com/ThalesIgnite/gose/jose"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/rand"
	"reflect"
	"testing"
)

const (
 	// See https://tools.ietf.org/html/rfc7516#appendix-A.1
 	oaepJweFromSpec = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ"
 	jwkFromSpec = `
{
      "kty":"RSA",
      "kid":"1",
      "key_ops":["decrypt"],
      "alg": "RSA-OAEP",
      "n":"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",
      "e":"AQAB",
      "d":"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",
      "p":"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lffNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",
      "q":"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",
      "dp":"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KLhMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",
      "dq":"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCjywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDBUfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",
      "qi":"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY"
}`
 	)

// Known answer test (KAT). See https://tools.ietf.org/html/rfc7516#appendix-A.1
func TestJweRsaKeyEncryptionDecryptorImpl_Decrypt_KAT(t *testing.T) {
	// load JWK
	buf := bytes.NewReader([]byte(jwkFromSpec))
	jwk, err := LoadJwk(buf, nil)
	require.NoError(t, err)
	key, err := NewRsaDecryptionKey(jwk)
	require.NoError(t, err)
	store, err := NewAsymmetricDecryptionKeyStoreImpl(map[string]AsymmetricDecryptionKey {key.Kid():key})
	require.NoError(t, err)
	decryptor := NewJweRsaKeyEncryptionDecryptorImpl(store)
	pt, aad, err := decryptor.Decrypt(oaepJweFromSpec)
	require.NoError(t, err)
	assert.Equal(t, "The true sign of intelligence is not knowledge but imagination.", string(pt))
	assert.Len(t, aad, 0)
}

func TestJweRsaKeyEncryptionDecryptorImpl_RoundTrip(t *testing.T) {
	params := []struct {
		contentEncryptionAlg jose.Alg
	} {
		{
			contentEncryptionAlg: jose.AlgA256GCM,
		},
		{
			contentEncryptionAlg: jose.AlgA192GCM,
		},
		{
			contentEncryptionAlg: jose.AlgA128GCM,
		},
	}
	for _, testCase := range params {
		t.Run(reflect.TypeOf(testCase.contentEncryptionAlg).Name(), func(tt *testing.T){
			randData := make([]byte, 32)
			_, err := rand.Read(randData)
			require.NoError(tt, err)
			generator := &RsaKeyDecryptionKeyGenerator{}
			decrytionKey, err := generator.Generate(jose.AlgRSAOAEP, 2048, []jose.KeyOps{jose.KeyOpsDecrypt})
			require.NoError(tt, err)
			encryptionKey, err := decrytionKey.Encryptor()
			require.NoError(tt, err)
			publicJwk, err := encryptionKey.Jwk()
			require.NoError(tt, err)
			encryptor, err := NewJweRsaKeyEncryptionEncryptorImpl(publicJwk, testCase.contentEncryptionAlg)
			require.NoError(t, err)
			ct, err := encryptor.Encrypt(randData, []byte("aad"))
			require.NoError(t, err)
			store, err := NewAsymmetricDecryptionKeyStoreImpl(map[string]AsymmetricDecryptionKey {decrytionKey.Kid(): decrytionKey})
			require.NoError(t, err)
			decryptor := NewJweRsaKeyEncryptionDecryptorImpl(store)
			pt, aad, err := decryptor.Decrypt(ct)
			require.NoError(t, err)
			assert.Equal(t, randData, pt)
			assert.Equal(t, []byte("aad"), aad)
		})
	}
}
