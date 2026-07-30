// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func getTLSCert(priv crypto.Signer, validAfter, validBefore time.Time) (tls.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName: "test",
		},
		NotBefore: validAfter,
		NotAfter:  validBefore,
	}

	if priv == nil {
		var err error
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return tls.Certificate{}, err
		}
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template,
		priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	var outCert tls.Certificate
	outCert.Certificate = append(outCert.Certificate, cert)
	outCert.PrivateKey = priv
	return outCert, nil
}

func TestTLSOptions(t *testing.T) {
	issuer := &mockIssuer[tls.Certificate]{}
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err)

	badSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err)

	cert, err := getTLSCert(signer, time.Now(), time.Now().Add(time.Hour))
	assert.Nil(t, err)
	tests := []struct {
		name    string
		options []TLSOption
		want    TLS
		failure error
	}{
		{
			name: "default",
			want: TLS{
				common: &common[tls.Certificate]{
					issuer: issuer,
					cert:   nil,
				},
				signer: signer,
			},
		},
		{
			name: "No signer",
			want: TLS{
				common: &common[tls.Certificate]{
					issuer: nil,
				},
				signer: nil,
			},
			failure: ErrNoSigner,
		},
		{
			name: "WithCert",
			want: TLS{
				common: &common[tls.Certificate]{
					issuer: nil,
					cert:   &cert,
				},
				signer: signer,
			},
			options: []TLSOption{
				WithTLSCert(&cert),
			},
		},
		{
			name: "WithCert not matching signer",
			want: TLS{
				common: &common[tls.Certificate]{
					issuer: nil,
					cert:   &cert,
				},
				signer: badSigner,
			},
			options: []TLSOption{
				WithTLSCert(&cert),
			},
			failure: ErrSignerMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewTLS(tt.want.signer, tt.want.issuer, tt.options...)
			if tt.failure != nil {
				assert.ErrorIs(t, err, tt.failure)
				return
			}
			assert.Nil(t, err)
			assert.Equal(t, tt.want.issuer, c.issuer)
			assert.Equal(t, tt.want.cert, c.cert)
			assert.Equal(t, tt.want.signer, c.signer)
		})
	}
}

func TestTLSSign(t *testing.T) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err)

	validCert, err := getTLSCert(signer, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	assert.Nil(t, err)

	expiredCert, err := getTLSCert(signer, time.Now().Add(-time.Hour), time.Now().Add(-time.Minute))
	assert.Nil(t, err)

	futureCert, err := getTLSCert(signer, time.Now().Add(time.Minute), time.Now().Add(time.Hour))
	assert.Nil(t, err)

	invalidCert, err := getTLSCert(signer, time.Now().Add(-time.Hour), time.Now().Add(-time.Minute))
	assert.Nil(t, err)
	invalidCert.Certificate[0] = []byte("invalid cert")

	tests := []struct {
		name string
		cert *tls.Certificate
		err  error
	}{
		{
			name: "valid cert",
			cert: &validCert,
			err:  nil,
		},
		{
			name: "expired cert",
			cert: &expiredCert,
			err:  ErrCertExpired,
		},
		{
			name: "future cert",
			cert: &futureCert,
			err:  ErrCertExpired,
		},
		{
			name: "invalid cert",
			cert: &invalidCert,
			err:  ErrCertInvalid,
		},
	}

	for _, tt := range tests {
		message := []byte("test")
		digest := sha256.Sum256(message)
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewTLS(signer, nil)
			assert.Nil(t, err)
			assert.Equal(t, &signer.PublicKey, c.Public())

			c.cert = tt.cert // cannot use WithTLSCert to initialise with invalid cert.

			signature, err := c.SignMessage(rand.Reader, message, nil)
			assert.ErrorIs(t, err, tt.err)

			if tt.err == nil {
				ok := ecdsa.VerifyASN1(&signer.PublicKey, digest[:], signature)
				assert.True(t, ok)
			}
		})
	}
}

func TestSignerMatchesLeaf(t *testing.T) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err)
	badSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err)
	tlsCert, err := getTLSCert(signer, time.Now(), time.Now().Add(time.Hour))
	assert.Nil(t, err)

	t.Run("success", func(t *testing.T) {
		c := TLS{
			common: &common[tls.Certificate]{cert: &tlsCert},
			signer: signer,
		}
		assert.Nil(t, c.signerMatchesLeaf())
	})

	t.Run("nil cert", func(t *testing.T) {
		c := TLS{
			common: &common[tls.Certificate]{cert: nil},
			signer: signer,
		}
		assert.Nil(t, c.signerMatchesLeaf())
	})

	t.Run("parse matching leaf cert", func(t *testing.T) {
		cpy := tlsCert
		cpy.Leaf = nil
		c := TLS{
			common: &common[tls.Certificate]{cert: &cpy},
			signer: signer,
		}
		assert.Nil(t, c.signerMatchesLeaf())
	})

	t.Run("malformed leaf cert", func(t *testing.T) {
		cpy := tlsCert
		cpy.Certificate = [][]byte{[]byte("invalid cert")}
		cpy.Leaf = nil
		c := TLS{
			common: &common[tls.Certificate]{cert: &cpy},
			signer: signer,
		}
		assert.ErrorIs(t, c.signerMatchesLeaf(), ErrCertInvalid)
	})

	t.Run("signer mismatch", func(t *testing.T) {
		c := TLS{
			common: &common[tls.Certificate]{cert: &tlsCert},
			signer: badSigner,
		}
		assert.ErrorIs(t, c.signerMatchesLeaf(), ErrSignerMismatch)
	})
}

// generateTestCertAndKey creates a test certificate and key for testing purposes.
var (
	pemBundle = `-----BEGIN CERTIFICATE-----
MIIBujCCAWGgAwIBAgIUJ4zMqUdMfYWZPRAHfFJY0h30X7QwCgYIKoZIzj0EAwIw
MzELMAkGA1UEBhMCRkIxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTENMAsGA1UECgwE
UENlUzAeFw0yNTAxMTcxMzQzMjVaFw0zNTAxMTUxMzQzMjVaMDMxCzAJBgNVBAYT
AkZCMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxDTALBgNVBAoMBFBDZVMwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATAxWmx7DvqRnO5zkrwP/jOkoXNDHaIB5sB/36c
2hsqlZlVmV2myxSj0dXNP68JyIC4r+WOieIobXe/f+Dac3Qho1MwUTAdBgNVHQ4E
FgQUxqjxeyIHs9mEKYpSmUIdGuuuKAMwHwYDVR0jBBgwFoAUxqjxeyIHs9mEKYpS
mUIdGuuuKAMwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiBH98SB
6hHbRZxgO0E8ChDmH6s/cql9NUqoXOavdIaxSAIgZ3is7O7I9rtRmWVtRF45Uzga
aw9PTV596wtlAuNzCvY=
-----END CERTIFICATE-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOvA+mn1i7ktn+Y/7y+W0j+NY67oQnCO9A7fIP1JIk3moAoGCCqGSM49
AwEHoUQDQgAEwMVpsew76kZzuc5K8D/4zpKFzQx2iAebAf9+nNobKpWZVZldpssU
o9HVzT+vCciAuK/ljoniKG13v3/g2nN0IQ==
-----END EC PRIVATE KEY-----
`

	pemKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOvA+mn1i7ktn+Y/7y+W0j+NY67oQnCO9A7fIP1JIk3moAoGCCqGSM49
AwEHoUQDQgAEwMVpsew76kZzuc5K8D/4zpKFzQx2iAebAf9+nNobKpWZVZldpssU
o9HVzT+vCciAuK/ljoniKG13v3/g2nN0IQ==
-----END EC PRIVATE KEY-----`
)

func TestParseTLSCertFromFile(t *testing.T) {
	t.Run("file does not exist", func(t *testing.T) {
		path := filepath.Join(testDir, "non-existing-file")
		_, err := parseTLSCertFromFile(path)
		assert.NotNil(t, err)
	})

	t.Run("no certificates", func(t *testing.T) {
		path := filepath.Join(testDir, "key")
		err := os.WriteFile(path, []byte(pemKey), 0644)
		assert.Nil(t, err)
		_, err = parseTLSCertFromFile(path)
		assert.NotNil(t, err)

	})

	t.Run("malformed certificate", func(t *testing.T) {
		path := filepath.Join(testDir, "tls-cert")
		cpy := []byte(pemBundle)
		cpy[40]++
		cpy[41]++
		cpy[42]++
		err := os.WriteFile(path, cpy, 0644)
		assert.Nil(t, err)
		_, err = parseTLSCertFromFile(path)
		assert.NotNil(t, err)
	})

	t.Run("valid certificate", func(t *testing.T) {
		path := filepath.Join(testDir, "tls-cert")
		err := os.WriteFile(path, []byte(pemBundle), 0644)
		assert.Nil(t, err)
		got, err := parseTLSCertFromFile(path)
		assert.Nil(t, err)

		want, err := tls.LoadX509KeyPair(path, path) // compare against stdlib function
		want.PrivateKey = nil
		assert.Equal(t, *got, want)
	})
}

func TestWithTlsCertFromFile(t *testing.T) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err)

	t.Run("error", func(t *testing.T) {
		path := filepath.Join(testDir, "non-existing-file")
		_, err := NewTLS(signer, nil, WithTLSCertFromFile(path))
		assert.NotNil(t, err)
	})

	t.Run("success", func(t *testing.T) {
		path := filepath.Join(testDir, "tls-cert")
		err := os.WriteFile(path, []byte(pemBundle), 0644)
		assert.Nil(t, err)
		want, err := tls.LoadX509KeyPair(path, path)
		assert.Nil(t, err)
		c, err := NewTLS(want.PrivateKey.(crypto.Signer), nil, WithTLSCertFromFile(path))
		assert.Nil(t, err)
		assert.Equal(t, *c.cert, want)
	})
}

func TestTLSType(t *testing.T) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	c, err := NewTLS(signer, nil)
	assert.NoError(t, err)
	assert.Equal(t, TypeTLS, c.Type())
}
