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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

func TestSSHOptions(t *testing.T) {
	issuer := &mockIssuer[ssh.Certificate]{}
	signer, err := getSSHSigner()
	assert.Nil(t, err)

	badSigner, err := getSSHSigner()
	assert.Nil(t, err)

	cert, err := getSSHCertificate(signer, nil)
	assert.Nil(t, err)

	tests := []struct {
		name    string
		options []SSHOption
		want    SSH
		failure error
	}{
		{
			name: "default",
			want: SSH{
				common: &common[ssh.Certificate]{
					issuer: issuer,
					cert:   nil,
				},
				signer: signer,
			},
		},
		{
			name: "no signer",
			want: SSH{
				common: &common[ssh.Certificate]{
					issuer: issuer,
					cert:   nil,
				},
				signer: nil,
			},
			failure: ErrNoSigner,
		},
		{
			name: "WithCert",
			want: SSH{
				common: &common[ssh.Certificate]{
					issuer: nil,
					cert:   cert,
				},
				signer: signer,
			},
			options: []SSHOption{
				WithSSHCert(cert),
			},
		},
		{
			name: "WtihCertMismatch",
			want: SSH{
				common: &common[ssh.Certificate]{
					issuer: nil,
					cert:   cert,
				},
				signer: badSigner,
			},
			options: []SSHOption{
				WithSSHCert(cert),
			},
			failure: ErrSignerMismatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewSSH(tt.want.signer, tt.want.issuer, tt.options...)
			if tt.failure != nil {
				assert.ErrorIs(t, err, tt.failure)
				return
			}
			assert.Nil(t, err)
			assert.Equal(t, tt.want.issuer, c.issuer)
			assert.Equal(t, tt.want.cert, c.cert)
			assert.Equal(t, tt.want.renewalFactor, c.renewalFactor)
			assert.Equal(t, tt.want.signer, c.signer)
		})
	}
}

func TestGetSigners(t *testing.T) {
	signer, err := getSSHSigner()
	assert.Nil(t, err)

	issuer := &mockIssuer[ssh.Certificate]{}

	t.Run("Invalid cert", func(t *testing.T) {
		c, err := NewSSH(signer, issuer)
		assert.Nil(t, err)
		_, err = c.GetSigners()
		assert.ErrorIs(t, err, ErrCertInvalid)
	})

	t.Run("Expired cert", func(t *testing.T) {
		cert, err := getSSHCertificate(signer, nil)
		assert.Nil(t, err)
		cert.ValidAfter = 100
		cert.ValidBefore = 100500
		c, err := NewSSH(signer, issuer, WithSSHCert(cert))
		assert.Nil(t, err)
		_, err = c.GetSigners()
		assert.ErrorIs(t, err, ErrCertExpired)
	})

	t.Run("Cert from future", func(t *testing.T) {
		cert, err := getSSHCertificate(signer, nil)
		assert.Nil(t, err)

		now := time.Now()
		cert.ValidAfter = uint64(now.Add(time.Hour).Unix())
		cert.ValidBefore = uint64(now.Add(3 * time.Hour).Unix())

		c, err := NewSSH(signer, issuer, WithSSHCert(cert))
		assert.Nil(t, err)
		_, err = c.GetSigners()
		assert.ErrorIs(t, err, ErrCertExpired)
	})

	t.Run("Valid cert no previous cert", func(t *testing.T) {
		cert, err := getSSHCertificate(signer, nil)
		assert.Nil(t, err)

		c, err := NewSSH(signer, issuer, WithSSHCert(cert))
		assert.Nil(t, err)
		signers, err := c.GetSigners()
		assert.Nil(t, err)
		assert.Equal(t, len(signers), 1)
		sshCertFromSigner := signers[0].PublicKey().(*ssh.Certificate)
		assert.Equal(t, sshCertFromSigner, cert)
	})

	t.Run("Valid cert valid previous cert", func(t *testing.T) {
		sshCert, err := getSSHCertificate(signer, nil)
		assert.Nil(t, err)

		prevSSHCert, err := getSSHCertificate(signer, nil)
		assert.Nil(t, err)

		c, err := NewSSH(signer, issuer, WithSSHCert(sshCert))
		assert.Nil(t, err)

		c.prevCert = prevSSHCert

		signers, err := c.GetSigners()
		assert.Nil(t, err)
		assert.Equal(t, len(signers), 2)

		sshCertFromSigner := signers[0].PublicKey().(*ssh.Certificate)
		assert.Equal(t, sshCertFromSigner, sshCert)

		sshCertFromSigner = signers[1].PublicKey().(*ssh.Certificate)
		assert.Equal(t, sshCertFromSigner, prevSSHCert)
	})
}

func TestWithSSHCertFromFile(t *testing.T) {
	signer, err := getSSHSigner()
	if err != nil {
		t.Fatalf("failed to create SSH signer: %v", err)
	}

	t.Run("file does not exist", func(t *testing.T) {
		path := filepath.Join(testDir, "non-existing-file")
		_, err := NewSSH(signer, nil, WithSSHCertFromFile(path))
		assert.NotNil(t, err)
	})

	t.Run("invalid certificate", func(t *testing.T) {
		sshCert, err := getSSHCertificate(nil, nil)
		if err != nil {
			t.Fatalf("failed to create SSH certificate: %v", err)
		}
		path := filepath.Join(testDir, "ssh-cert")

		data := ssh.MarshalAuthorizedKey(sshCert)
		data[40]++
		data[41]++
		data[42]++
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatalf("failed to write SSH certificate to file: %v", err)
		}

		_, err = NewSSH(signer, nil, WithSSHCertFromFile(path))
		assert.NotNil(t, err)
	})

	t.Run("valid cert", func(t *testing.T) {
		sshCert, err := getSSHCertificate(signer, nil)
		if err != nil {
			t.Fatalf("failed to create SSH certificate: %v", err)
		}
		path := filepath.Join(testDir, "ssh-cert")
		data := ssh.MarshalAuthorizedKey(sshCert)

		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatalf("failed to write SSH certificate to file: %v", err)
		}

		c, err := NewSSH(signer, nil, WithSSHCertFromFile(path))
		if err != nil {
			t.Fatalf("failed to create SSH certificate: %v", err)
		}
		assert.True(t, equalCerts(*sshCert, *c.cert))
	})
}

func TestSSHType(t *testing.T) {
	signer, err := getSSHSigner()
	assert.NoError(t, err)
	c, err := NewSSH(signer, nil)
	assert.NoError(t, err)
	assert.Equal(t, TypeSSH, c.Type())
}

func getSSHSigner() (ssh.Signer, error) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromSigner(signer)
}

func getSSHCertificate(certKey, caKey ssh.Signer) (*ssh.Certificate, error) {
	var err error
	if certKey == nil {
		certKey, err = getSSHSigner()
		if err != nil {
			return nil, err
		}
	}

	if caKey == nil {
		caKey, err = getSSHSigner()
		if err != nil {
			return nil, err
		}
	}

	now := time.Now()
	sshCert := &ssh.Certificate{
		Nonce:           []byte("nonce"),
		Key:             certKey.PublicKey(),
		Serial:          100500,
		CertType:        ssh.UserCert,
		KeyId:           "PCeS",
		ValidPrincipals: []string{"root"},
		ValidAfter:      uint64(now.Unix()),
		ValidBefore:     uint64(now.Unix()) + 3600,
		SignatureKey:    caKey.PublicKey(),
	}

	if err := sshCert.SignCert(rand.Reader, caKey); err != nil {
		return nil, err
	}
	return sshCert, nil
}

func equalCerts(a, b ssh.Certificate) bool {
	if len(a.Extensions) == 0 {
		a.Extensions = nil
	}
	if len(a.CriticalOptions) == 0 {
		a.CriticalOptions = nil
	}

	if len(b.Extensions) == 0 {
		b.Extensions = nil
	}
	if len(b.CriticalOptions) == 0 {
		b.CriticalOptions = nil
	}

	return bytes.Equal(a.Nonce, b.Nonce) &&
		bytes.Equal(a.Key.Marshal(), b.Key.Marshal()) &&
		a.Serial == b.Serial &&
		a.CertType == b.CertType &&
		a.KeyId == b.KeyId &&
		reflect.DeepEqual(a.ValidPrincipals, b.ValidPrincipals) &&
		a.ValidAfter == b.ValidAfter &&
		a.ValidBefore == b.ValidBefore &&
		reflect.DeepEqual(a.Permissions, b.Permissions) &&
		bytes.Equal(a.Reserved, b.Reserved) &&
		bytes.Equal(a.SignatureKey.Marshal(), b.SignatureKey.Marshal()) &&
		reflect.DeepEqual(a.Signature, b.Signature)
}
