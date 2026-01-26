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
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSH is a SSH certificate.
type SSH struct {
	*common[ssh.Certificate]

	signer ssh.Signer
}

// SSHOption is a functional option for SSH.
type SSHOption func(c *SSH) error

// WithSSHCert sets the SSH certificate.
func WithSSHCert(cert *ssh.Certificate) SSHOption {
	return func(c *SSH) error {
		c.cert = cert
		return nil
	}
}

// WithSSHRenewalFactor sets the renewal factor on a Cert, it determines at what timestamp
// this certificate needs to be renewed relative to its expiry time.
// This renewal time is determined using a decimal factor between 0 and 1 inclusive.
// For example, if the factor is 1, the certificate needs to be renewed at its expiry time. If the factor is 0.5,
// the certificate needs to be renewed halfway between the time it starts to be valid and its expiry time.
func WithSSHRenewalFactor(factor float64) SSHOption {
	return func(c *SSH) error {
		return withRenewalFactor(c.common, factor)
	}
}

// WithSSHCertFromFile sets the SSH certificate from a file.
func WithSSHCertFromFile(path string) SSHOption {
	return func(c *SSH) error {
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("WithSSHCertFromFile: %w", err)
		}
		sshPubKey, _, _, _, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			return fmt.Errorf("WithSSHCertFromFile: %w", err)
		}
		sshCert, ok := sshPubKey.(*ssh.Certificate)
		if !ok {
			return fmt.Errorf("WithSSHCertFromFile: cannot cast public key to ssh certificate")
		}
		c.common.cert = sshCert
		return nil
	}
}

// SSH certificate validity extractor.
func extractSSHValidity(cert *ssh.Certificate) (validAfter, validBefore time.Time, err error) {
	if cert == nil {
		return time.Time{}, time.Time{}, ErrCertInvalid
	}
	validAfter = time.Unix(int64(cert.ValidAfter), 0)
	validBefore = time.Unix(int64(cert.ValidBefore), 0)

	if !validBefore.After(validAfter) {
		return time.Time{}, time.Time{}, ErrCertInvalid
	}

	return validAfter, validBefore, nil
}

// NewSSH creates a new SSH certificate.
func NewSSH(signer ssh.Signer, issuer Issuer[ssh.Certificate], opts ...SSHOption) (*SSH, error) {
	c := &SSH{
		common: &common[ssh.Certificate]{
			issuer:          issuer,
			extractValidity: extractSSHValidity,
		},
		signer: signer,
	}

	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	if c.signer == nil {
		return nil, ErrNoSigner
	}

	if !c.signerMatchesCert() {
		return nil, ErrSignerMismatch
	}

	return c, nil
}

func (c *SSH) signerMatchesCert() bool {
	if c.common.cert == nil {
		return true
	}

	sshKey := c.signer.PublicKey()

	return bytes.Equal(sshKey.Marshal(), c.common.cert.Key.Marshal())
}

// GetSigners returns signers backed by the SSH certificate key.
func (c *SSH) GetSigners() ([]ssh.Signer, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	signer, err := c.certSigner(c.cert, c.signer)
	if err != nil {
		return nil, fmt.Errorf("cert: failed to get ssh signers: %w", err)
	}

	signers := []ssh.Signer{signer}

	// Return current and previous certificate signers,
	// this is to handle the case where the certificate is renewed during
	// establishing SSH connection.
	signer, err = c.certSigner(c.prevCert, c.signer)
	if err == nil {
		return append(signers, signer), nil
	}

	return signers, nil
}

func (c *SSH) certSigner(cert *ssh.Certificate, signer ssh.Signer) (ssh.Signer, error) {
	validAfter, validBefore, err := c.lifetime(cert)
	if err != nil {
		return nil, ErrCertInvalid
	}

	if now := time.Now(); !now.Before(validBefore) || !now.After(validAfter) {
		return nil, ErrCertExpired
	}

	return ssh.NewCertSigner(cert, signer)
}

// Type returns certificate type.
func (c *SSH) Type() string {
	return TypeSSH
}
