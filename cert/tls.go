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
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"time"
)

// TLS is a TLS certificate.
type TLS struct {
	*common[tls.Certificate]

	signer crypto.Signer
}

// TLSOption is a functional option for TLS.
type TLSOption func(c *TLS) error

// WithTLSCert sets the TLS certificate.
func WithTLSCert(cert *tls.Certificate) TLSOption {
	return func(c *TLS) error {
		c.cert = cert
		return nil
	}
}

// WithTLSRenewalFactor sets the renewal factor on a Cert, it determines at what timestamp
// this certificate needs to be renewed relative to its expiry time.
// This renewal time is determined using a decimal factor between 0 and 1 inclusive.
// For example, if the factor is 1, the certificate needs to be renewed at its expiry time. If the factor is 0.5,
// the certificate needs to be renewed halfway between the time it starts to be valid and its expiry time.
func WithTLSRenewalFactor(factor float64) TLSOption {
	return func(c *TLS) error {
		return withRenewalFactor(c.common, factor)
	}
}

func parseTLSCertFromFile(path string) (*tls.Certificate, error) {
	pemEncoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var (
		certs [][]byte
		leaf  *x509.Certificate
	)

	for block, rest := pem.Decode(pemEncoded); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}

		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing x509 certificate: %w", err)
		}
		if leaf == nil {
			leaf = c
		}
		certs = append(certs, block.Bytes)
	}

	if leaf == nil {
		return nil, fmt.Errorf("no certificates found")
	}

	return &tls.Certificate{
		Certificate: certs,
		Leaf:        leaf,
	}, nil
}

// WithTLSCertFromFile sets the TLS certificate from a pem-encoded file.
// Only CERTIFICATE blocks are parsed, all other blocks including PRIVATE KEY are ignored.
func WithTLSCertFromFile(path string) TLSOption {
	return func(c *TLS) error {
		cert, err := parseTLSCertFromFile(path)
		if err != nil {
			return fmt.Errorf("WithTLSCertFromFile: %w", err)
		}
		return WithTLSCert(cert)(c)
	}
}

// TLS certificate validity extractor.
func extractTLSValidity(cert *tls.Certificate) (validAfter, validBefore time.Time, err error) {
	if cert == nil {
		return time.Time{}, time.Time{}, ErrCertInvalid
	}

	leaf := cert.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("failed to parse leaf certificate: (%w): %w", ErrCertInvalid, err)
		}
	}
	validAfter, validBefore = leaf.NotBefore, leaf.NotAfter

	if !validBefore.After(validAfter) {
		return time.Time{}, time.Time{}, ErrCertInvalid
	}

	return validAfter, validBefore, nil
}

// NewTLS creates a new TLS certificate.
func NewTLS(signer crypto.Signer, issuer Issuer[tls.Certificate], opts ...TLSOption) (*TLS, error) {
	c := &TLS{
		common: &common[tls.Certificate]{
			issuer:          issuer,
			extractValidity: extractTLSValidity,
		},
		signer: signer,
	}

	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	if err := c.init(); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *TLS) init() error {
	if c.signer == nil {
		return ErrNoSigner
	}

	if err := c.signerMatchesLeaf(); err != nil {
		return err
	}
	if c.cert != nil {
		c.cert.PrivateKey = c.signer
	}
	return nil
}

func (c *TLS) signerMatchesLeaf() error {
	if c.cert == nil {
		return nil
	}

	if c.cert != nil && c.common.cert.Leaf == nil {
		leaf, err := x509.ParseCertificate(c.cert.Certificate[0])
		if err != nil {
			return fmt.Errorf("%w: parsing leaf certificate: %w", ErrCertInvalid, err)
		}
		c.cert.Leaf = leaf
	}

	type equaler interface {
		Equal(x crypto.PublicKey) bool
	}

	leafPubKey, ok := c.cert.Leaf.PublicKey.(equaler)
	if !ok {
		return fmt.Errorf("%w: leaf public key does not implement recommended Equal(crypto.PublicKey) bool function", ErrCertInvalid)
	}
	match := leafPubKey.Equal(c.signer.Public())
	if !match {
		return ErrSignerMismatch
	}
	return nil
}

// SignMessage implements SignMessage() method of crypto.MessageSigner interface.
func (c *TLS) SignMessage(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	validAfter, validBefore, err := c.lifetime(c.cert)
	if err != nil {
		return nil, err
	}

	if now := time.Now(); !now.Before(validBefore) || !now.After(validAfter) {
		return nil, ErrCertExpired
	}

	// Use crypto.SignMessage with SHA256 as the hash function
	if opts == nil {
		opts = crypto.SHA256
	}
	return crypto.SignMessage(c.signer, rand, msg, opts)
}

// Public implements Public() method of crypto.Signer interface.
func (c *TLS) Public() crypto.PublicKey {
	return c.signer.Public()
}

// Type returns certificate type.
func (c *TLS) Type() string {
	return TypeTLS
}

// EncodedCert returns the TLS certificate chain data.
func (c *TLS) EncodedCert(_ context.Context) ([]byte, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	if c.cert == nil {
		return nil, ErrCertNotFound
	}

	if len(c.cert.Certificate) == 0 {
		return nil, ErrCertInvalid
	}

	var encodedChain []byte
	for _, certBytes := range c.cert.Certificate {
		pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
		encodedChain = append(encodedChain, pem.EncodeToMemory(pemBlock)...)
	}

	return encodedChain, nil
}
