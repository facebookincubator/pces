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

package issuers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/facebookincubator/pces/cert"
	"github.com/facebookincubator/pces/oscert"
)

// TLSIssuerConfig contains all configuration parameters for TLSIssuer.
type TLSIssuerConfig struct {
	CACert       *x509.Certificate
	CASigner     crypto.Signer
	CertTemplate *x509.Certificate
	CertSigner   crypto.Signer
	CertDir      string
	OSKeychain   bool
}

// TLSIssuer implements the cert.Issuer interface for TLS certificates.
type TLSIssuer struct {
	cfg     TLSIssuerConfig
	logger  *slog.Logger
	manager *oscert.Manager
}

// Issue implements the cert.Issuer interface method that generates and returns a signed TLS certificate.
func (tlsIssuer TLSIssuer) Issue(_ context.Context) (*tls.Certificate, error) {
	cfg := tlsIssuer.cfg
	now := time.Now()
	validDuration := cfg.CertTemplate.NotAfter.Sub(cfg.CertTemplate.NotBefore)

	cfg.CertTemplate.NotBefore = now
	cfg.CertTemplate.NotAfter = now.Add(validDuration)

	certBytes, err := x509.CreateCertificate(rand.Reader, cfg.CertTemplate, cfg.CACert, cfg.CertSigner.Public(), cfg.CASigner)
	if err != nil {
		return nil, errors.New("failed to create certificate: " + err.Error())
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certBytes, cfg.CACert.Raw},
		PrivateKey:  cfg.CertSigner,
	}

	if err := saveTLSCertToFile(cert, cfg.CertDir); err != nil {
		slog.Warn("failed to save TLS certificate to file", "error", err)
	}

	if cfg.OSKeychain {
		go func() {
			if err := tlsIssuer.addToOSKeychain(cert); err != nil {
				tlsIssuer.logger.Error("agent: certs: add certificate to OS keychain", "error", err)
			}
		}()
	}

	return cert, nil
}

// NewTLSIssuer creates a new instance of TLSIssuer using a config struct.
func NewTLSIssuer(config TLSIssuerConfig) (*TLSIssuer, error) {
	if config.CACert == nil {
		return nil, errors.New("ca certificate is required but was nil")
	}
	if config.CASigner == nil {
		return nil, errors.New("ca signer is required but was nil")
	}
	if config.CertSigner == nil {
		return nil, errors.New("certificate signer is required but was nil")
	}
	if config.CertTemplate == nil {
		return nil, errors.New("certificate template is required but was nil")
	}
	keychain := oscert.NewOSKeychain()
	return &TLSIssuer{
		cfg:     config,
		logger:  slog.Default(),
		manager: oscert.New(keychain, oscert.WithLogger(slog.Default())),
	}, nil
}

func (tlsIssuer *TLSIssuer) addToOSKeychain(cert *tls.Certificate) error {
	if cert == nil {
		return nil
	}

	ctx := context.Background()
	return tlsIssuer.manager.Add(ctx, cert)
}

func saveTLSCertToFile(tlsCert *tls.Certificate, certDir string) error {
	if tlsCert == nil {
		return fmt.Errorf("cert is nil")
	}

	// If no certificate directory is specified, skip saving to disk
	if certDir == "" {
		return nil
	}

	combinedPath := filepath.Join(certDir, fmt.Sprintf("%s.pem", cert.TypeTLS))

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: tlsCert.Certificate[0],
	})

	signer, ok := tlsCert.PrivateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("private key does not implement crypto.Signer interface")
	}

	var keyPEM []byte
	if ecdsaKey, ok := signer.(*ecdsa.PrivateKey); ok {
		bytes, err := x509.MarshalECPrivateKey(ecdsaKey)
		if err != nil {
			return fmt.Errorf("failed to marshal ECDSA private key: %w", err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: bytes,
		})
	}

	pubKey := signer.Public()
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	keyPEM = append(keyPEM, pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})...)

	combinedPEM := append(certPEM, keyPEM...)

	if err := saveBytesToFile(combinedPath, combinedPEM, 0600); err != nil {
		return fmt.Errorf("failed to save combined certificate and key file: %w", err)
	}

	return nil
}
