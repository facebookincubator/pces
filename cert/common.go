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
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// validityExtractor extracts validity period from a certificate.
type validityExtractor[T any] func(cert *T) (validAfter, validBefore time.Time, err error)

// Certificate errors.
var (
	ErrCertInvalid          = errors.New("certificate is invalid")
	ErrCertExpired          = errors.New("certificate expired")
	ErrCertNotFound         = errors.New("certificate not found")
	ErrCertExists           = errors.New("certificate already exists")
	ErrNoSigner             = errors.New("signer not found")
	ErrSignerMismatch       = errors.New("signer does not match certificate")
	ErrInvalidRenewalFactor = errors.New("renewal factor must be between 0.0 and 1.0")
)

// Supported certificate types.
const (
	TypeSSH = "pces_ssh"
	TypeTLS = "pces_tls"
)

type certs interface {
	ssh.Certificate | tls.Certificate
}

// Certificate defines interface for certificate.
type Certificate interface {
	Issue(ctx context.Context) error
	GetCert(ctx context.Context) (any, error)
	Lifetime(ctx context.Context) (validAfter, validBefore time.Time, err error)
	RenewalFactor(ctx context.Context) float64
	Type() string
}

// Issuer is an interface that represents a certificate issuer.
type Issuer[T certs] interface {
	Issue(ctx context.Context) (*T, error)
}

// common is a struct that represents a certificate.
type common[T certs] struct {
	lock sync.RWMutex

	issuer Issuer[T]

	cert     *T
	prevCert *T

	renewalFactor   float64
	extractValidity validityExtractor[T]
}

// Issue issues a new certificate using provided issuer.
func (c *common[T]) Issue(ctx context.Context) error {
	cert, err := c.issuer.Issue(ctx)
	if err != nil {
		return err
	}

	c.lock.Lock()
	defer c.lock.Unlock()
	c.cert, c.prevCert = cert, c.cert
	return nil
}

// GetCert checks the vailidity of the certificate before returning it.
// If the certificate is invalid or expired, it will return corresponding error.
// It is up to the caller from that point to trigger a renewal.
func (c *common[T]) GetCert(ctx context.Context) (any, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	validAfter, validBefore, err := c.lifetime(c.cert)
	if err != nil {
		return c.cert, err
	}
	if now := time.Now(); !now.Before(validBefore) || !now.After(validAfter) {
		return c.cert, ErrCertExpired
	}

	return *c.cert, nil // shallow copy
}

// Lifetime returns certificate's ValidAfter and ValidBefore.
func (c *common[T]) Lifetime(_ context.Context) (validAfter, validBefore time.Time, err error) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.lifetime(c.cert)
}

func (c *common[T]) lifetime(certificate *T) (validAfter, validBefore time.Time, err error) {
	if certificate == nil {
		return time.Time{}, time.Time{}, ErrCertInvalid
	}

	if c.extractValidity == nil {
		return time.Time{}, time.Time{}, fmt.Errorf("no validity extractor provided for certificate type")
	}

	return c.extractValidity(certificate)
}

// RenewalFactor determines at what timestamp this certificate needs to be renewed relative to its expiry time.
// This renewal time is determined using a decimal factor between 0 and 1 inclusive.
// For example, if the factor is 1, the certificate needs to be renewed at its expiry time. If the factor is 0.5,
// the certificate needs to be renewed halfway between the time it starts to be valid and its expiry time.
func (c *common[T]) RenewalFactor(_ context.Context) float64 {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.renewalFactor
}

func withRenewalFactor[T certs](c *common[T], factor float64) error {
	if factor < 0.0 || factor > 1.0 {
		return fmt.Errorf("%w got: %f", ErrInvalidRenewalFactor, factor)
	}

	c.renewalFactor = factor
	return nil
}
