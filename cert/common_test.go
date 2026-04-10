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
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	gossh "golang.org/x/crypto/ssh"
)

// Constants for certificate validity timestamps used in tests
const (
	testValidAfter  = uint64(100)    // Early timestamp for certificate validity start.
	testValidBefore = uint64(100500) // Later timestamp for certificate validity end.
)

type mockIssuer[T certs] struct {
	idx   int
	certs []*T
	errs  []error
}

func (m *mockIssuer[T]) Issue(ctx context.Context) (*T, error) {
	cert, err := m.certs[m.idx], m.errs[m.idx]
	m.idx++
	return cert, err
}

func TestIssue(t *testing.T) {
	certs := []*gossh.Certificate{
		{KeyId: "key1"},
		{KeyId: "key2"},
		nil,
	}

	testErr := errors.New("error")
	issuer := &mockIssuer[gossh.Certificate]{
		certs: certs,
		errs:  []error{nil, nil, testErr},
	}

	c := common[gossh.Certificate]{
		issuer: issuer,
	}
	if err := c.Issue(context.Background()); err != nil {
		t.Fatalf("failed to issue cert: %v", err)
	}
	assert.Equal(t, c.cert, certs[0])
	assert.Nil(t, c.prevCert)

	if err := c.Issue(context.Background()); err != nil {
		t.Fatalf("failed to issue cert: %v", err)
	}
	assert.Equal(t, c.cert, certs[1])
	assert.Equal(t, c.prevCert, certs[0])

	err := c.Issue(context.Background())
	assert.ErrorIs(t, err, testErr)
	assert.Equal(t, c.cert, certs[1])
	assert.Equal(t, c.prevCert, certs[0])
}

func TestGetCert(t *testing.T) {
	t.Run("Invalid cert", func(t *testing.T) {
		c := common[gossh.Certificate]{
			extractValidity: extractSSHValidity,
		}
		_, err := c.GetCert(context.Background())
		assert.ErrorIs(t, err, ErrCertInvalid)
	})

	t.Run("Invalid validity", func(t *testing.T) {
		c := common[gossh.Certificate]{
			cert: &gossh.Certificate{
				ValidAfter:  testValidBefore,
				ValidBefore: testValidAfter,
			},
			extractValidity: extractSSHValidity,
		}
		_, err := c.GetCert(context.Background())
		assert.ErrorIs(t, err, ErrCertInvalid)
	})

	t.Run("Expired cert", func(t *testing.T) {
		c := common[gossh.Certificate]{
			cert: &gossh.Certificate{
				ValidAfter:  testValidAfter,
				ValidBefore: testValidBefore,
			},
			extractValidity: extractSSHValidity,
		}
		_, err := c.GetCert(context.Background())
		assert.ErrorIs(t, err, ErrCertExpired)
	})

	t.Run("Cert from future", func(t *testing.T) {
		now := time.Now()
		c := common[gossh.Certificate]{
			cert: &gossh.Certificate{
				ValidAfter:  uint64(now.Add(time.Hour).Unix()),
				ValidBefore: uint64(now.Add(3 * time.Hour).Unix()),
			},
			extractValidity: extractSSHValidity,
		}
		_, err := c.GetCert(context.Background())
		assert.ErrorIs(t, err, ErrCertExpired)
	})

	t.Run("Valid cert", func(t *testing.T) {
		time.Now()
		key := "key"
		c := common[gossh.Certificate]{
			cert: &gossh.Certificate{
				KeyId:       "key",
				ValidAfter:  testValidAfter,
				ValidBefore: uint64(time.Now().Add(time.Hour).Unix()),
			},
			extractValidity: extractSSHValidity,
		}

		certInterface, err := c.GetCert(context.Background())
		assert.Nil(t, err)
		cert, ok := certInterface.(gossh.Certificate)
		assert.True(t, ok)
		assert.Equal(t, cert.KeyId, key)
	})
}

func TestLifetime(t *testing.T) {
	t.Run("Invalid nil cert", func(t *testing.T) {
		c := common[gossh.Certificate]{
			extractValidity: extractSSHValidity,
		}
		_, _, err := c.Lifetime(context.Background())
		assert.ErrorIs(t, err, ErrCertInvalid)
	})

	t.Run("Invalid validity", func(t *testing.T) {
		c := common[gossh.Certificate]{
			cert: &gossh.Certificate{
				ValidAfter:  100500,
				ValidBefore: 100,
			},
			extractValidity: extractSSHValidity,
		}
		_, _, err := c.Lifetime(context.Background())
		assert.ErrorIs(t, err, ErrCertInvalid)
	})

	t.Run("SSH cert lifetime", func(t *testing.T) {
		after, before := testValidAfter, testValidBefore
		c := common[gossh.Certificate]{
			cert: &gossh.Certificate{
				ValidAfter:  after,
				ValidBefore: before,
			},
			extractValidity: extractSSHValidity,
		}
		validAfter, validBefore, err := c.Lifetime(context.Background())
		assert.Nil(t, err)
		assert.Equal(t, validAfter, time.Unix(int64(after), 0))
		assert.Equal(t, validBefore, time.Unix(int64(before), 0))
	})

	t.Run("TLS cert invalid leaf", func(t *testing.T) {
		after := time.Unix(int64(testValidAfter), 0)
		before := time.Unix(int64(testValidBefore), 0)

		cert, err := getTLSCert(nil, after, before)
		assert.Nil(t, err)
		cert.Certificate[0] = []byte("invalid cert")
		c := common[tls.Certificate]{
			cert:            &cert,
			extractValidity: extractTLSValidity,
		}
		_, _, err = c.Lifetime(context.Background())
		assert.ErrorIs(t, err, ErrCertInvalid)
	})

	t.Run("TLS cert lifetime", func(t *testing.T) {
		after := time.Unix(int64(testValidAfter), 0)
		before := time.Unix(int64(testValidBefore), 0)

		cert, err := getTLSCert(nil, after, before)
		assert.Nil(t, err)
		c := common[tls.Certificate]{
			cert:            &cert,
			extractValidity: extractTLSValidity,
		}
		validAfter, validBefore, err := c.Lifetime(context.Background())
		assert.Nil(t, err)
		assert.Equal(t, validAfter.Unix(), after.Unix())
		assert.Equal(t, validBefore.Unix(), before.Unix())
	})
}

var testDir string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pces*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot create temp dir for tests: %v", err)
		os.Exit(1)
	}
	testDir = dir
	defer os.RemoveAll(dir)
	m.Run()
}
