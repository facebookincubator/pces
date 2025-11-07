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

package storage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/facebookincubator/pces/cert"
	"github.com/stretchr/testify/assert"
)

const eps = 3 * time.Millisecond

func TestUpdaterUpdates(t *testing.T) {
	delay := 10 * time.Millisecond
	wantDelay := []time.Duration{
		0, 0, delay,
	}
	timing := make(chan time.Duration, len(wantDelay))

	var lock sync.Mutex
	var iteration int
	start := time.Now()
	retryAt := start
	update := func(_ context.Context, cb OnUpdate) {
		lock.Lock()
		defer lock.Unlock()
		timing <- time.Since(start)
		start = time.Now()
		retryAt = start

		if iteration == 1 {
			retryAt = start.Add(delay)
		}
		iteration++
		cb(nil)
	}

	upd := NewUpdater("test", update, func() bool {
		lock.Lock()
		defer lock.Unlock()
		return time.Now().After(retryAt)
	}, UpdaterMinRetry(time.Millisecond), UpdaterMaxRetry(time.Hour), UpdaterFrequency(time.Millisecond))

	go upd.run()

	for i, want := range wantDelay {
		got := <-timing
		if got < want-eps || got > want+eps {
			t.Errorf("Unexpected update delay: got %v, want %v <= %v <= %v", got, want-eps, got, want+eps)
		}
		if i > 0 {
			continue
		}
		// Auto update followed by manual update, followed by auto update.
		if err := upd.do(context.Background(), "test"); err != nil {
			t.Errorf("update() error: %v", err)
		}
	}
	upd.close()
}

func TestUpdaterExponentialBackoff(t *testing.T) {
	want := []time.Duration{
		0,
		10 * time.Millisecond,
		20 * time.Millisecond,
		35 * time.Millisecond,
		35 * time.Millisecond,
		5 * time.Millisecond,
		time.Hour,
	}

	timing := make(chan time.Duration, len(want))

	var (
		lock      sync.Mutex
		iteration int
	)

	start := time.Now()
	retryAt := start
	update := func(_ context.Context, cb OnUpdate) {
		lock.Lock()
		defer lock.Unlock()
		if iteration == len(want)-1 {
			return
		}

		if iteration < len(want)-3 {
			retryAt = time.Now()
			cb(errors.New("dummy error"))
		} else {
			retryAt = time.Now()
			cb(nil)
		}

		timing <- time.Since(start)
		start = time.Now()
		iteration++
	}

	upd := NewUpdater("test", update, func() bool {
		lock.Lock()
		defer lock.Unlock()
		return !time.Now().Before(retryAt)
	}, UpdaterMinRetry(5*time.Millisecond), UpdaterMaxRetry(35*time.Millisecond), UpdaterFrequency(time.Millisecond))

	go upd.run()

	for i := range len(want) - 1 {
		got := <-timing
		if got < want[i]-eps || got > want[i]+eps {
			t.Errorf("Unexpected update delay %d: got %v, want %v <= %v <= %v", i, got, want[i]-eps, got, want[i]+eps)
		}
	}
	upd.close()
}

func TestDisableAutoUpdate(t *testing.T) {
	upd := NewUpdater("test", func(_ context.Context, cb OnUpdate) {
		t.Errorf("Unexpected update")
		cb(nil)
	}, func() bool {
		return true
	}, UpdaterDisableAutoUpdate(), UpdaterMinRetry(time.Millisecond), UpdaterFrequency(time.Millisecond))

	go upd.run()
	time.Sleep(10 * time.Millisecond)
	upd.close()
}

func TestUpdaterClose(t *testing.T) {
	for i := range 16 {
		t.Run(fmt.Sprintf("iteration=%d", i), func(t *testing.T) {
			updStarted := make(chan struct{})

			done := make(chan string)
			update := func(_ context.Context, cb OnUpdate) {
				close(updStarted)
				time.Sleep(20 * time.Millisecond)
				cb(nil)
				done <- "upd"
			}

			upd := NewUpdater("test", update, func() bool {
				return false
			}, UpdaterMinRetry(time.Millisecond), UpdaterMaxRetry(time.Hour), UpdaterFrequency(time.Millisecond))

			go upd.run()

			go func() {
				if err := upd.do(context.Background(), "test"); err != nil {
					t.Errorf("update() error: %v", err)
				}
			}()

			go func() {
				<-updStarted
				upd.close()
				done <- "close"
			}()

			if got := <-done; got != "upd" {
				t.Errorf("Unexpected done: got %v, want %v", got, "upd")
			}
			if got := <-done; got != "close" {
				t.Errorf("Unexpected done: got %v, want %v", got, "close")
			}
		})
	}
}

// mockCertificate implements the cert.Certificate interface for testing
type mockCertificate struct {
	validAfter    time.Time
	validBefore   time.Time
	renewalFactor float64
}

func (m *mockCertificate) Issue(ctx context.Context) error {
	return nil
}

func (m *mockCertificate) GetCert(ctx context.Context) (any, error) {
	return nil, nil
}

func (m *mockCertificate) Lifetime(ctx context.Context) (time.Time, time.Time, error) {
	return m.validAfter, m.validBefore, nil
}

func (m *mockCertificate) RenewalFactor(ctx context.Context) float64 {
	return m.renewalFactor
}

func (m *mockCertificate) Type() string {
	return "mock"
}

func TestNeedsRenewWithFactor(t *testing.T) {
	// Create a mock certificate for testing
	mockCert := &mockCertificate{
		validAfter:  time.Now().Add(-1 * time.Hour),
		validBefore: time.Now().Add(1 * time.Hour),
	}

	// Test valid factor.
	needsRenew, err := NeedsRenewWithFactor(mockCert, 0.42)
	assert.Nil(t, err)
	assert.NotNil(t, needsRenew)

	// Test invalid factors.
	_, err = NeedsRenewWithFactor(mockCert, -100500)
	assert.NotNil(t, err)
	assert.ErrorIs(t, err, cert.ErrInvalidRenewalFactor)

	_, err = NeedsRenewWithFactor(mockCert, +100500)
	assert.NotNil(t, err)
	assert.ErrorIs(t, err, cert.ErrInvalidRenewalFactor)

	// Test the returned function.
	now := time.Now()

	// Factor 0.0 should always return true (renew immediately).
	needsRenew, err = NeedsRenewWithFactor(mockCert, 0.0)
	assert.Nil(t, err)
	assert.True(t, needsRenew())

	// Factor 0.1 should return true.
	needsRenew, err = NeedsRenewWithFactor(mockCert, 0.1)
	assert.Nil(t, err)
	assert.True(t, needsRenew())

	// Factor 1.0 should return false (renew at expiry).
	needsRenew, err = NeedsRenewWithFactor(mockCert, 1.0)
	assert.Nil(t, err)
	assert.False(t, needsRenew())

	// Factor 0.8 should return false.
	needsRenew, err = NeedsRenewWithFactor(mockCert, 0.8)
	assert.Nil(t, err)
	assert.False(t, needsRenew())

	// Test with a certificate that should be renewed (past renewal time).
	oldMockCert := &mockCertificate{
		validAfter:  now.Add(-2 * time.Hour),
		validBefore: now.Add(1 * time.Hour),
	}
	needsRenew, err = NeedsRenewWithFactor(oldMockCert, 0.5)
	assert.Nil(t, err)
	assert.True(t, needsRenew())
}

func TestUpdaterOptions(t *testing.T) {
	tests := []struct {
		name    string
		options []UpdaterOption
		want    Updater
	}{
		{
			name: "default",
			want: Updater{
				minRetry:   defaultMinRetry,
				maxRetry:   defaultMaxRetry,
				frequency:  defaultFrequency,
				autoUpdate: true,
				logger:     slog.Default(),
			},
		},
		{
			name: "disable auto update",
			options: []UpdaterOption{
				UpdaterDisableAutoUpdate(),
			},
			want: Updater{
				minRetry:   defaultMinRetry,
				maxRetry:   defaultMaxRetry,
				frequency:  defaultFrequency,
				autoUpdate: false,
				logger:     slog.Default(),
			},
		},
		{
			name: "set min retry",
			options: []UpdaterOption{
				UpdaterMinRetry(42 * time.Second),
			},
			want: Updater{
				minRetry:   42 * time.Second,
				maxRetry:   defaultMaxRetry,
				frequency:  defaultFrequency,
				autoUpdate: true,
				logger:     slog.Default(),
			},
		},
		{
			name: "set max retry",
			options: []UpdaterOption{
				UpdaterMaxRetry(42 * time.Second),
			},
			want: Updater{
				minRetry:   defaultMinRetry,
				maxRetry:   42 * time.Second,
				frequency:  defaultFrequency,
				autoUpdate: true,
				logger:     slog.Default(),
			},
		},
		{
			name: "set frequency",
			options: []UpdaterOption{
				UpdaterFrequency(42 * time.Second),
			},
			want: Updater{
				minRetry:   defaultMinRetry,
				maxRetry:   defaultMaxRetry,
				frequency:  42 * time.Second,
				autoUpdate: true,
				logger:     slog.Default(),
			},
		},
		{
			name: "set logger",
			options: []UpdaterOption{
				UpdaterWithLogger(nil),
			},
			want: Updater{
				minRetry:   defaultMinRetry,
				maxRetry:   defaultMaxRetry,
				frequency:  defaultFrequency,
				autoUpdate: true,
				logger:     nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := NewUpdater("test", nil, nil, tt.options...)
			assert.Equal(t, tt.want.minRetry, u.minRetry)
			assert.Equal(t, tt.want.maxRetry, u.maxRetry)
			assert.Equal(t, tt.want.frequency, u.frequency)
			assert.Equal(t, tt.want.autoUpdate, u.autoUpdate)
			assert.Equal(t, tt.want.logger, u.logger)
		})
	}
}
