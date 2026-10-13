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
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/facebookincubator/pces/cert"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestStorageConstructor(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ts1 := make(chan time.Time, 10)
	ts2 := make(chan time.Time, 10)

	var (
		lock          sync.Mutex
		c1ValidAfter  time.Time
		c1ValidBefore time.Time

		c2ValidAfter  time.Time
		c2ValidBefore time.Time
	)

	c1 := NewMockCertificate(ctrl)
	needsRenew1 := func() bool {
		lock.Lock()
		defer lock.Unlock()
		now := time.Now()
		if c1ValidAfter.Equal(c1ValidBefore) {
			ts1 <- now
			c1ValidAfter = now
			c1ValidBefore = now.Add(10 * time.Millisecond)
		}
		return !time.Now().Before(c1ValidBefore)
	}

	upd1 := NewUpdater("c1", func(ctx context.Context, cb OnUpdate) {
		c1.Issue(ctx)
		cb(nil)
	}, needsRenew1, UpdaterMinRetry(time.Millisecond), UpdaterFrequency(time.Millisecond))

	c1.EXPECT().Issue(gomock.Any()).
		DoAndReturn(func(_ context.Context) error {
			lock.Lock()
			defer lock.Unlock()
			now := time.Now()
			ts1 <- now
			c1ValidBefore = now.Add(time.Hour)
			return nil
		})

	c2 := NewMockCertificate(ctrl)

	needsRenew2 := func() bool {
		lock.Lock()
		defer lock.Unlock()
		now := time.Now()
		if c2ValidAfter.Equal(c2ValidBefore) {
			ts2 <- now
			c2ValidAfter = now
			c2ValidBefore = now.Add(20 * time.Millisecond)
		}
		return !time.Now().Before(c2ValidBefore)
	}

	upd2 := NewUpdater("c2", func(ctx context.Context, cb OnUpdate) {
		c2.Issue(ctx)
		cb(nil)
	}, needsRenew2, UpdaterMinRetry(time.Millisecond), UpdaterFrequency(time.Millisecond))

	c2.EXPECT().Issue(gomock.Any()).
		DoAndReturn(func(_ context.Context) error {
			lock.Lock()
			defer lock.Unlock()
			now := time.Now()
			ts2 <- now
			c2ValidBefore = now.Add(time.Hour)
			return nil
		})

	st := NewStorage(
		WithCertificate("mockCert1", c1, upd1),
		WithCertificate("mockCert2", c2, upd2),
	)

	check := func(ts <-chan time.Time, want time.Duration) {
		start := <-ts
		renew := <-ts

		got := renew.Sub(start)
		if got < want-eps || got > want+eps {
			t.Errorf("Unexpected update delay: got %v, want %v <= %v <= %v", got, want-eps, got, want+eps)
		}
	}

	check(ts1, 10*time.Millisecond)
	check(ts2, 20*time.Millisecond)

	st.Close()
}

func TestStorageGetCert(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c := NewMockCertificate(ctrl)

	label := "mockCert"
	upd := NewUpdater(label, func(ctx context.Context, cb OnUpdate) {
		cb(nil)
	}, func() bool {
		return false
	}, UpdaterMinRetry(time.Millisecond), UpdaterFrequency(time.Millisecond))

	st := NewStorage(
		WithCertificate(label, c, upd),
	)
	defer st.Close()
	stt := st.(*storage)
	if _, err := stt.getCert("does not exist"); err != cert.ErrCertNotFound {
		t.Errorf("getCert() error got %v, want %v", err, cert.ErrCertNotFound)
	}

	got, err := stt.getCert(label)
	if err != nil {
		t.Errorf("getCert() returned error: %v", err)
	}
	if !reflect.DeepEqual(got.c, c) {
		t.Errorf("getCert() got %v, want %v", got.c, c)
	}
}

func TestStorageRenew(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockErr := errors.New("mock error")

	c := NewMockCertificate(ctrl)
	c.EXPECT().Issue(gomock.Any()).Return(nil)
	c.EXPECT().Issue(gomock.Any()).Return(mockErr)

	label := "mockCert"
	upd := NewUpdater(label, func(ctx context.Context, cb OnUpdate) {
		cb(c.Issue(ctx))
	}, func() bool {
		return false
	}, UpdaterMinRetry(time.Millisecond), UpdaterFrequency(time.Millisecond))

	st := NewStorage(
		WithCertificate(label, c, upd),
	)
	defer st.Close()

	if err := st.Renew(context.Background(), "does not exist", "test"); err != cert.ErrCertNotFound {
		t.Errorf("Renew() error got %v, want %v", err, cert.ErrCertNotFound)
	}
	if err := st.Renew(context.Background(), label, "test"); err != nil {
		t.Errorf("Renew() error: %v", err)
	}
	if err := st.Renew(context.Background(), label, "test"); err != mockErr {
		t.Errorf("Renew() error got %v, want %v", err, mockErr)
	}
}

func TestStorageGetValidCert(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	want := 42

	c := NewMockCertificate(ctrl)

	c.EXPECT().GetCert(gomock.Any()).Return(want, nil)

	mockErr := errors.New("mock error")
	c.EXPECT().GetCert(gomock.Any()).Return(nil, cert.ErrCertInvalid)
	c.EXPECT().Issue(gomock.Any()).Return(mockErr)
	c.EXPECT().GetCert(gomock.Any()).Return(nil, cert.ErrCertInvalid)
	c.EXPECT().Issue(gomock.Any()).Return(nil)
	c.EXPECT().GetCert(gomock.Any()).Return(want, nil)
	c.EXPECT().GetCert(gomock.Any()).Return(want, mockErr)

	label := "mockCert"
	upd := NewUpdater(label, func(ctx context.Context, cb OnUpdate) {
		cb(c.Issue(ctx))
	}, func() bool {
		return false
	}, UpdaterMinRetry(time.Millisecond), UpdaterFrequency(time.Millisecond))

	st := NewStorage(
		WithCertificate(label, c, upd),
	)
	defer st.Close()

	if _, err := st.GetValidCert(context.Background(), "does not exist"); err != cert.ErrCertNotFound {
		t.Errorf("GetValidCert() error got %v, want %v", err, cert.ErrCertNotFound)
	}

	got, err := st.GetValidCert(context.Background(), label)
	if err != nil {
		t.Errorf("GetValidCert() returned error: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetValidCert() got %v, want %v", got, want)
	}

	_, err = st.GetValidCert(context.Background(), label)
	if err != mockErr {
		t.Errorf("GetValidCert() error got %v, want %v", err, mockErr)
	}

	got, err = st.GetValidCert(context.Background(), label)
	if err != nil {
		t.Errorf("GetValidCert() returned error: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetValidCert() got %v, want %v", got, want)
	}

	_, err = st.GetValidCert(context.Background(), label)
	if err != mockErr {
		t.Errorf("GetValidCert() error got %v, want %v", err, mockErr)
	}
}

func TestStorageCertificates(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c1 := NewMockCertificate(ctrl)
	c2 := NewMockCertificate(ctrl)
	label1 := "mockCert1"

	upd1 := NewUpdater(label1, func(ctx context.Context, cb OnUpdate) {
		t.Errorf("Should not be called")
	}, func() bool {
		return false
	}, UpdaterDisableAutoUpdate(), UpdaterMinRetry(time.Millisecond), UpdaterFrequency(time.Millisecond))

	label2 := "mockCert2"
	upd2 := NewUpdater(label2, func(ctx context.Context, cb OnUpdate) {
		t.Errorf("Should not be called")
	}, func() bool {
		return false
	}, UpdaterDisableAutoUpdate(), UpdaterMinRetry(time.Millisecond), UpdaterFrequency(time.Millisecond))

	st := NewStorage(
		WithCertificate(label1, c1, upd1),
		WithCertificate(label2, c2, upd2),
	)
	defer st.Close()

	got := st.Certificates()
	want := map[string]cert.Certificate{
		label1: c1,
		label2: c2,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Certificates() got %+v, want %+v", got, want)
	}
}

func TestStorageCertificate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c := NewMockCertificate(ctrl)
	label := "mockCert"

	upd := NewUpdater(label, func(ctx context.Context, cb OnUpdate) {
		t.Errorf("Should not be called")
	}, func() bool {
		return false
	}, UpdaterDisableAutoUpdate(), UpdaterMinRetry(time.Millisecond), UpdaterFrequency(time.Millisecond))

	st := NewStorage(
		WithCertificate(label, c, upd),
	)
	defer st.Close()

	got, err := st.Certificate(label)
	assert.NoError(t, err)
	assert.Equal(t, c, got)

	_, err = st.Certificate("not found")
	assert.Error(t, cert.ErrCertNotFound, err)
}

func TestStorageAddRemove(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	c := NewMockCertificate(ctrl)
	label := "mockCert"

	updated := make(chan struct{})

	upd := NewUpdater(label, func(ctx context.Context, cb OnUpdate) {
		select {
		case updated <- struct{}{}:
		default:
		}
		cb(nil)
	}, func() bool {
		return true
	}, UpdaterMinRetry(time.Millisecond), UpdaterFrequency(time.Millisecond))

	st := NewStorage()
	defer st.Close()

	err := st.Add(label, c, upd)
	assert.NoError(t, err)

	got, err := st.Certificate(label)
	assert.NoError(t, err)
	assert.Equal(t, c, got)

	<-updated // verify updater is running.

	err = st.Add(label, c, upd)
	assert.Error(t, cert.ErrCertExists, err)

	err = st.Remove(label)
	assert.NoError(t, err)

	select {
	case <-updated:
		t.Errorf("updater has not been stopped")
	case <-time.After(3 * time.Second):
	}
	err = st.Remove(label)
	assert.Error(t, cert.ErrCertNotFound, err)
}
