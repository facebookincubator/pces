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
	"time"

	"github.com/facebookincubator/pces/cert"
)

// Updater can run update function both manually and automatically.
// On failure retry with exponential backoff is scheduled automatically.
//
// If manual update is running, then automatic update is skipped,
// while manual updates are always appended to an update queue.
type Updater struct {
	minRetry time.Duration
	maxRetry time.Duration

	frequency time.Duration

	done chan struct{}
	reqs chan request

	label  string
	update Update

	autoUpdate bool
	needsRenew func() bool

	logger *slog.Logger
}

// Update is a function that updates certificate and
// calls feedback function on completion.
type Update func(context.Context, OnUpdate)

// OnUpdate is a callback for update completion.
type OnUpdate func(error)

type feedback struct {
	err    error
	reason string
}

type request struct {
	ctx    context.Context
	result chan error
	reason string
}

const (
	reasonAuto       = "auto"
	defaultMinRetry  = 30 * time.Second
	defaultMaxRetry  = 30 * time.Minute
	defaultFrequency = 10 * time.Second

	// maxFlatNotReadyRetries bounds how many consecutive not-ready results are
	// retried at the base interval before exponential backoff resumes.
	maxFlatNotReadyRetries = 10
)

// ErrNotReady reports that an update could not be attempted because a
// precondition was not satisfied, as opposed to the update being attempted and
// failing. Updates reporting it are rescheduled at the minimum retry interval
// rather than backed off exponentially, for at most maxFlatNotReadyRetries
// consecutive results.
var ErrNotReady = errors.New("update preconditions not met")

// NeedsRenewWithFactor returns a function that determines if a certificate needs to be renewed
// based on the provided factor. The factor must be between 0.0 and 1.0 inclusive.
// For example, if the factor is 1.0, the certificate needs to be renewed at its expiry time.
// If the factor is 0.5, the certificate needs to be renewed halfway between the time it starts
// to be valid and its expiry time.
func NeedsRenewWithFactor(c cert.Certificate, factor float64) (func() bool, error) {
	if factor < 0.0 || factor > 1.0 {
		return nil, fmt.Errorf("%w, got: %f", cert.ErrInvalidRenewalFactor, factor)
	}

	return func() bool {
		// Renewal time is defined as start + (end - start) * factor.
		validAfter, validBefore, err := c.Lifetime(context.Background())
		if err != nil {
			// Likely cert is invalid and needs renewal.
			return true
		}
		untilRenewal := float64(validBefore.Sub(validAfter)) * factor
		renewalTime := validAfter.Add(time.Duration(untilRenewal)).Round(time.Millisecond)
		now := time.Now()
		return now.After(renewalTime) || now.Equal(renewalTime)
	}, nil
}

// NewUpdater creates new Updater.
func NewUpdater(label string, update Update, needsRenew func() bool, opts ...UpdaterOption) Updater {
	upd := Updater{
		minRetry:   defaultMinRetry,
		maxRetry:   defaultMaxRetry,
		frequency:  defaultFrequency,
		autoUpdate: true,

		label:      label,
		update:     update,
		needsRenew: needsRenew,

		done: make(chan struct{}),
		reqs: make(chan request, 16),

		logger: slog.Default(),
	}

	for _, opt := range opts {
		opt(&upd)
	}

	return upd
}

func (upd Updater) run() {
	var (
		pending  []request
		inFlight *request

		retryAt   = time.Now()
		retryIn   = upd.minRetry
		reqs      = upd.reqs
		feedbacks = make(chan feedback, 1)

		// Consecutive not-ready results, reset by any other outcome.
		notReady int
	)
	if upd.autoUpdate && upd.needsRenew() {
		upd.reqs <- request{
			ctx:    context.Background(),
			result: make(chan error, 1),
			reason: reasonAuto,
		}
	}

	var tick <-chan time.Time
	if upd.autoUpdate {
		tick = time.NewTicker(upd.frequency).C
	}
	for done := false; !done || inFlight != nil; {
		if done {
			reqs = nil
		}

		select {
		case <-upd.done:
			done = true

		case <-tick:
			// There is an edge-case in this code when wall clock's time is changed,
			// this should be fine for certificates with relatively long lifetime.
			if inFlight != nil || done || time.Now().Before(retryAt) {
				continue
			}

			if upd.needsRenew() {
				pending = append(pending, request{
					ctx:    context.Background(),
					result: make(chan error, 1),
					reason: reasonAuto,
				})
			}

		case r := <-reqs:
			pending = append(pending, r)
			// Manual updates always reset retry interval.
			notReady = 0
			retryIn = upd.minRetry
			retryAt = time.Now().Add(retryIn)

		case fb := <-feedbacks:
			inFlight.result <- fb.err
			inFlight = nil

			pending = pending[1:]

			switch {
			case fb.err == nil:
				notReady = 0
				retryIn = upd.minRetry
				upd.logger.Info(fmt.Sprintf("updater: successfully renewed %q (reason %q)", upd.label, fb.reason))
			case errors.Is(fb.err, ErrNotReady):
				// Not reset once the cap is reached: resetting on the first
				// backed-off attempt would reopen the flat window, and the two
				// would alternate instead of escalating.
				if notReady < maxFlatNotReadyRetries {
					notReady++
					retryIn = upd.minRetry
					upd.logger.Debug("updater: preconditions not met, retrying at base interval",
						"label", upd.label, "reason", fb.reason, "attempt", notReady, "retry_in", retryIn, "err", fb.err)
				} else {
					retryIn = min(retryIn*2, upd.maxRetry)
					upd.logger.Info(fmt.Sprintf("updater: preconditions for %q still not met (%v) (reason %q), backing off, next attempt in %v", upd.label, fb.err, fb.reason, retryIn.Round(time.Second)))
				}
			default:
				// Exponential backoff.
				notReady = 0
				retryIn = min(retryIn*2, upd.maxRetry)
				upd.logger.Info(fmt.Sprintf("updater: failed to renew %q (%v) (reason %q), next attempt in %v", upd.label, fb.err, fb.reason, retryIn.Round(time.Minute)))
			}
			retryAt = time.Now().Add(retryIn)
		}

		if inFlight != nil || len(pending) == 0 {
			continue
		}
		inFlight = &pending[0]

		go upd.update(inFlight.ctx, func(err error) {
			feedbacks <- feedback{err: err, reason: inFlight.reason}
		})
	}

	close(upd.done)
}

func (upd Updater) close() {
	upd.done <- struct{}{}
	<-upd.done
}

func (upd Updater) do(ctx context.Context, reason string) error {
	r := request{
		ctx:    ctx,
		result: make(chan error, 1),
		reason: reason,
	}
	upd.reqs <- r
	return <-r.result
}
