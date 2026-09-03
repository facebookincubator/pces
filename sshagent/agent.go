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

package sshagent

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/facebookincubator/pces/cert"
	"github.com/facebookincubator/pces/storage"
)

// Errors returned by Agent.
var (
	ErrAgentLocked    = errors.New("agent is locked")
	ErrAgentNotLocked = errors.New("agent is not locked")
	ErrNotImplemented = errors.New("not implemented")
)

// Option is a functional option for New.
type Option func(a *Agent) error

// Interceptor is a function that is called when a method is called on the agent.
type Interceptor func(method string, duration time.Duration, err error)

// WithKeys adds the given keys to the agent.
func WithKeys(keys []agent.AddedKey) Option {
	return func(a *Agent) error {
		for _, key := range keys {
			if err := a.keyring.Add(key); err != nil {
				return err
			}
		}
		return nil
	}
}

// WithInterceptor sets the interceptor for the agent.
func WithInterceptor(interceptor Interceptor) Option {
	return func(a *Agent) error {
		a.interceptor = interceptor
		return nil
	}
}

// WithLogger sets the logger for the agent.
func WithLogger(logger *slog.Logger) Option {
	return func(a *Agent) error {
		a.logger = logger
		return nil
	}
}

// WithRequestTimeout sets the request timeout for the agent.
func WithRequestTimeout(timeout time.Duration) Option {
	return func(a *Agent) error {
		a.requestTimeout = timeout
		return nil
	}
}

// New returns a new Agent.
func New(st storage.Storage, opts ...Option) (*Agent, error) {
	a := &Agent{
		keyring:        agent.NewKeyring(),
		st:             st,
		logger:         slog.Default(),
		requestTimeout: 30 * time.Second,
	}

	for _, opt := range opts {
		if err := opt(a); err != nil {
			return nil, err
		}
	}

	return a, nil
}

var _ agent.Agent = &Agent{}

// Agent is a PCeS implementation of the ssh agent interface.
type Agent struct {
	lock   sync.Mutex
	locked bool

	keyring agent.Agent // agent.NewKeyring()
	st      storage.Storage

	interceptor    Interceptor
	logger         *slog.Logger
	requestTimeout time.Duration
	running        bool
}

func (a *Agent) intercept(method string, op func() error) error {
	start := time.Now()
	err := op()
	if a.interceptor == nil {
		return err
	}
	a.interceptor(method, time.Since(start), err)
	return err
}

// List returns the identities known to the agent.
func (a *Agent) List() (keys []*agent.Key, err error) {
	err = a.intercept("List", func() error {
		a.lock.Lock()
		defer a.lock.Unlock()
		if a.locked {
			return nil
		}

		keys, err = a.keyring.List()
		if err != nil {
			a.logger.Error("keyring List()", "err", err)
		}

		for _, signer := range a.signers() {
			pub := signer.PublicKey()
			keys = append(keys, &agent.Key{
				Format: pub.Type(),
				Blob:   pub.Marshal(),
			})
		}
		return nil
	})

	return keys, err
}

// Sign has the agent sign the data using a protocol 2 key as defined in [PROTOCOL.agent] section 2.6.2.
func (a *Agent) Sign(key ssh.PublicKey, data []byte) (signature *ssh.Signature, err error) {
	err = a.intercept("Sign", func() error {
		a.lock.Lock()
		defer a.lock.Unlock()
		if a.locked {
			return ErrAgentLocked
		}

		wanted := key.Marshal()
		signers := a.signers()
		for _, signer := range signers {
			if bytes.Equal(signer.PublicKey().Marshal(), wanted) {
				signature, err = signer.Sign(rand.Reader, data)
				return err
			}
		}
		signature, err = a.keyring.Sign(key, data)
		return err
	})
	return signature, err
}

// Add adds a private key to the agent.
func (a *Agent) Add(key agent.AddedKey) error {
	return a.intercept("Add", func() error {
		a.lock.Lock()
		defer a.lock.Unlock()
		if a.locked {
			return ErrAgentLocked
		}

		if key.Certificate != nil {
			return fmt.Errorf("cannot add certificate: %w", ErrNotImplemented)
		}

		return a.keyring.Add(key)
	})
}

// Remove removes all identities with the given public key.
func (a *Agent) Remove(key ssh.PublicKey) error {
	return a.intercept("Remove", func() error {
		a.lock.Lock()
		defer a.lock.Unlock()
		if a.locked {
			return ErrAgentLocked
		}
		return fmt.Errorf("'Remove' %w", ErrNotImplemented)
	})
}

// RemoveAll removes all identities.
func (a *Agent) RemoveAll() error {
	return a.intercept("RemoveAll", func() error {
		a.lock.Lock()
		defer a.lock.Unlock()
		if a.locked {
			return ErrAgentLocked
		}
		return fmt.Errorf("'RemoveAll' %w", ErrNotImplemented)
	})
}

// Lock locks the agent. Sign and Remove will fail, and List will empty an empty list.
func (a *Agent) Lock(passphrase []byte) error {
	return a.intercept("Lock", func() error {
		a.lock.Lock()
		defer a.lock.Unlock()
		if a.locked {
			return ErrAgentLocked
		}

		err := a.keyring.Lock(passphrase)
		a.locked = err == nil
		return err
	})
}

// Unlock undoes the effect of Lock
func (a *Agent) Unlock(passphrase []byte) error {
	return a.intercept("Unlock", func() error {
		a.lock.Lock()
		defer a.lock.Unlock()
		if !a.locked {
			return ErrAgentNotLocked
		}

		err := a.keyring.Unlock(passphrase)
		a.locked = err != nil
		return err
	})
}

// Signers returns signers for all the known identities.
func (a *Agent) Signers() (signers []ssh.Signer, err error) {
	err = a.intercept("Signers", func() error {
		a.lock.Lock()
		defer a.lock.Unlock()
		if a.locked {
			return ErrAgentLocked
		}

		signers, err = a.keyring.Signers()
		if err != nil {
			a.logger.Error("keyring Signers()", "err", err)
		}

		certSigners := a.signers()
		signers = append(signers, certSigners...)
		return nil
	})
	return signers, err
}

func (a *Agent) signers() (signers []ssh.Signer) {
	for _, c := range a.st.Certificates() {
		if c.Type() != cert.TypeSSH {
			continue
		}

		ss, err := c.(*cert.SSH).GetSigners()
		if err != nil {
			a.logger.Error("cert Signers()", "err", err)
			continue
		}
		signers = append(signers, ss...)
	}
	return signers
}

// deadlineConn wraps a net.Conn and resets its deadline before every Read
// or Write.
type deadlineConn struct {
	net.Conn
	timeout time.Duration
}

func (c *deadlineConn) Read(b []byte) (int, error) {
	if err := c.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *deadlineConn) Write(b []byte) (int, error) {
	if err := c.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

// Serve starts the SSH agent server using the provided listener.
func (a *Agent) serve(listener net.Listener) error {
	a.logger.Info("SSH agent server listening")

	// Start accepting connections.
	for {
		conn, err := listener.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				a.logger.Warn("timeout error accepting connection", "error", err)
				continue
			}
			return fmt.Errorf("failed to accept connection: %w", err)
		}

		go func(c net.Conn) {
			defer c.Close()

			// requestTimeout is an idle timeout here, not a hard cutoff.
			dc := &deadlineConn{Conn: c, timeout: a.requestTimeout}
			if err := agent.ServeAgent(a, dc); err != nil && !errors.Is(err, io.EOF) {
				a.logger.Error("error serving agent connection", "error", err)
			}
		}(conn)
	}
}

// Start starts the PCeS Thrift server.
func (a *Agent) Start(listener net.Listener) error {
	a.lock.Lock()
	if a.running {
		a.lock.Unlock()
		return errors.New("server is already running")
	}

	a.running = true
	a.lock.Unlock()

	sshErrCh := a.startSSHAgent(listener)

	// Directly return the error from the channel
	return <-sshErrCh
}

// startSSHAgent sets up and starts the SSH agent on a separate Unix socket.
func (a *Agent) startSSHAgent(listener net.Listener) <-chan error {
	a.logger.Info("Created SSH agent Unix socket", "path", listener.Addr().String())

	// Start SSH agent server in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		a.logger.Info("Starting SSH agent server", "socket_path", listener.Addr().String())
		if err := a.serve(listener); err != nil {
			a.logger.Error("SSH agent server error", "error", err)
			errCh <- err
		}
	}()

	return errCh
}
