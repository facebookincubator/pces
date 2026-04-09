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

package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/facebookincubator/pces/example/api/pces"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Option is a functional option for configuring the PCeS gRPC client.
type Option func(*Client) error

// Client implements a gRPC client for the PCeS API.
type Client struct {
	socketPath string
	logger     *slog.Logger
	timeout    time.Duration
	client     pces.PCeSAgentClient
}

// NewClient creates a new PCeS gRPC client.
func NewClient(socketPath string, opts ...Option) (*Client, error) {
	if socketPath == "" {
		return nil, errors.New("socket path cannot be empty")
	}
	client := &Client{
		socketPath: socketPath,
		logger:     slog.Default(),
	}
	for _, opt := range opts {
		if err := opt(client); err != nil {
			return nil, err
		}
	}

	client.logger.Info("Creating PCeS gRPC client connection", "socket_path", client.socketPath)

	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		d := net.Dialer{}
		return d.DialContext(ctx, "unix", client.socketPath)
	}

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
	}

	conn, err := grpc.NewClient("unix:///"+client.socketPath, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	client.client = pces.NewPCeSAgentClient(conn)
	client.logger.Info("Created PCeS gRPC client", "socket_path", client.socketPath)

	return client, nil
}

// Renew sends a renew request to the PCeS gRPC server.
func (c *Client) Renew(ctx context.Context, label, reason string) error {
	c.logger.Info("Sending renew request", "label", label, "reason", reason)
	_, err := c.client.Renew(ctx, &pces.RenewRequest{
		Label:  label,
		Reason: reason,
	})

	if err != nil {
		c.logger.Error("Failed to renew certificate", "label", label, "error", err)
		return err
	}

	c.logger.Info("Certificate renewed successfully", "label", label)
	return nil
}

// Status sends a status request to the PCeS gRPC server.
func (c *Client) Status(ctx context.Context) (*pces.AgentStatus, error) {
	c.logger.Info("Sending status request")
	resp, err := c.client.Status(ctx, &pces.StatusRequest{})
	if err != nil {
		c.logger.Error("Failed to get status", "error", err)
		return nil, err
	}

	c.logger.Info("Status request completed", "certificates_count", len(resp.Status.Certificates))
	return resp.Status, nil
}

// GetCert sends a get certificate request to the PCeS gRPC server.
func (c *Client) GetCert(ctx context.Context, label string) ([]byte, error) {
	c.logger.Info("Sending get certificate request", "label", label)
	resp, err := c.client.GetTLSCert(ctx, &pces.GetTLSCertRequest{
		Label: label,
	})

	if err != nil {
		c.logger.Error("Failed to get certificate", "label", label, "error", err)
		return nil, err
	}

	c.logger.Info("Certificate retrieved successfully", "label", label)
	return resp.CertData, nil
}

// Sign sends a sign request to the PCeS gRPC server.
func (c *Client) Sign(ctx context.Context, label string, data []byte) ([]byte, error) {
	c.logger.Info("Sending sign request", "label", label, "data_length", len(data))
	resp, err := c.client.SignWithTLSCert(ctx, &pces.SignWithTLSCertRequest{
		Label: label,
		Data:  data,
	})

	if err != nil {
		c.logger.Error("Failed to sign data", "label", label, "error", err)
		return nil, err
	}

	c.logger.Info("Data signed successfully", "label", label)
	return resp.Signature, nil
}
