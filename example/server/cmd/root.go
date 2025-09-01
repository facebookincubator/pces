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

package cmd

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/facebookincubator/pces/cert"
	"github.com/facebookincubator/pces/example/issuers"
	"github.com/facebookincubator/pces/example/server/handler"
	"github.com/facebookincubator/pces/sshagent"
	"github.com/facebookincubator/pces/storage"
)

var (
	verbose        bool
	sshSocketPath  string
	grpcSocketPath string
	certDir        string
	osKeychain     bool
	renewalFactor  float64

	rootCmd = &cobra.Command{
		Use:   "pces-server",
		Short: "PCeS server",
		Long:  `PCeS server is a command line interface to start the PCeS agent server.`,
		RunE:  run,
	}
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

// GetRootCmd returns the root command for documentation generation
func GetRootCmd() *cobra.Command {
	return rootCmd
}

func init() {
	rootCmd.Flags().BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	rootCmd.Flags().StringVar(&sshSocketPath, "ssh-socket-path", "", "Path for the SSH agent socket (required). The socket will be refreshed before listening. Remember to set it as an environment variable SSH_AUTH_SOCK")
	rootCmd.Flags().StringVar(&grpcSocketPath, "grpc-socket-path", "", "Path for the gRPC server socket (required). The socket will be refreshed before listening.")
	rootCmd.Flags().StringVar(&certDir, "cert-dir", "", "Directory to save certificate files. If not specified, certificates will not be saved to disk.")
	rootCmd.Flags().BoolVar(&osKeychain, "os-keychain", false, "Enable adding TLS certificates to the OS keychain/certificate store")
	rootCmd.Flags().Float64Var(&renewalFactor, "renewal-factor", 0.5, "Factor used to determine when certificates should be renewed (0.0-1.0)")

	rootCmd.MarkFlagRequired("ssh-socket-path")
	rootCmd.MarkFlagRequired("grpc-socket-path")
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}

func run(cmd *cobra.Command, args []string) error {
	logLevel := slog.LevelInfo
	if verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	logger.Info("Creating SSH and TLS certificates...")

	sshCert, err := createSSHCertificate(logger)
	if err != nil {
		return fmt.Errorf("failed to create SSH certificate: %w", err)
	}

	tlsCert, err := createTLSCertificate(logger)
	if err != nil {
		return fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	sshUpdater, err := createUpdater(cert.TypeSSH, sshCert, logger)
	if err != nil {
		return fmt.Errorf("failed to create SSH updater: %w", err)
	}

	tlsUpdater, err := createUpdater(cert.TypeTLS, tlsCert, logger)
	if err != nil {
		return fmt.Errorf("failed to create TLS updater: %w", err)
	}

	st := storage.NewStorage(
		storage.WithCertificate(cert.TypeSSH, sshCert, sshUpdater),
		storage.WithCertificate(cert.TypeTLS, tlsCert, tlsUpdater),
	)
	defer st.Close()

	logger.Info("Storage configured with certificates")
	for label, cert := range st.Certificates() {
		logger.Info("Certificate configured", "label", label, "type", cert.Type())
	}

	agent, err := createSSHAgent(st, logger)
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}

	logger.Info("Setting up SSH agent server...")

	// Try removing existing socket left from previous runs, ignore failures, worst case Listener will fail.
	os.Remove(sshSocketPath)
	sshListener, err := net.Listen("unix", sshSocketPath)
	if err != nil {
		return fmt.Errorf("failed to create SSH Agent listener %q: %w", sshSocketPath, err)
	}
	defer func() {
		sshListener.Close()
		os.Remove(sshSocketPath)
	}()

	logger.Info("Setting up gRPC server...")
	grpcServer, err := handler.NewServer(st, handler.WithLogger(logger))
	if err != nil {
		return fmt.Errorf("failed to create gRPC server: %w", err)
	}

	// Try removing existing socket left from previous runs, ignore failures, worst case Listener will fail.
	os.Remove(grpcSocketPath)
	grpcListener, err := net.Listen("unix", grpcSocketPath)
	if err != nil {
		return fmt.Errorf("failed to setup gRPC socket listener: %w", err)
	}
	defer func() {
		grpcListener.Close()
		os.Remove(grpcSocketPath)
	}()

	logger.Info("Starting SSH agent and Thrift servers...")

	sshErrCh := make(chan error, 1)
	grpcErrCh := make(chan error, 1)

	go func() {
		logger.Info("Starting SSH agent server...")
		err := agent.Start(sshListener)
		if err != nil {
			logger.Error("SSH agent server error", "error", err)
		}
		sshErrCh <- err
	}()
	logger.Info("SSH agent server started in background")

	go func() {
		logger.Info("Starting gRPC server...")
		err := grpcServer.Start(grpcListener)
		if err != nil {
			logger.Error("gRPC server error", "error", err)
		}
		grpcErrCh <- err
	}()
	logger.Info("gRPC server started in background")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case <-sigCh:
		logger.Info("Received termination signal")
	case err := <-sshErrCh:
		logger.Error("SSH agent server failed", "error", err)
	case err := <-grpcErrCh:
		logger.Error("gRPC server failed", "error", err)
	}

	logger.Info("Shutting down...")
	// TODO: Implement graceful shutdown logic here
	return nil
}

// createSSHAgent creates an SSH agent.
func createSSHAgent(st storage.Storage, logger *slog.Logger) (*sshagent.Agent, error) {
	logger.Info("Creating SSH agent...")
	agent, err := sshagent.New(st, sshagent.WithLogger(logger))
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH agent: %w", err)
	}

	logger.Info("SSH agent created")
	return agent, nil
}

func createSSHCertificate(logger *slog.Logger) (cert.Certificate, error) {
	sshIssuer, sshSigner, err := createSSHIssuer(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH issuer: %w", err)
	}
	sshCert, err := cert.NewSSH(sshSigner, sshIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH certificate: %w", err)
	}

	logger.Info("SSH certificate created successfully")
	return sshCert, nil
}

func createTLSCertificate(logger *slog.Logger) (cert.Certificate, error) {
	tlsIssuer, tlsSigner, err := createTLSIssuer(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS issuer: %w", err)
	}
	tlsCert, err := cert.NewTLS(tlsSigner, tlsIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	logger.Info("TLS certificate created successfully")
	return tlsCert, nil
}

func createSSHIssuer(logger *slog.Logger) (*issuers.SSHIssuer, ssh.Signer, error) {
	// Create CA key
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	caSigner, err := ssh.NewSignerFromSigner(caPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create SSH signer from CA key: %w", err)
	}

	// Generate certificate private key (implementation differs between SKS and disk)
	certSigner, err := generateSSHCertPrivateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate certificate key: %w", err)
	}

	certKey, err := ssh.NewSignerFromSigner(certSigner)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create SSH signer from certificate key: %w", err)
	}

	cfg := issuers.SSHIssuerConfig{
		CASigner:        caSigner,
		CertType:        ssh.UserCert,
		KeyID:           "pces-storage-demo",
		ValidPrincipals: []string{"user1", "user2"},
		ValidDuration:   24 * time.Hour,
		CertSigner:      certSigner,
		CertDir:         certDir,
	}

	issuer, err := issuers.NewSSHIssuer(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create SSH issuer: %w", err)
	}
	logger.Info("SSH issuer created successfully")
	return issuer, certKey, nil
}

func createTLSIssuer(logger *slog.Logger) (*issuers.TLSIssuer, crypto.Signer, error) {
	const keySize = 2048
	validDuration := 24 * time.Hour
	now := time.Now()

	subject := pkix.Name{
		Organization:  []string{"Meta"},
		Country:       []string{"US"},
		Locality:      []string{"Menlo Park"},
		StreetAddress: []string{"1 Hacker Way"},
		PostalCode:    []string{"94025"},
	}

	ipAddresses := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	dnsNames := []string{"localhost", "meta.com"}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Generate certificate private key (implementation differs between SKS and disk)
	certSigner, err := generateTLSCertPrivateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate cert key: %w", err)
	}

	caTemplate := &x509.Certificate{
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              now.Add(validDuration),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	certTemplate := &x509.Certificate{
		Subject:        subject,
		IPAddresses:    ipAddresses,
		DNSNames:       dnsNames,
		NotBefore:      now,
		NotAfter:       now.Add(validDuration),
		SubjectKeyId:   []byte{1, 2, 3, 4, 5},
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:       x509.KeyUsageDigitalSignature,
		IsCA:           false,
		MaxPathLenZero: true,
	}

	caCertBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPrivKey.Public(), caPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	cfg := issuers.TLSIssuerConfig{
		CACert:       caCert,
		CASigner:     caPrivKey,
		CertTemplate: certTemplate,
		CertSigner:   certSigner,
		CertDir:      certDir,
		OSKeychain:   osKeychain,
	}

	issuer, err := issuers.NewTLSIssuer(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create TLS issuer: %w", err)
	}
	logger.Info("TLS issuer created successfully")
	return issuer, certSigner, nil
}

func createUpdater(label string, certificate cert.Certificate, logger *slog.Logger) (storage.Updater, error) {
	needsUpdateFunc, err := storage.NeedsRenewWithFactor(certificate, renewalFactor)
	if err != nil {
		return storage.Updater{}, fmt.Errorf("failed to create needs update function: %w", err)
	}

	logger.Info("Created certificate updater",
		"label", label,
		"type", certificate.Type())

	return storage.NewUpdater(
		label,
		func(ctx context.Context, cb storage.OnUpdate) {
			err := certificate.Issue(ctx)
			cb(err)
		},
		needsUpdateFunc,
		storage.UpdaterFrequency(20*time.Second),
		storage.UpdaterMinRetry(5*time.Second),
		storage.UpdaterMaxRetry(1*time.Minute),
	), nil
}
