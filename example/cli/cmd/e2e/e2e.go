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

package e2e

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/facebookincubator/pces/cert"
	"github.com/facebookincubator/pces/example/api/client"
	"github.com/facebookincubator/pces/example/api/pces"
)

// ANSI color codes
const (
	colorReset = "\033[0m"
	colorRed   = "\033[31m"
	colorGreen = "\033[32m"
	colorBlue  = "\033[34m"
	colorBold  = "\033[1m"
	colorDim   = "\033[2m"
)

func printGreen(format string, args ...interface{}) {
	log.Printf("%s%s"+format+"%s\n", append([]interface{}{colorBold, colorGreen}, append(args, colorReset)...)...)
}

func printRed(format string, args ...interface{}) {
	log.Printf("%s%s"+format+"%s\n", append([]interface{}{colorBold, colorRed}, append(args, colorReset)...)...)
}

func printInfoWithKeyValues(prefix string, keyValues ...interface{}) {
	result := fmt.Sprintf("%s%s%s", colorBold, colorDim, prefix)

	for i := 0; i < len(keyValues); i += 2 {
		key := keyValues[i]
		value := keyValues[i+1]

		if i == 0 {
			result += ": "
		} else {
			result += ", "
		}

		result += fmt.Sprintf("%s=%s%s%v%s%s%s", key, colorBlue, colorBold, value, colorReset, colorBold, colorDim)
	}

	result += colorReset
	log.Printf("%s\n", result)
}

// TestResult represents the result of a single test
type TestResult struct {
	Name    string
	Passed  bool
	Message string
}

// TestSuite represents the complete test suite results
type TestSuite struct {
	Tests       []TestResult
	TotalTests  int
	PassedTests int
	FailedTests int
}

// RunTests executes the end-to-end test suite for PCeS agent.
func RunTests(grpcSocketPath, sshSocketPath, certDir string, timeout time.Duration) (*TestSuite, error) {
	printInfoWithKeyValues("Running PCeS agent e2e test suite with", "gRPC socket", grpcSocketPath, "SSH socket", sshSocketPath, "cert dir", certDir)

	suite := &TestSuite{
		Tests: make([]TestResult, 0),
	}

	testCases := []struct {
		name string
		fn   func(string, string, string, time.Duration) error
	}{
		{"Certificate Status Test", testCertificateStatus},
		{"Certificate Renewal Test", testCertificateRenewal},
		{"SSH Agent Test", testSSHAgent},
		{"TLS Test", testTLS},
	}

	fmt.Println("\n-------------------")
	for _, tc := range testCases {
		log.Printf("%s%s  Running %s%s%s%s%s...%s\n",
			colorBold, colorDim, colorBlue, tc.name, colorReset, colorBold, colorDim, colorReset)

		result := TestResult{
			Name: tc.name,
		}

		if err := tc.fn(grpcSocketPath, sshSocketPath, certDir, timeout); err != nil {
			result.Passed = false
			result.Message = err.Error()
			suite.FailedTests++
			printRed(" ✗ FAILED: %s", err.Error())
		} else {
			result.Passed = true
			result.Message = "Test passed successfully"
			suite.PassedTests++
			printGreen(" ✓ PASSED")
		}

		suite.Tests = append(suite.Tests, result)
		suite.TotalTests++
		fmt.Println("-------------------")
	}
	fmt.Println()

	if suite.FailedTests > 0 {
		return suite, fmt.Errorf("%s%s%d/%d tests failed%s", colorBold, colorRed, suite.FailedTests, suite.TotalTests, colorReset)
	}
	printGreen("All tests passed!")

	return suite, nil
}

func testCertificateStatus(grpcSocketPath string, sshSocketPath string, certDir string, timeout time.Duration) error {
	c, err := client.NewClient(grpcSocketPath)
	if err != nil {
		return fmt.Errorf("failed to create gRPC client: %w", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	status, err := c.Status(ctx)
	if err != nil {
		return fmt.Errorf("failed to get status from PCeS agent: %w", err)
	}

	if status == nil {
		return fmt.Errorf("received nil status response")
	}

	if status.Uptime < 0 {
		return fmt.Errorf("invalid uptime value: %d", status.Uptime)
	}

	if status.Certificates == nil {
		return fmt.Errorf("certificates array is nil")
	}

	for i, cert := range status.Certificates {
		if cert == nil {
			return fmt.Errorf("certificate at index %d is nil", i)
		}

		if cert.Label == "" {
			return fmt.Errorf("certificate at index %d has empty label", i)
		}

		if cert.Type == "" {
			return fmt.Errorf("certificate at index %d has empty type", i)
		}

		if cert.ValidAfter > 0 && cert.ValidBefore > 0 && cert.ValidAfter >= cert.ValidBefore {
			return fmt.Errorf("certificate %s has invalid validity period: after=%d, before=%d",
				cert.Label, cert.ValidAfter, cert.ValidBefore)
		}
	}

	printInfoWithKeyValues("Status check successful", "uptime", fmt.Sprintf("%ds", status.Uptime), "certificates", len(status.Certificates))

	return nil
}

func testCertificateRenewal(grpcSocketPath string, _ string, certDir string, timeout time.Duration) error {
	c, err := client.NewClient(grpcSocketPath)
	if err != nil {
		return fmt.Errorf("failed to create gRPC client: %w", err)
	}
	defer c.Close()

	renewReason := "e2e test renewal"
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	initialStatus, err := c.Status(ctx)
	if err != nil {
		return fmt.Errorf("failed to get initial status: %w", err)
	}

	certLabels := []string{cert.TypeSSH, cert.TypeTLS}

	for i, label := range certLabels {
		err = c.Renew(ctx, label, renewReason)
		if err != nil {
			return fmt.Errorf("failed to renew certificate '%s' at index %d: %w", label, i, err)
		}

		printInfoWithKeyValues("Certificate renewal successful", "label", label, "index", i, "reason", renewReason)
	}

	newStatus, err := c.Status(ctx)
	if err != nil {
		return fmt.Errorf("failed to get status after renewal: %w", err)
	}

	if err := verifyRenewal(initialStatus.Certificates, newStatus.Certificates); err != nil {
		return fmt.Errorf("renewal verification failed: %w", err)
	}

	return nil
}

func testSSHAgent(_, sshSocketPath string, certDir string, timeout time.Duration) error {
	conn, err := net.Dial("unix", sshSocketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to SSH agent at %s: %w", sshSocketPath, err)
	}
	defer conn.Close()

	agentClient := agent.NewClient(conn)

	keys, err := agentClient.List()
	if err != nil {
		return fmt.Errorf("failed to list SSH agent keys: %w", err)
	}

	if len(keys) == 0 {
		return fmt.Errorf("no SSH keys found in agent")
	}

	keyPairs := make([]interface{}, 0, len(keys)*2)
	for i, key := range keys {
		keyPairs = append(keyPairs, fmt.Sprintf("\n %d", i+1), key.Format)
	}
	printInfoWithKeyValues(fmt.Sprintf("SSH agent accessible, found %d keys", len(keys)), keyPairs...)

	testData := []byte("test data for SSH signing")

	for i, testKey := range keys {
		signature, err := agentClient.Sign(testKey, testData)
		if err != nil {
			return fmt.Errorf("failed to sign test data with SSH key %d: %w", i+1, err)
		}

		publicKey, err := ssh.ParsePublicKey(testKey.Blob)
		if err != nil {
			return fmt.Errorf("failed to parse SSH public key %d: %w", i+1, err)
		}

		err = publicKey.Verify(testData, signature)
		if err != nil {
			return fmt.Errorf("signature verification failed for key %d: %w", i+1, err)
		}

		printInfoWithKeyValues(fmt.Sprintf("SSH signing test successful for key %d", i+1),
			"key_type", publicKey.Type(),
			"data_size", len(testData),
			"signature_format", signature.Format)
	}

	return nil
}

// extractCertificateFromPEM extracts only the certificate blocks from PEM data.
func extractCertificateFromPEM(pemData []byte) ([]byte, error) {
	var certBlocks []byte
	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certBlocks = append(certBlocks, pem.EncodeToMemory(block)...)
		}
		pemData = rest
	}

	if len(certBlocks) == 0 {
		return nil, fmt.Errorf("no certificate blocks found in PEM data")
	}

	return certBlocks, nil
}

func testTLS(grpcSocketPath string, _ string, certDir string, timeout time.Duration) error {
	c, err := client.NewClient(grpcSocketPath)
	if err != nil {
		return fmt.Errorf("failed to create gRPC client: %w", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	status, err := c.Status(ctx)
	if err != nil {
		return fmt.Errorf("failed to get status from PCeS agent: %w", err)
	}

	var tlsCerts []*pces.CertificateStatus
	for _, certificate := range status.Certificates {
		if certificate.Type == cert.TypeTLS {
			tlsCerts = append(tlsCerts, certificate)
		}
	}

	if len(tlsCerts) == 0 {
		return fmt.Errorf("no TLS certificates found in agent")
	}

	keyPairs := make([]interface{}, 0, len(tlsCerts)*2)
	for i, certificate := range tlsCerts {
		keyPairs = append(keyPairs, fmt.Sprintf("\n %d", i+1), certificate.Label)
	}

	printInfoWithKeyValues(fmt.Sprintf("Found %d TLS certificates", len(tlsCerts)), keyPairs...)

	testData := []byte("test data for TLS signing")

	for i, tlsCert := range tlsCerts {
		agentCertData, err := c.GetCert(ctx, tlsCert.Label)
		if err != nil {
			return fmt.Errorf("failed to get TLS certificate %d (%s): %w", i+1, tlsCert.Label, err)
		}

		// Only check disk certificate if certDir is specified
		if certDir != "" {
			combinedPath := filepath.Join(certDir, fmt.Sprintf("%s.pem", cert.TypeTLS))

			diskCertData, err := os.ReadFile(combinedPath)
			if err != nil {
				return fmt.Errorf("failed to read certificate from disk for %s at path %s: %w", tlsCert.Label, combinedPath, err)
			}

			diskCertOnly, err := extractCertificateFromPEM(diskCertData)
			if err != nil {
				return fmt.Errorf("failed to extract certificate from disk data for %s: %w", tlsCert.Label, err)
			}

			agentCertOnly, err := extractCertificateFromPEM(agentCertData)
			if err != nil {
				return fmt.Errorf("failed to extract certificate from agent data for %s: %w", tlsCert.Label, err)
			}

			if !bytes.Equal(diskCertOnly, agentCertOnly) {
				return fmt.Errorf("certificate mismatch for %s: disk and agent certificates are different", tlsCert.Label)
			}
		}

		block, _ := pem.Decode(agentCertData)
		if block == nil || block.Type != "CERTIFICATE" {
			return fmt.Errorf("failed to decode PEM certificate for %s", tlsCert.Label)
		}

		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse TLS certificate %d (%s): %w", i+1, tlsCert.Label, err)
		}

		signature, err := c.Sign(ctx, tlsCert.Label, testData)
		if err != nil {
			return fmt.Errorf("failed to sign test data with TLS certificate %d (%s): %w", i+1, tlsCert.Label, err)
		}

		err = verifyTLSSignature(certificate.PublicKey, testData, signature)
		if err != nil {
			return fmt.Errorf("signature verification failed for TLS certificate %d (%s): %w", i+1, tlsCert.Label, err)
		}

		certMatchStatus := "N/A (no cert-dir)"
		if certDir != "" {
			certMatchStatus = "✓"
		}

		printInfoWithKeyValues(fmt.Sprintf("TLS test successful for certificate %d", i+1),
			"label", tlsCert.Label,
			"cert_match", certMatchStatus,
			"data_size", len(testData),
			"signature_size", len(signature))
	}

	return nil
}

// verifyTLSSignature verifies a signature using the public key from a TLS certificate
func verifyTLSSignature(publicKey crypto.PublicKey, data, signature []byte) error {
	hash := sha256.Sum256(data)

	pub, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not ECDSA")
	}
	if !ecdsa.VerifyASN1(pub, hash[:], signature) {
		return fmt.Errorf("ECDSA signature verification failed")
	}
	return nil
}

// verifyRenewal checks that certificates were actually renewed by comparing validity periods
func verifyRenewal(initialCerts, newCerts []*pces.CertificateStatus) error {
	if len(initialCerts) != len(newCerts) {
		return fmt.Errorf("certificate count changed after renewal: %d -> %d", len(initialCerts), len(newCerts))
	}

	for _, newCert := range newCerts {
		var initialCert *pces.CertificateStatus
		for _, cert := range initialCerts {
			if cert.Label == newCert.Label {
				initialCert = cert
				break
			}
		}

		if initialCert == nil {
			return fmt.Errorf("certificate %s not found in initial status", newCert.Label)
		}

		if initialCert.ValidAfter == newCert.ValidAfter && initialCert.ValidBefore == newCert.ValidBefore {
			return fmt.Errorf("certificate %s appears not to have been renewed (same validity period)", newCert.Label)
		}

		printInfoWithKeyValues("Certificate renewal verified",
			"label", newCert.Label,
			"old_valid_after", time.Unix(initialCert.ValidAfter, 0).Format(time.RFC3339),
			"new_valid_after", time.Unix(newCert.ValidAfter, 0).Format(time.RFC3339))
	}
	return nil
}
