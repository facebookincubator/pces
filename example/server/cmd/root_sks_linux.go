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

//go:build sks_backend && linux

package cmd

import (
	"bytes"
	"crypto"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/facebookincubator/sks"
)

var sksKeyDir string

func init() {
	rootCmd.Flags().StringVar(&sksKeyDir, "sks-key-dir", "", "Directory to store SKS key files persistently.")

	rootCmd.MarkFlagRequired("sks-key-dir")
}

// generateSSHCertPrivateKey generates a certificate private key using SKS for SSH
func generateSSHCertPrivateKey() (crypto.Signer, error) {
	sksKeyPath := filepath.Join(sksKeyDir, "pces-sks-key.blob.ssh")
	akPath := filepath.Join(sksKeyDir, "pces-ak-key.blob.ssh")
	return createSKSKey("ssh-cert", "pces-ssh-cert", sksKeyPath, akPath)
}

// generateTLSCertPrivateKey generates a certificate private key using SKS for TLS
func generateTLSCertPrivateKey() (crypto.Signer, error) {
	sksKeyPath := filepath.Join(sksKeyDir, "pces-sks-key.blob.tls")
	akPath := filepath.Join(sksKeyDir, "pces-ak-key.blob.tls")
	return createSKSKey("tls-cert", "pces-tls-cert", sksKeyPath, akPath)
}

// createSKSKey creates an SKS key by loading existing key blobs from disk if available,
// creating the key with SKS, and storing updated blobs back to disk if they differ
func createSKSKey(keyLabel, keyTag, sksKeyPath, akPath string) (sks.Key, error) {
	sksKeyBlob, akBlob, err := loadKeys(sksKeyPath, akPath)
	if err != nil {
		return nil, err
	}

	key, err := sks.New(keyLabel, keyTag, sks.WithAKKeyBlob(akBlob), sks.WithSKSKeyBlob(sksKeyBlob))
	if err != nil {
		return nil, err
	}

	newAKBlob, newSKSBlob, err := key.EncryptedBlob()
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(newSKSBlob, sksKeyBlob) || !bytes.Equal(newAKBlob, akBlob) {
		slog.Warn("Key blobs have changed, updating stored keys for %s", keyLabel)
		if err := storeKeys(newSKSBlob, sksKeyPath, newAKBlob, akPath); err != nil {
			return nil, err
		}
	}

	return key, nil
}

func loadKeys(sksKeyPath string, akPath string) (keyBlob []byte, akBlob []byte, err error) {
	keyBlob, err = os.ReadFile(sksKeyPath)
	if err != nil {
		return nil, nil, err
	}

	akBlob, err = os.ReadFile(akPath)
	if err != nil {
		return nil, nil, err
	}

	return
}

func storeKeys(sksKeyBlob []byte, sksKeyPath string, akBlob []byte, akPath string) error {
	if err := os.MkdirAll(filepath.Dir(sksKeyPath), 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(akPath), 0700); err != nil {
		return err
	}

	if err := os.WriteFile(akPath, akBlob, 0600); err != nil {
		return err
	}

	if err := os.WriteFile(sksKeyPath, sksKeyBlob, 0600); err != nil {
		return err
	}

	return nil
}
