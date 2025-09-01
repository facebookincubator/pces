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
	"fmt"

	"github.com/facebookincubator/pces/example/cli/cmd/e2e"
	"github.com/spf13/cobra"
)

var (
	sshSocketPath string
	certDir       string
)

func init() {
	e2eCmd.Flags().StringVar(&sshSocketPath, "ssh-socket-path", "", "Path for the SSH agent socket")
	e2eCmd.MarkFlagRequired("ssh-socket-path")
	e2eCmd.Flags().StringVar(&certDir, "cert-dir", "", "Directory to save certificate files. If not specified, certificates from the disk will not be checked.")

	rootCmd.AddCommand(e2eCmd)
}

var e2eCmd = &cobra.Command{
	Use:    "e2e",
	Short:  "Run end-to-end tests",
	Long:   "Execute the PCeS agent end-to-end test suite",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		return runE2E()
	},
}

func runE2E() error {
	fmt.Println("Starting PCeS agent e2e tests...")

	_, err := e2e.RunTests(grpcSocketPath, sshSocketPath, certDir, timeout)
	if err != nil {
		return fmt.Errorf("e2e tests failed: %w", err)
	}

	return nil
}
