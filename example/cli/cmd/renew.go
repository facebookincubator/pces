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
	"fmt"

	"github.com/facebookincubator/pces/example/api/client"
	"github.com/spf13/cobra"
)

var (
	label  string
	reason string
)

func init() {
	renewCmd.Flags().StringVar(&label, "label", "", "Certificate label to renew")
	renewCmd.Flags().StringVar(&reason, "reason", "Manual renewal from CLI", "Reason for certificate renewal")
	renewCmd.MarkFlagRequired("label")

	rootCmd.AddCommand(renewCmd)
}

var renewCmd = &cobra.Command{
	Use:   "renew",
	Short: "Renew a certificate",
	Long:  "Request renewal of a certificate managed by the PCeS agent",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runRenew()
	},
}

func runRenew() error {
	c, err := client.NewClient(grpcSocketPath)
	if err != nil {
		return err
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := c.Renew(ctx, label, reason); err != nil {
		return fmt.Errorf("failed to renew certificate: %w", err)
	}

	fmt.Printf("Certificate '%s' renewed successfully\n", label)
	return nil
}
