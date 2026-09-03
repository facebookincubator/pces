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
	"time"

	"github.com/facebookincubator/pces/example/api/client"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(statusCmd)
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get PCeS agent status",
	Long:  "Display the status of the PCeS agent and its certificates",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runStatus()
	},
}

func runStatus() error {
	c, err := client.NewClient(grpcSocketPath)
	if err != nil {
		return err
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	status, err := c.Status(ctx)
	if err != nil {
		return fmt.Errorf("failed to get status: %w", err)
	}

	fmt.Printf("\nAgent status:\n")

	for _, cert := range status.Certificates {
		validBefore := time.Unix(cert.ValidBefore, 0)
		fmt.Printf("	%s certificate:\texpires in %s (%s)\n",
			cert.Label, time.Until(validBefore)/time.Second*time.Second, validBefore.Format("2006-01-02 15:04:05"))
		if cert.ErrorMessage != nil {
			fmt.Printf("      Error: %s\n", *cert.ErrorMessage)
		}
	}

	return nil
}
