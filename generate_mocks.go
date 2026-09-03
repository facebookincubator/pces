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

// Package pces contains mock generation directives for PCES interfaces.
package pces

// This file is used to generate mocks for the project.
// Run `go generate ./...` to generate all mocks.

// Generate mocks for each package in their own directory
//go:generate mockgen -destination=oscert/mock_oscert.go -package=oscert github.com/facebookincubator/pces/oscert OSKeychain

//go:generate mockgen -destination=storage/mock_storage.go -package=storage github.com/facebookincubator/pces/storage Storage

//go:generate mockgen -destination=cert/mock_cert.go -package=cert github.com/facebookincubator/pces/cert Certificate

//go:generate mockgen -destination=sshagent/mock_agent.go -package=sshagent golang.org/x/crypto/ssh/agent Agent

//go:generate mockgen -destination=sshagent/mock_storage.go -package=sshagent github.com/facebookincubator/pces/storage Storage

//go:generate mockgen -destination=storage/mock_cert.go -package=storage github.com/facebookincubator/pces/cert Certificate
