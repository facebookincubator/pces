<div align="center">
  <img src="logo.png" alt="PCeS Logo" width="400" height="auto">
  <h1>PCeS: Persistent Certificate Store</h1>
</div>

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/facebookincubator/pces)
[![Go Build](https://github.com/facebookincubator/pces/actions/workflows/go-build.yml/badge.svg)](https://github.com/facebookincubator/pces/actions/workflows/go-build.yml)
[![PCES E2E Testing](https://github.com/facebookincubator/pces/actions/workflows/e2e-test.yml/badge.svg)](https://github.com/facebookincubator/pces/actions/workflows/e2e-test.yml)

**PCeS (Persistent Certificate Store)** is a certificate lifecycle management system written in Go.

## Key Features:

- Automatic certificate renewal and issuance
- SSH and x.509 certificate support
- SSH agent integration
- Windows keychain integration

The repo also provides a **CLI and daemon components** for flexible deployment.

- **Integration with [SKS](http://github.com/facebookincubator/sks)** for leveraging hardware security modules (e.g TPM, SecureEnclave)
- **gRPC-based client-server architecture** as an example usage

Requires Go 1.25+ and is distributed as `github.com/facebookincubator/pces` module.

# Introduction

PCeS is a **certificate management tool** designed to simplify the lifecycle management of SSH and X.509 certificates. Originally developed as part of Meta's internal certificate infrastructure, PCeS has been extracted into a standalone, open-source module that can be deployed in any environment.

PCeS addresses common certificate management challenges including **expiration monitoring**, **automatic renewal**, and **secure storage**, making it suitable for development environments, CI/CD systems, and production deployments where certificate lifecycle automation is critical.

# Getting started

The best place to start is *[`example`](https://github.com/facebookincubator/pces/tree/main/example)* folder. You can also expore the [man pages](https://github.com/facebookincubator/pces/tree/main/example/man) for more details.

The system consists of a [**certificate agent daemon**](https://github.com/facebookincubator/pces/tree/main/example/server) that handles automatic certificate issuance and renewal, and a [**command-line client**](https://github.com/facebookincubator/pces/tree/main/example/cli) for manual operations and status monitoring. Communication between components uses gRPC over Unix sockets.

### Example Usage

You can explore an **example** of running and creating a PCeS daemon server in the [root.go](https://github.com/facebookincubator/pces/blob/main/example/server/cmd/root.go) file.


1. Create SSH and X.509 Certificates
    - Generate SSH and TLS certificate issuers with appropriate keys and configurations.
    ```go
    sshIssuer := issuers.NewSSHIssuer(cfg)
    tlsIssuer := issuers.NewTLSIssuer(cfg)
    ```
    - Create certificate objects that handle issuance and renewal.
    ```go
    sshCert := cert.NewSSH(sshSigner, sshIssuer)
    tlsCert := cert.NewTLS(tlsSigner, tlsIssuer)
    ```
2. Create Updaters for Automatic Renewal
    - For each certificate type, create an updater that periodically checks if renewal is needed and triggers issuance.
    ```go
    needsUpdateFunc := storage.NeedsRenewWithFactor(certificate, defaultRenewalFactor)
    updater := storage.NewUpdater(
        label,
        func(ctx context.Context, cb storage.OnUpdate) {
            err := certificate.Issue(ctx)
            cb(err)
        },
        needsUpdateFunc,
        storage.UpdaterFrequency(20*time.Second),
        storage.UpdaterMinRetry(5*time.Second),
        storage.UpdaterMaxRetry(1*time.Minute),
    )
    ```
3. Configure Storage
    - Initialize a storage object that holds certificates and their updaters, managing lifecycle and updates.
    ```go
    storage := storage.NewStorage(
        storage.WithCertificate(cert.TypeSSH, sshCert, sshUpdater),
        storage.WithCertificate(cert.TypeTLS, tlsCert, tlsUpdater),
    )
    ```
4. Create SSH Agent
    - Instantiate an SSH agent that integrates with the storage to provide SSH certificate access.
    ```go
    agent := sshagent.New(st, sshagent.WithLogger(logger))
    ```
5. Setup Unix Socket Listeners
    - Prepare Unix domain sockets for the SSH agent and server, ensuring proper permissions and cleanup of existing sockets.
    ```go
    sshListener  := net.Listen("unix", sshSocketPath)
    grpcListener := net.Listen("unix", grpcSocketPath)
    ```

# Installation

**Prerequisites:**

- Go 1.25 or later

**Install dependencies:**

Follow the Protobuf installation instructions in the [protobuf.dev](https://protobuf.dev/installation/) website.

```bash
# Install GO Protobuf compiler
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Install mockgen
go install go.uber.org/mock/mockgen@latest

# Generate code, install plugins and build
go generate ./api/if/...
go build -v ./...

# Run server binaries
go run ./example/server --help  # w/o sks backend
go run -tags sks_backend ./example/server --help  # with sks backend
```

> **Note for the SKS usage:**
To use SecureEnclave on Mac, your app must have a registered App ID (com.apple.application-identifier entitlement). For more information, see [this thread]( https://developer.apple.com/forums/thread/728150).

# Development

Project structure:

```bash
├── cert          # Certificate types and interfaces for SSH and TLS
├── example       # Example implementations and usage
│   ├── api       # API definitions and gRPC server/client code
│   ├── cli       # Command-line interface client implementation
│   ├── issuers   # Certificate issuer implementations
│   ├── man       # Manual pages and documentation
│   └── server    # Certificate agent server implementation
├── oscert        # OS certificate integration utilities
├── sshagent      # SSH agent implementation and integration
└── storage       # Certificate storage and updater logic
```

# Run tests

Examples of the tests run can be found in the GitHub Actions workflows for CI/CD.

## Run Unit tests

```bash
go generate ./generate_mocks.go   # Generate test mocks
go test ./...
```

## Run e2e tests

```bash
# Generate protobuf code
go generate ./api/if/...
```

```bash
# Run a server w/o SKS
go run ./example/server
    --ssh-socket-path=<ssh socket path>
    --grpc-socket-path=<grpc socket path>
    --cert-dir=<cert directory>

# Run a server with SKS
go run -tags sks_backend ./example/server
    --ssh-socket-path=<ssh socket path>
    --grpc-socket-path=<grpc socket path>
    --cert-dir=<cert directory>

# Run a server with OS keychain integration (works for Windows only)
go run ./example/server
    --ssh-socket-path=<ssh socket path>
    --grpc-socket-path=<grpc socket path>
    --cert-dir=<cert directory>
    --os-keychain
```

```bash
# Run e2e tests from the client
go run ./example/server e2e
    --ssh-socket-path=<ssh socket path>
    --grpc-socket-path=<grpc socket path>
    --cert-dir=<cert directory>
```

# License
PCeS is published under the Apache v2.0 License.
