# Knox -- the high level overview
Knox is a service for storing and rotation of secrets, keys, and passwords used by other services.

## The Problem Knox is Meant to Solve
Pinterest has a plethora of keys or secrets doing things like signing cookies, encrypting data, protecting our network via TLS, accessing our AWS machines, communicating with our third parties, and many more. If these keys become compromised, rotating (or changing our keys) used to be a difficult process generally involving a deploy and likely a code change. Keys/secrets within Pinterest were stored in git repositories. This means they were copied all over our company's infrastructure and present on many of our employees laptops. There was no way to audit who accessed or who has access to the keys. Knox was built to solve these problems.

The goals of Knox are:
- Ease of use for developers to access/use confidential secrets, keys, and credentials
- Confidentiality for secrets, keys, and credentials
- Provide mechanisms for key rotation in case of compromise
- Create audit log to keep track of what systems and users access confidential data

Read more at https://github.com/pinterest/knox/wiki

## Getting knox set up
The first step is to install Go (or use Docker, see below). We require Go >= 1.6 or Go 1.5 with the vendor flag enabled (`GO15VENDOREXPERIMENT=1`). For instructions on setting up Go, please visit https://golang.org/doc/install

After Go is set up (including a `$GOPATH` directory that will store your workspace), please run `go get -d github.com/pinterest/knox` to get the latest version of the knox code.

To compile the devserver and devclient binaries, run `go install github.com/pinterest/knox/cmd/dev_server` and `go install github.com/pinterest/knox/cmd/dev_client`. These can be directly executed, the dev_client expects the server to be running on a localhost. By default, the client uses mTLS with a hardcoded signed cert given for example.com for machine authentication and had github authentication enabled for users.

To start your server run:
```sh
$GOPATH/bin/dev_server
```

For using this client as a user, generate a token via these instructions https://help.github.com/articles/creating-an-access-token-for-command-line-use/ with read:org permissions. This token will be able to get your username and the organization you belong to. With the dev_server running you can now create your first knox key.

```sh
export KNOX_USER_AUTH=<insert generated github token here>
echo -n "My first knox secret" | $GOPATH/bin/dev_client create test_service:first_secret
```

You can retrieve the secret using:
```sh
$GOPATH/bin/dev_client get test_service:first_secret
```

---

# Knox Extension: First Iteration Plan & Architecture Blueprint

## Goals

- Deliver robust client and server implementations for secret management.
- Harden security: authentication, authorization, audit logging, input validation.
- Modularize code for future extensibility (e.g., protocol support).
- Document APIs, configuration, and security features.

## Project Structure

```
knox/
  client/         # Knox client implementation
  server/         # Knox server implementation
  api/            # Shared API types/interfaces
  storage/        # Secret storage backend abstraction
  auth/           # Authentication & authorization logic
  config/         # Configuration management
  main.go         # Entry point for server binary
  README.md       # Documentation
  tests/          # Integration and unit tests
```

## Client API (Go)

```go
type Client struct {
    // Transport, auth, config
}

func (c *Client) GetSecret(name string) (string, error)
func (c *Client) SetSecret(name, value string) error
func (c *Client) DeleteSecret(name string) error
func (c *Client) ListSecrets() ([]string, error)
```

- Transport: Support HTTP (REST/gRPC) with TLS.
- Auth: API key, mTLS, or token-based.

## Server API (Go)

```go
type Server struct {
    // Config, storage, auth
}

func (s *Server) Start() error
func (s *Server) Stop() error
// Internal handlers for CRUD, auth, etc.
```

- Endpoints: `/secrets/{name}` for CRUD, `/secrets` for listing.
- Security: TLS, authentication, authorization, audit logging.
- Storage: Pluggable backend (file, DB, etc.).

## Security Hardening

- Authentication: API keys, mTLS, or JWT.
- Authorization: Per-secret or per-user access control.
- Audit Logging: Log all access and mutation events.
- Input Validation: Strict checks on all incoming data.
- Rate Limiting: Prevent abuse.

## Testing & Documentation

- Unit Tests: For client, server, and storage logic.
- Integration Tests: End-to-end flows.
- Documentation: API usage, configuration, security features.

## Iteration Goals

- Deliver a working client and server with secure, robust secret management.
- Harden against common security threats and edge cases.
- Document everything for easy onboarding and review.

---

You can see all key IDs using:
```sh
$GOPATH/bin/dev_client keys
```

To see all available commands run:
```sh
$GOPATH/bin/dev_client help
```

For production usage, I recommend making your own client, renaming it `knox`, and moving it into you $PATH for ease of use.

For more information on interacting with knox, use `knox help` or go to https://github.com/pinterest/knox/wiki/Knox-Client

## Knox with Docker

You can run a Docker container to get knox set up, instead of installing Go on your host.

```sh
git clone https://github.com/pinterest/knox.git
cd knox
docker run --name knox --rm -v "$PWD":/go/src/github.com/pinterest/knox -it golang /bin/bash
```

This will run a bash shell into the container, mounting a local copy of knox in the go source path.

You can refer back to the section "Getting knox set up" to set up knox.
