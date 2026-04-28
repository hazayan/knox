# Knox - Self-Hosted Secret Management

Knox is a self-hosted secret management service forked from
[pinterest/knox](https://github.com/pinterest/knox). The target for this fork is
a sturdy secret manager for Unix systems, CLI workflows, and optional
FreeDesktop Secret Service integration.

## Current Status

Knox is under active stabilization. The codebase has meaningful pieces in place:

- AES-256-GCM envelope encryption for stored secrets
- HTTP API with ACL-aware key operations
- CLI commands for key, ACL, and config workflows
- Filesystem, SQLite, memory, and etcd storage packages
- D-Bus Secret Service bridge implementation
- Tests across crypto, storage, server, client, and D-Bus packages

The implementation does not yet live up to the older production claims in the
documentation. Treat it as alpha software until the full test suite is green and
the operational path is documented end to end.

## Intended Use

The practical deployment model is:

```text
Unix server or workstation
  knox-server
  filesystem or SQLite storage
  master key from /etc/knox/master.key or KNOX_MASTER_KEY_FILE
  TLS and simple auth suitable for a private environment

Unix workstation or laptop
  knox CLI
  optional knox-dbus launched by a user service or XDG autostart entry

local scripts and services
  scripts and services using knox CLI or the HTTP API
```

## Build

Prerequisites:

- Go 1.21 or later

Build the three main binaries:

```bash
go build -o bin/knox ./cmd/client
go build -o bin/knox-server ./cmd/server
go build -o bin/knox-dbus ./cmd/dbus
```

## Server Configuration

`knox-server` is currently configured through a YAML file. By default it reads
`/etc/knox/server.yaml`; pass a different path with `--config`.

Minimal local example:

```yaml
bind_address: "127.0.0.1:9000"

storage:
  backend: "filesystem"
  filesystem_dir: "/var/lib/knox/keys"

  # SQLite is also available through the ORM backend:
  # backend: "sqlite"
  # sqlite_path: "/var/lib/knox/knox.db"

auth:
  providers:
    - type: "mock"

observability:
  metrics:
    enabled: true
    endpoint: "/metrics"
  logging:
    level: "info"
    format: "text"
  audit:
    enabled: true
    output: "stdout"

limits:
  rate_limit_per_principal: 100
  max_key_size: "1MB"
  max_keys_per_list: 1000
```

The server needs a 32-byte master key. Supported sources, in priority order:

1. `KNOX_MASTER_KEY`, as base64 or hex
2. `KNOX_MASTER_KEY_FILE`, pointing to an absolute path
3. `/etc/knox/master.key`

Key files must be owner-only, for example:

```bash
install -d -m 0700 /etc/knox
openssl rand -base64 32 > /etc/knox/master.key
chmod 0600 /etc/knox/master.key
```

Start the server:

```bash
knox-server --config /etc/knox/server.yaml
```

## CLI

Initialize client configuration:

```bash
knox config init --server 127.0.0.1:9000
```

Common workflows:

```bash
echo "secret-value" | knox key create app:test
knox key get app:test
knox key list
knox key rotate app:test --data "new-secret-value"
knox acl get app:test
```

The CLI and older client library still need cleanup around legacy cache/register
behavior. See [docs/CLI_GUIDE.md](docs/CLI_GUIDE.md) for current command details.

## Desktop Integration

`knox-dbus` implements a FreeDesktop Secret Service bridge. The intended Unix
desktop path is to launch it with a user service manager or an XDG
session/autostart mechanism.

Current D-Bus limitations are documented in
[docs/DBUS_GUIDE.md](docs/DBUS_GUIDE.md). Browser/libsecret compatibility should
be verified with `secret-tool` and real desktop applications before relying on it
for daily use.

## Stabilization Checklist

Knox should not be considered sturdy until:

- `go test ./...` passes
- the server has one canonical route path
- storage backend create/update semantics are consistent
- audit logging covers key and ACL operations without logging secret values
- master-key rotation cannot remove old cryptors while data still needs them
- generic service-manager examples exist
- backup and restore are documented and tested
- D-Bus behavior is verified with `secret-tool`

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [CLI Guide](docs/CLI_GUIDE.md)
- [D-Bus Guide](docs/DBUS_GUIDE.md)
- [Operations](docs/OPERATIONS.md)
- [Documentation Index](docs/INDEX.md)
