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
- Vault-like one-time initialization with explicit global administrators
- FIDO2/WebAuthn authentication for short-lived user and machine API tokens
- FIDO2 hmac-secret wrapping for the Knox master key at rest
- Filesystem, SQLite, memory, and etcd storage packages
- D-Bus Secret Service bridge implementation
- Tests across crypto, storage, server, client, and D-Bus packages

The current server, storage, crypto, and CLI paths are covered by the Go test
suite. The D-Bus bridge still needs live verification with Secret Service
clients before it should be treated as a dependable desktop secret store.

## Intended Use

The practical deployment model is:

```text
Unix server or workstation
  knox-server
  filesystem or SQLite storage
  initialized global administrator state
  master key from an encrypted FIDO2 bundle, or from a legacy file/env source
  TLS and simple auth appropriate for the deployment

Unix workstation or laptop
  knox CLI
  optional knox-dbus launched by a user service or XDG autostart entry

local scripts and services
  scripts and services using knox CLI or the HTTP API
```

## Build

Prerequisites:

- Go 1.24 or later

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

initialization:
  state_file: "/usr/local/etc/knox/init.json"

access_control:
  policy_file: "/usr/local/etc/knox/policies.json"

master_key:
  backend: "fido2"
  encrypted_key_file: "/var/db/knox/master.key.fido2"
  metadata_file: "/usr/local/etc/knox/fido2-master-key-credential.json"
  device: "auto"
  pin_file: "/var/run/knox/.fido2-master-key.pin"

storage:
  backend: "filesystem"
  filesystem_dir: "/var/lib/knox/keys"

  # SQLite is also available through the ORM backend:
  # backend: "sqlite"
  # sqlite_path: "/var/lib/knox/knox.db"

auth:
  fido2:
    enabled: true
    rp_id: "knox.example.net"
    rp_name: "Knox"
    origins:
      - "https://knox.example.net"
    token_issuer: "knox"
    token_ttl: "15m"
    token_signing_key_file: "/usr/local/etc/knox/fido2-auth-token.key"
    credentials_file: "/usr/local/etc/knox/fido2-auth-principals.json"
  providers:
    - type: "fido2"

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

Knox has two separate FIDO2 flows in hardened deployments:

1. Storage unlock: a FIDO2 hmac-secret credential unwraps the Knox master key
   during server startup so the storage backend can be decrypted.
2. Identity authentication: a different WebAuthn/FIDO2 credential proves a Knox
   user or machine principal and mints a short-lived API token.

These flows may use the same physical authenticator, but they must use distinct
credentials, metadata files, token/key material, and operator ceremonies. The
storage-unlock credential does not grant API access, and the root/admin identity
credential does not unwrap storage.

`master_key.backend: "fido2"` is the hardened path. `knox-server key
fido2-enroll`, `key init`, `key migrate`, `key backup`, `key restore`, and
`key unlock-test` manage that bundle explicitly; normal server startup only
loads the configured bundle.

For compatibility, `master_key.backend: "default"` or `"file"` loads a 32-byte
plaintext master key. Supported legacy sources, in priority order:

1. `KNOX_MASTER_KEY`, as base64 or hex
2. `KNOX_MASTER_KEY_FILE`, pointing to an absolute path
3. `/etc/knox/master.key`

See [FIDO2 Master Key Wrapping](docs/FIDO2_MASTER_KEY.md) and
[FIDO2 Authentication](docs/FIDO2_AUTH.md) for the storage-unlock and identity
flows.

Key files must be owner-only, for example:

```bash
install -d -m 0700 /etc/knox
openssl rand -base64 32 > /etc/knox/master.key
chmod 0600 /etc/knox/master.key
```

Initialize the server before the first start. This creates the persistent
initialization state and prints a one-time bootstrap token for the first global
administrator:

```bash
knox-server --config /etc/knox/server.yaml init \
  --principal-type user \
  --subject admin \
  --group knox-admins
```

The initialization state is created with owner-only permissions and cannot be
created twice. FIDO2 credential administration is restricted to principals named
in this state, or users in one of its admin groups. Per-secret ACLs remain
separate from this global administrator role.

Inspect initialized administrators without exposing secret material:

```bash
knox-server --config /etc/knox/server.yaml admin status
```

The bootstrap token printed by `init` is intentionally one-time operator
material. It should be used to enroll the first administrator authenticator and
then discarded. Knox does not persist a reusable root token.

Local privileged token minting has two explicit modes:

```bash
knox-server --config /etc/knox/server.yaml admin recover-token \
  --principal-type user \
  --subject admin

knox-server --config /etc/knox/server.yaml auth mint-token \
  --automation \
  --principal-type machine \
  --subject kha-controller
```

`admin recover-token` is for initialized global administrators only. It is a
recovery path, not a steady-state automation credential. `auth mint-token
--automation` mints a short-lived machine token for a scoped automation
principal; access still comes from per-key ACLs or ACL policies and should be
limited to the namespaces that automation owns. FIDO2 user tokens are sent with
the Knox `0u` provider prefix, while FIDO2 machine tokens are sent with `0m`.
A server with the `fido2` auth provider enabled accepts both prefixes through
the same signing key and principal store.

Inspect a local token's claims without printing token material:

```bash
knox auth inspect-token
knox auth inspect-token --token-file ~/.config/knox/machine-token
```

The inspection command is a local diagnostic. It decodes token claims so an
operator can verify the principal and expiry selected by the client; it does not
validate the token signature.

Start the server:

```bash
knox-server --config /etc/knox/server.yaml
```

## CLI

Initialize client configuration:

```bash
knox config init --server 127.0.0.1:9000
```

Client and D-Bus profiles use `scheme: "http"` or `scheme: "https"` with a
plain `host:port` server value. A full `http://` or `https://` server URL also
works and takes precedence over the separate scheme field.

Common workflows:

```bash
echo "secret-value" | knox key create app:test
knox key get app:test
knox key list
knox key rotate app:test --data "new-secret-value"
knox acl get app:test
```

ACL policies provide Vault-inspired namespace defaults for newly-created keys.
Policies are global-admin managed JSON documents. Rules match exact key IDs or
prefixes ending in `*`, and matching grants are merged into the key ACL when the
key is created:

```json
{
  "name": "trust-services",
  "rules": [
    {
      "pattern": "service:kanidm:*",
      "grants": [
        {"type": "UserGroup", "id": "knox-admins", "access": "Admin"}
      ]
    }
  ]
}
```

```bash
knox policy put trust-services.json
knox policy get trust-services
knox policy list
```

## License

Knox is distributed under the Apache License 2.0. See [LICENSE](LICENSE).

Policies do not bypass per-key ACL checks for existing keys.

See [docs/CLI_GUIDE.md](docs/CLI_GUIDE.md) for current command details.

## Desktop Integration

`knox-dbus` implements a FreeDesktop Secret Service bridge. The intended Unix
desktop path is to launch it with a user service manager or an XDG
session/autostart mechanism.

Current D-Bus limitations are documented in
[docs/DBUS_GUIDE.md](docs/DBUS_GUIDE.md). Browser/libsecret compatibility should
be verified with `secret-tool` and real desktop applications before relying on it
for daily use.

## Stabilization Checklist

Current stabilization state:

- `go test ./...` passes
- the server uses one canonical route path
- storage backend create/update/delete semantics are tested
- supported backends are limited to memory, filesystem, SQLite, and etcd
- audit logging covers key and ACL operations without logging secret values
- master-key rotation protects data that still needs previous cryptors
- generic service-manager examples exist
- backup and restore are documented and tested
- D-Bus behavior still needs live verification with `secret-tool`

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [CLI Guide](docs/CLI_GUIDE.md)
- [D-Bus Guide](docs/DBUS_GUIDE.md)
- [FIDO2 Master Key Wrapping](docs/FIDO2_MASTER_KEY.md)
- [Operations](docs/OPERATIONS.md)
- [Secret Rulebook](docs/SECRET_RULEBOOK.md)
- [Documentation Index](docs/INDEX.md)
