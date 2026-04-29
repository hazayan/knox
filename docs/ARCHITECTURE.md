# Knox Architecture

## Scope

This fork is scoped as a small self-hosted Unix secret manager. It should be
simple enough to run on ordinary servers, workstations, and laptops, and
recoverable without specialized services.

The design priority is:

1. Correct secret storage and retrieval
2. Clear master-key and backup handling
3. Small, auditable operational surface
4. CLI usability for scripts and daily administration
5. Optional desktop integration through FreeDesktop Secret Service

## Runtime Components

```text
knox-server
  HTTP API
  authentication middleware
  ACL enforcement
  key manager
  encryption layer
  storage backend

knox
  CLI for key, ACL, and config workflows

knox-dbus
  FreeDesktop Secret Service bridge
  maps D-Bus collections/items to Knox keys
```

## Recommended Deployment

```text
Unix server or workstation
  /usr/local/bin/knox-server
  /etc/knox/server.yaml
  /etc/knox/master.key
  /var/lib/knox/keys

Unix workstation or laptop
  /usr/local/bin/knox
  ~/.config/knox/config.yaml
  optional /usr/local/bin/knox-dbus
```

For a simple deployment, prefer filesystem storage. SQLite is available
through the ORM backend when a single database file is preferable. etcd is not
recommended for the default profile because it adds operational complexity that
does not help a simple single-server use case.

## Data Flow

```text
client or knox-dbus
  -> Knox HTTP API
  -> auth middleware identifies principal
  -> route handler validates request
  -> key manager checks ACLs
  -> crypto layer encrypts/decrypts versions
  -> storage adapter persists encrypted DBKey payload
```

Storage backends should not receive plaintext secret data in the server path.
The router keeps one canonical key API path so tests and real deployments
exercise the same encryption and ACL logic.

## Storage

The storage abstraction lives under `pkg/storage`.

Supported packages in the tree:

- `memory`: tests and ephemeral development
- `filesystem`: recommended first default backend
- `sqlite`: ORM-backed single-file SQL storage
- `etcd`: advanced backend for deployments that already operate etcd

Backend behavior is covered by shared storage tests for key creation,
replacement, deletion, listing, and atomic update behavior.

## Encryption

Knox uses AES-256-GCM envelope encryption. Each secret version is encrypted with
a data encryption key, and that key is encrypted with the master key.

Master key sources:

1. `KNOX_MASTER_KEY`
2. `KNOX_MASTER_KEY_FILE`
3. `/etc/knox/master.key`

The default operational path should document and test:

- generating a master key
- file permission checks
- server restart behavior
- backup and restore
- rotation without data loss

The TLA+ specs under `spec/tla` describe intended safety properties. They verify
models, not the Go implementation. Any formal-verification claim must stay in
sync with code and tests.

## Authentication

The default profile should prefer a small set of boring authentication options:

- token-based auth for humans and scripts
- mTLS for machines where host identity matters

SPIFFE and GitHub auth may remain available, but they are not core to the
default use case and should not drive the default setup.

## Authorization

Knox keys use ACLs with these access levels:

- `Read`: retrieve secret versions
- `Write`: add/rotate versions
- `Admin`: modify ACLs and delete keys

ACL behavior belongs in the key manager and server route handlers. Storage
backends are persistence implementations, not alternate API surfaces.

## Observability

Useful observability is:

- clear structured logs
- health and readiness endpoints
- audit records for key and ACL operations
- metrics where they do not complicate setup

Audit logs must never include secret values.

## D-Bus Bridge

`knox-dbus` maps FreeDesktop Secret Service concepts to Knox:

| D-Bus Concept | Knox Mapping |
|---------------|--------------|
| Collection | Key namespace prefix |
| Item | Individual Knox key |
| Item attributes | Metadata packed with stored secret data |
| Item label | Metadata packed with stored secret data |
| Session | D-Bus-side encryption/session object |

Operational examples should cover common Unix service-manager and desktop
session startup patterns without making any one init system a requirement.

## Stabilization State

Completed:

- Documentation truth pass
- `go test ./...` green
- One canonical server route path
- Backend conformance tests and storage semantics cleanup
- Master-key and rotation safety fixes
- CLI workflow alignment
- Generic Unix service-manager examples

Remaining manual verification:

- D-Bus verification with `secret-tool` and real Secret Service clients

## Definition Of Sturdy

Knox is sturdy enough for the target use case when this workflow is tested:

1. Start `knox-server` on a Unix system with filesystem storage.
2. Connect from another Unix workstation using the CLI.
3. Create, read, rotate, list, and delete a secret.
4. Restart the server and verify secrets persist.
5. Back up storage plus master key.
6. Restore on another host and read secrets.
7. Run `knox-dbus` from a user service or session startup entry.
8. Store and retrieve a secret with `secret-tool`.
9. Run the full Go test suite successfully.
