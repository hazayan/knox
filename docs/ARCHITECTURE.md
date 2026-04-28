# Knox Architecture

## Scope

This fork is scoped as a home-network secret manager. It should be simple enough
to run on a FreeBSD host, usable from Artix Linux workstations and laptops, and
recoverable without specialized infrastructure.

The design priority is:

1. Correct secret storage and retrieval
2. Clear master-key and backup handling
3. Small, auditable operational surface
4. CLI usability for scripts and daily administration
5. Optional Linux desktop integration through FreeDesktop Secret Service

Enterprise features such as high availability, Kubernetes automation, cloud KMS,
and compliance reporting are not part of the main maturity target.

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

## Recommended Home Deployment

```text
FreeBSD or Linux server
  /usr/local/bin/knox-server
  /etc/knox/server.yaml
  /etc/knox/master.key
  /var/lib/knox/keys

Artix workstation/laptop
  /usr/local/bin/knox
  ~/.config/knox/config.yaml
  optional /usr/local/bin/knox-dbus
```

For the first sturdy home-network release, prefer filesystem storage unless
PostgreSQL is already part of the local environment. etcd is not recommended for
the home profile because it adds operational complexity that does not help the
single-server use case.

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

Storage backends should not receive plaintext secret data in the production
server path. The current stabilization work must keep one canonical server route
path so tests and real deployments exercise the same encryption and ACL logic.

## Storage

The storage abstraction lives under `pkg/storage`.

Supported packages in the tree:

- `memory`: tests and ephemeral development
- `filesystem`: recommended first home-network backend
- `postgres`: optional if a local PostgreSQL server is already maintained
- `etcd`: advanced/experimental for this fork's scope

Backend behavior must be made consistent before the project can be considered
sturdy. In particular, create/update semantics should be identical across
backends, and backend conformance tests should cover key creation, replacement,
deletion, listing, and atomic update behavior.

## Encryption

Knox uses AES-256-GCM envelope encryption. Each secret version is encrypted with
a data encryption key, and that key is encrypted with the master key.

Master key sources:

1. `KNOX_MASTER_KEY`
2. `KNOX_MASTER_KEY_FILE`
3. `/etc/knox/master.key`

The home-network target should document and test:

- generating a master key
- file permission checks
- server restart behavior
- backup and restore
- rotation without data loss

The TLA+ specs under `spec/tla` describe intended safety properties. They verify
models, not the Go implementation. Any formal-verification claim must stay in
sync with code and tests.

## Authentication

The home profile should prefer a small set of boring authentication options:

- token-based auth for humans and scripts
- mTLS for machines where host identity matters

SPIFFE and GitHub auth may remain available, but they are not core to the home
network use case and should not drive the default setup.

## Authorization

Knox keys use ACLs with these access levels:

- `Read`: retrieve secret versions
- `Write`: add/rotate versions
- `Admin`: modify ACLs and delete keys

ACL behavior belongs in the key manager and server route handlers. Any direct
storage route that bypasses this path is test-only at best and should not be
part of the production router.

## Observability

For home use, useful observability is:

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

For Artix Linux, the operational examples should use dinit or desktop session
startup mechanisms instead of systemd.

## Stabilization Milestones

1. Documentation truth pass
2. `go test ./...` green
3. One canonical server route path
4. Backend conformance tests and storage semantics cleanup
5. Master-key and rotation safety fixes
6. CLI workflow alignment
7. FreeBSD rc.d and Artix dinit examples
8. D-Bus verification with `secret-tool`

## Definition Of Sturdy

Knox is sturdy enough for the target use case when this workflow is tested:

1. Start `knox-server` on FreeBSD or Linux with filesystem storage.
2. Connect from an Artix workstation using the CLI.
3. Create, read, rotate, list, and delete a secret.
4. Restart the server and verify secrets persist.
5. Back up storage plus master key.
6. Restore on another host and read secrets.
7. Run `knox-dbus` without systemd.
8. Store and retrieve a secret with `secret-tool`.
9. Run the full Go test suite successfully.
