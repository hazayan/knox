# Operations

This guide describes a practical Knox setup for Unix systems without assuming a
specific distribution, init system, or desktop session.

## Server Layout

Recommended default:

- run one Knox server in a trusted environment
- bind to loopback or an address appropriate for the deployment
- use the filesystem backend first, or SQLite if a single database file is
  preferable
- use FIDO2-wrapped master-key storage for hardened hosts, or keep legacy
  plaintext master keys outside the repository and outside regular shell
  history
- back up both the storage directory and the master key material

Example filesystem paths:

```text
/usr/local/etc/knox/server.yaml
/var/db/knox/
/var/log/knox/
```

## System Service

Install the server binary as `/usr/local/bin/knox-server`, write a config file
at `/usr/local/etc/knox/server.yaml`, and adapt one of the service templates
under [examples](examples) for the target host.

Generic templates are provided for the server and D-Bus bridge:

- [service-manager-knox-server.conf](examples/service-manager-knox-server.conf)
- [service-manager-knox-dbus.conf](examples/service-manager-knox-dbus.conf)

Then enable and start it with the host's service manager:

```sh
service knox-server start
service knox-server status
```

## User Service

For a workstation Secret Service bridge, adapt a user-service template or launch
`knox-dbus` from the desktop session's autostart mechanism.

```sh
service-manager --user start knox-dbus
service-manager --user status knox-dbus
```

Exact user-service commands vary by service manager.

## Backup And Restore

Backups are only useful if they include the encrypted storage and the master key
material needed to decrypt it.

For FIDO2-backed master-key mode, backup must include:

- the Knox storage backend data,
- the encrypted master-key bundle,
- the non-secret FIDO2 metadata for the restore target,
- a tested encrypted backup artifact for the master key.

Use a distinct FIDO2 credential for backup artifacts where possible. Sharing the
same physical authenticator with other trust services is acceptable, but Knox
should use its own credential and metadata. See
[FIDO2 Master Key Wrapping](FIDO2_MASTER_KEY.md).

For the filesystem backend:

1. Stop `knox-server`.
2. Archive the storage directory, for example `/var/db/knox/`.
3. Archive the server config and master-key file, if a file-based key is used.
4. Record the Knox binary version used by the service.
5. Store the archive somewhere offline or on another trusted machine.
6. Start `knox-server`.

Restore should be tested before relying on Knox for daily secrets:

1. Stop a test Knox server.
2. Restore the storage directory and key material into a temporary location.
3. Start the server against the restored config.
4. Confirm `knox key list` includes a known key.
5. Confirm `knox key get <known-key>` returns the expected secret.
6. Rotate or add a version to the known key and read it back.

The Go integration tests exercise the same shape of restore for the filesystem
backend: storage directory copy, master-key file copy, fresh server startup,
list/get, and post-restore version add.

For FIDO2-backed master keys, the restore drill must also exercise the hardware
unlock path before and after restoring the encrypted master-key backup artifact.
The operational drill on 2026-05-19 validated copied filesystem storage,
FIDO2 unlock-test, FIDO2 backup and restore, isolated server startup, key list,
drill-only key read, rotation, restart, and post-restart readback.

## Cluster Peer Unlock

Knox can use FIDO2 for cold start while allowing rolling maintenance restarts
from another already-unlocked Knox peer. This is a cluster-scoped operation, not
a generic remote unlock path.

Cold-start rule:

- if every Knox peer is down, at least one peer must be unlocked locally with
  the FIDO2 master-key path
- once one peer is unlocked and serving, another configured peer may restart and
  request a single-use peer unlock response from it

Server configuration shape:

```yaml
master_key:
  backend: fido2
  encrypted_key_file: /var/db/knox/master.key.fido2
  metadata_file: /usr/local/etc/knox/fido2-master-key-credential.json
  pin_file: /var/run/knox/.fido2-master-key.pin

peer_unlock:
  enabled: true
  node_id: node-a
  shared_key_file: /usr/local/etc/knox/peer-unlock.key
  ttl: 2m
  peers:
    - id: node-b
      url: https://node-b.example.net:9000
```

The shared key file must be a regular non-symlink file, mode `0600`, and contain
at least 32 bytes. It may contain raw bytes or a base64-encoded value. Treat it
as sensitive machine-local cluster material.

Peer unlock behavior:

- local FIDO2 unlock is attempted first
- if local unlock fails and `peer_unlock.enabled` is true, Knox asks configured
  peers for `/v0/cluster/peer-unlock`
- the request is HMAC-authenticated with the shared key and bound to the
  requester ID, timestamp, and nonce
- the response wraps the master key with AES-GCM, expires quickly, and the
  responder rejects replayed request nonces

Operationally, restart peers one at a time. Keep at least one unlocked Knox peer
online until the restarted peer is healthy.

## Health Checks

The server exposes unauthenticated operational endpoints:

```text
/health
/ready
```

Use these for supervision checks only. They should not replace exercising real
key create/get/rotate operations during backup or upgrade testing.

`/health` is a liveness check for the server process. `/ready` checks whether
the configured storage backend is reachable and should be used before sending
real key traffic.
