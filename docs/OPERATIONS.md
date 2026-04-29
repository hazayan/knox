# Operations

This guide describes a practical Knox setup for Unix systems without assuming a
specific distribution, init system, or desktop session.

## Server Layout

Recommended default:

- run one Knox server in a trusted environment
- bind to loopback or an address appropriate for the deployment
- use the filesystem backend first, or SQLite if a single database file is
  preferable
- keep the master key outside the repository and outside regular shell history
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
