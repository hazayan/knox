# Personal Operations

This guide describes a practical Knox setup for personal Unix systems without
assuming a specific distribution, init system, or desktop session.

## Server Layout

Recommended default:

- run one Knox server in a private environment
- bind to a private address or loopback behind a local reverse proxy
- use the filesystem backend first, then Postgres if multi-host access becomes
  necessary
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
2. Archive `/var/db/knox/`.
3. Archive the server config and master-key file, if a file-based key is used.
4. Store the archive somewhere offline or on another trusted machine.
5. Start `knox-server`.

Restore should be tested before relying on Knox for daily secrets:

1. Stop a test Knox server.
2. Restore the storage directory and key material into a temporary location.
3. Start the server against the restored config.
4. Confirm `knox key list` and `knox key get <known-key>` work.

## Health Checks

The server exposes unauthenticated operational endpoints:

```text
/health
/ready
```

Use these for local supervision checks only. They should not replace exercising
real key create/get/rotate operations during backup or upgrade testing.
