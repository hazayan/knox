# Home Operations

This guide describes a practical Knox setup for a small trusted home network:
FreeBSD servers, Artix Linux workstations, and no systemd dependency.

## Server Layout

Recommended default:

- run one Knox server on a trusted LAN host
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

## FreeBSD rc.d

Install the server binary as `/usr/local/bin/knox-server`, write a config file
at `/usr/local/etc/knox/server.yaml`, and copy
[examples/freebsd-knox-server.rc](examples/freebsd-knox-server.rc) to:

```text
/usr/local/etc/rc.d/knox_server
```

Then enable it:

```sh
sysrc knox_server_enable=YES
service knox_server start
service knox_server status
```

## Artix Linux With Dinit

For an Artix server, copy [examples/dinit-knox-server](examples/dinit-knox-server)
to the system service directory used by your installation and start it with:

```sh
dinitctl start knox-server
dinitctl status knox-server
```

For a workstation Secret Service bridge, copy
[examples/dinit-knox-dbus](examples/dinit-knox-dbus) to
`~/.config/dinit.d/knox-dbus`, replace `USER` with your login name, and start it:

```sh
dinitctl --user start knox-dbus
dinitctl --user status knox-dbus
```

If your session does not run a dinit user instance, launch `knox-dbus` from the
desktop session's autostart mechanism instead.

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
