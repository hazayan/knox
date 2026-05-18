# FIDO2 Master Key Wrapping

Knox already encrypts stored secret versions with an AES-256-GCM envelope
scheme. The next hardening step is to protect the Knox master key at rest with
a local FIDO2 authenticator instead of keeping the plaintext master key in
`/etc/knox/master.key`.

## Model

The storage model stays unchanged:

```text
Knox secret storage
  encrypted by the Knox master key

Knox master key
  encrypted in a local bundle
  wrapping key derived from FIDO2 hmac-secret
```

FIDO2 is a master-key source, not a replacement for the storage backend. The
server still decrypts the master key into process memory during startup, so this
protects at-rest material and restart/unlock paths. It does not protect secrets
from a fully compromised running server process.

Use a separate credential from other services and from Knox FIDO2
authentication on the same physical authenticator. Sharing a physical
authenticator with `kunci-server`, or with a Knox administrator identity, is
acceptable only when each purpose has its own RP ID, credential ID, salt,
metadata file, and backup credential.

This storage-unlock credential is not a Knox principal. Possession of it only
allows the server process to unwrap the master key during startup; it must not
grant API access or global-admin authority.

## Proposed Config

```yaml
master_key:
  backend: "fido2"
  encrypted_key_file: "/var/db/knox/master.key.fido2"
  metadata_file: "/usr/local/etc/knox/fido2-master-key-credential.json"
  device: "auto"
  pin_file: "/var/run/knox/.fido2-master-key.pin"
```

The metadata file is not secret, but it should be root-readable only because it
describes the credential used to unlock the storage. The encrypted key file is
the wrapped Knox master key and must be backed up with the storage.

## Implementation Status

The current implementation includes the encrypted master-key bundle format,
server config selection, admin commands, and a libfido2-backed hardware
provider. Normal builds keep the fake provider available for tests through
`KNOX_FIDO2_FAKE_SECRET_B64`; production builds that need hardware FIDO2
hardware support must be built with:

```sh
go build -tags libfido2 ./cmd/server
```

The build host needs libfido2 headers and pkg-config metadata. On FreeBSD that
means installing the `security/libfido2` package before building the port.

## Commands

All sensitive state changes are explicit:

```sh
knox-server key fido2-enroll \
  --metadata-file /usr/local/etc/knox/fido2-master-key-credential.json \
  --rp-id identity-primary-knox \
  --rp-name "Identity Primary Knox" \
  --derive-info "knox master key fido2 v1" \
  --fido2-device auto \
  --fido2-pin-file /var/run/knox/.fido2-master-key.pin

knox-server key init \
  --backend fido2 \
  --encrypted-key-file /var/db/knox/master.key.fido2 \
  --fido2-metadata-file /usr/local/etc/knox/fido2-master-key-credential.json \
  --fido2-device auto \
  --fido2-pin-file /var/run/knox/.fido2-master-key.pin

knox-server key migrate \
  --backend fido2 \
  --master-key-file /etc/knox/master.key \
  --encrypted-key-file /var/db/knox/master.key.fido2 \
  --fido2-metadata-file /usr/local/etc/knox/fido2-master-key-credential.json \
  --fido2-device auto \
  --fido2-pin-file /var/run/knox/.fido2-master-key.pin

knox-server key unlock-test \
  --backend fido2 \
  --encrypted-key-file /var/db/knox/master.key.fido2 \
  --fido2-metadata-file /usr/local/etc/knox/fido2-master-key-credential.json \
  --fido2-device auto \
  --fido2-pin-file /var/run/knox/.fido2-master-key.pin
```

Normal server startup must not silently enroll, initialize, migrate, or rewrite
key material.

## Backup

FIDO2 at rest needs backup from day one. Losing or resetting the authenticator
without a backup path makes the Knox storage unrecoverable.

The backup artifact should contain the wrapped master key and enough non-secret
metadata to restore it onto another Knox host. It should be encrypted with a
distinct backup FIDO2 credential when possible:

```sh
knox-server key backup \
  --backend fido2 \
  --encrypted-key-file /var/db/knox/master.key.fido2 \
  --fido2-metadata-file /usr/local/etc/knox/fido2-master-key-credential.json \
  --backup-fido2-metadata-file /usr/local/etc/knox/fido2-master-key-backup-credential.json \
  --fido2-device auto \
  --fido2-pin-file /var/run/knox/.fido2-master-key.pin \
  --output knox-master-key.knox-backup

knox-server key restore \
  --input knox-master-key.knox-backup \
  --encrypted-key-file /var/db/knox/master.key.fido2 \
  --fido2-metadata-file /usr/local/etc/knox/fido2-master-key-credential.json \
  --backup-fido2-metadata-file /usr/local/etc/knox/fido2-master-key-backup-credential.json \
  --fido2-device auto \
  --fido2-pin-file /var/run/knox/.fido2-master-key.pin
```

Storage backup still needs the selected storage backend data, for example
`/var/db/knox/keys` for filesystem storage or `/var/db/knox/knox.db` for
SQLite. A restore drill must prove both parts together: restored storage plus
restored/unwrapped master key.

## Kha Boundary

Kha should configure Knox and wire services/build jobs to read secrets from
Knox. Kha should not implement a second generic secret encryption system for
the same host-local secret problem.
