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

Use a separate credential from other services on the same physical
authenticator. Sharing the TrustKey device with `kunci-server` is acceptable,
but Knox should use its own RP ID, credential ID, salt, metadata file, and
backup credential.

## Proposed Config

```yaml
master_key:
  backend: "fido2"
  encrypted_key_file: "/var/db/knox/master.key.fido2"
  metadata_file: "/usr/local/etc/knox/fido2-credential.json"
  device: "auto"
  pin_file: "/run/knox/fido2.pin"
```

The metadata file is not secret, but it should be root-readable only because it
describes the credential used to unlock the storage. The encrypted key file is
the wrapped Knox master key and must be backed up with the storage.

## Implementation Status

The current implementation includes the encrypted master-key bundle format,
server config selection, admin commands, and tests for FIDO2-style wrapping. The
hardware provider is still a boundary: tests use `KNOX_FIDO2_FAKE_SECRET_B64`
to supply the hmac-secret output. Production use still needs the libfido2-backed
provider that talks to the TrustKey device and records the real credential ID at
enrollment.

## Commands

All sensitive state changes are explicit:

```sh
knox-server key fido2-enroll \
  --metadata-file /usr/local/etc/knox/fido2-credential.json \
  --rp-id ishum-knox \
  --rp-name "ishum Knox" \
  --derive-info "knox master key fido2 v1"

knox-server key init \
  --backend fido2 \
  --encrypted-key-file /var/db/knox/master.key.fido2 \
  --fido2-metadata-file /usr/local/etc/knox/fido2-credential.json

knox-server key migrate \
  --backend fido2 \
  --master-key-file /etc/knox/master.key \
  --encrypted-key-file /var/db/knox/master.key.fido2 \
  --fido2-metadata-file /usr/local/etc/knox/fido2-credential.json

knox-server key unlock-test \
  --backend fido2 \
  --encrypted-key-file /var/db/knox/master.key.fido2 \
  --fido2-metadata-file /usr/local/etc/knox/fido2-credential.json
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
  --fido2-metadata-file /usr/local/etc/knox/fido2-credential.json \
  --backup-fido2-metadata-file /usr/local/etc/knox/backup-fido2-credential.json \
  --output knox-master-key.knox-backup

knox-server key restore \
  --input knox-master-key.knox-backup \
  --encrypted-key-file /var/db/knox/master.key.fido2 \
  --fido2-metadata-file /usr/local/etc/knox/fido2-credential.json \
  --backup-fido2-metadata-file /usr/local/etc/knox/backup-fido2-credential.json
```

Storage backup still needs the selected storage backend data, for example
`/var/db/knox/keys` for filesystem storage or `/var/db/knox/knox.db` for
SQLite. A restore drill must prove both parts together: restored storage plus
restored/unwrapped master key.

## Kha Boundary

Kha should configure Knox and wire services/build jobs to read secrets from
Knox. Kha should not implement a second generic secret encryption system for
the same host-local secret problem.
