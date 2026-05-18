# FIDO2 Authentication

Knox FIDO2 authentication is a WebAuthn ceremony that mints a short-lived Knox
API token. It is separate from FIDO2-backed master-key storage: master-key
storage unlocks the server database, while FIDO2 authentication proves an
operator or machine identity to the API.

## Model

The server owns four responsibilities:

1. Store registered WebAuthn credentials and their mapped Knox principal.
2. Issue login challenges and persist short-lived session data.
3. Validate login assertions through a WebAuthn relying-party implementation.
4. Mint and verify short-lived Knox bearer tokens.

This identity credential is not the storage-unlock credential. It must not be
used to derive the Knox master-key wrapping key. Root/admin bootstrap should use
the initialization token to enroll the first administrator credential, then
normal administration should use the FIDO2 login path.

Normal Knox API routes do not run WebAuthn. They only validate the minted token
through the regular auth-provider interface. This keeps secret operations simple
and makes the ceremony replaceable without changing the core API.

## Routes

The FIDO2 routes are public authentication routes and must not be wrapped by the
normal Knox API authentication middleware.

- `POST /v0/auth/fido2/login/begin`
  - input: principal kind and ID, or a future discoverable-login hint
  - output: WebAuthn credential assertion options and an opaque session ID

- `POST /v0/auth/fido2/login/finish`
  - input: session ID and WebAuthn assertion response
  - output: short-lived Knox token, expiry, and authenticated principal

Registration is an administrative flow and is wrapped by the normal Knox API
authentication middleware:

- `POST /v0/auth/fido2/credentials/begin`
  - input: principal kind, subject, optional display name, and optional groups
  - output: WebAuthn credential creation options and an opaque session ID

- `POST /v0/auth/fido2/credentials/finish`
  - input: session ID and WebAuthn credential creation response
  - output: the persisted credential ID and mapped principal

- `POST /v0/auth/fido2/credentials/import`
  - input: principal metadata and one serialized `go-webauthn` credential record
  - output: the persisted credential ID and mapped principal

The CLI exposes the same administrative flow under:

```sh
knox auth fido2 register begin --principal-type user --subject alice
knox auth fido2 register finish --session-id "$SESSION" --credential-file credential.json
knox auth fido2 import --principal-type user --subject alice --credential-file credential-record.json
```

## Token

The token is an HMAC-SHA256 signed envelope:

- `version`
- `issuer`
- `subject`
- `principal_type`
- `groups`
- `issued_at`
- `expires_at`

The signing key is loaded from a configured file and must contain at least 32
bytes of random material. Token verification rejects malformed signatures,
expired tokens, unsupported versions, and unsupported principal types.

## Configuration

```yaml
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
```

Credential imports use a JSON array of principals:

```json
[
  {
    "principal_type": "user",
    "subject": "alice",
    "display_name": "Alice",
    "groups": ["operators"],
    "user_handle": "base64url-user-handle",
    "credentials": []
  }
]
```

The `credentials` values are serialized `go-webauthn` credential records. The
registration and import flows update this file durably with owner-only file
permissions.

## Validation Plan

Normal tests cover server routing, token minting, token validation, credential
registration/import persistence, and CLI storage without hardware. The opt-in
hardware drill is gated behind the `fido2hardware libfido2` build tags.
