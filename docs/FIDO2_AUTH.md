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

Registration is intentionally an administrative flow. The first production
version should support offline/imported credential records before exposing
self-service registration.

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
    token_signing_key_file: "/usr/local/etc/knox/fido2-token.key"
    credentials_file: "/usr/local/etc/knox/fido2-principals.json"
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
registration flow will later produce these records directly.

## Validation Plan

The first milestone uses an interface-backed ceremony service and fake tests so
server routing, token minting, token validation, and CLI storage can be tested
without hardware. Hardware validation comes after a FIDO2 authenticator is
visible to the host running the tests.
