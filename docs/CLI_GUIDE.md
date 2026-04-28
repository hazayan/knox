# Knox CLI Guide

## Overview

The Knox CLI (`knox`) is the main interface for administering a home-network
Knox server. It currently exposes these command groups:

- `key`: create, get, list, delete, rotate, and inspect versions
- `acl`: get, add, and remove ACL entries
- `config`: initialize, show, generate, and manage profiles
- `version`: print CLI version information
- `completion`: generate shell completion

Status: alpha. The CLI is usable, but legacy client/cache behavior still needs
cleanup before it should be considered stable.

## Build

```bash
go build -o bin/knox ./cmd/client
```

Install it somewhere on `PATH` when ready:

```bash
install -m 0755 bin/knox /usr/local/bin/knox
```

## Configuration

Initialize a default config:

```bash
knox config init --server knox.home.arpa:9000
```

Knox follows the XDG config path, usually:

```text
~/.config/knox/config.yaml
```

Show the active config:

```bash
knox config show
knox config show --json
```

Manage profiles:

```bash
knox config profile add laptop --server knox.home.arpa:9000
knox config profile list
knox config profile use laptop
knox --profile laptop key list
```

## Key Management

Create a key:

```bash
knox key create home:api_key --data "secret123"
echo "secret123" | knox key create home:api_key
knox key create home:api_key --data-file secret.txt
```

Create with ACL entries:

```bash
knox key create home:api_key --data "secret123" \
  --acl "User:alice:Read" \
  --acl "Machine:freebsd-server:Write"
```

Read a key:

```bash
knox key get home:api_key
knox key get home:api_key --json
```

List keys:

```bash
knox key list
knox key list home:
knox key list --json
```

Rotate a key:

```bash
knox key rotate home:api_key --data "newsecret456"
echo "newsecret456" | knox key rotate home:api_key
knox key versions home:api_key
```

Delete a key:

```bash
knox key delete home:api_key
knox key delete home:api_key --force
```

## ACL Management

View ACLs:

```bash
knox acl get home:api_key
knox acl get home:api_key --json
```

Add access:

```bash
knox acl add home:api_key User:alice:Read
knox acl add home:api_key Machine:freebsd-server:Write
knox acl add home:api_key User:admin:Admin
```

Remove access:

```bash
knox acl remove home:api_key User:alice
```

ACL format:

```text
TYPE:PRINCIPAL:ACCESS
```

Types:

- `User`
- `UserGroup`
- `Machine`
- `MachinePrefix`
- `Service`
- `ServicePrefix`

Access levels:

- `Read`
- `Write`
- `Admin`

## Authentication

Supported client auth paths are still being consolidated. Current code supports
environment or token-file based auth in the client layer, and TLS fields in the
profile config.

Environment example:

```bash
export KNOX_USER_AUTH="token-value"
knox key list
```

Token file example:

```bash
install -d -m 0700 ~/.config/knox
printf '%s\n' "token-value" > ~/.config/knox/token
chmod 0600 ~/.config/knox/token
```

mTLS profile fields:

```bash
knox config profile add secure \
  --server knox.home.arpa:9000 \
  --ca-cert /etc/knox/ca.crt \
  --client-cert /etc/knox/client.crt \
  --client-key /etc/knox/client.key
```

## JSON Output

Use `--json` for scripting:

```bash
knox key get home:api_key --json
knox key list --json
knox acl get home:api_key --json
```

## Shell Completion

```bash
knox completion bash
knox completion zsh
knox completion fish
```

## Current Gaps

- `server health/info` commands are documented as desired but not implemented.
- `auth login/logout` commands are documented as desired but not implemented.
- Legacy `knox register` cache behavior still exists in the client library but
  is not exposed by the current Cobra CLI.
- Cache path and token-file behavior need a single XDG-compatible design.

## See Also

- [Architecture](ARCHITECTURE.md)
- [D-Bus Guide](DBUS_GUIDE.md)
