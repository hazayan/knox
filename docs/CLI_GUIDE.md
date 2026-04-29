# Knox CLI Guide

## Overview

The Knox CLI (`knox`) is the main interface for administering a Knox server. It
currently exposes these command groups:

- `key`: create, get, list, delete, rotate, and inspect versions
- `acl`: get, add, and remove ACL entries
- `auth`: store, inspect, and remove the local token file
- `server`: check health, readiness, and local profile information
- `config`: initialize, show, generate, and manage profiles
- `version`: print CLI version information
- `completion`: generate shell completion

Status: usable for the documented server workflows. Legacy client/register cache
code still exists for compatibility but is not the primary CLI path.

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
knox config init --server 127.0.0.1:9000
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
knox config profile add workstation --server 127.0.0.1:9000
knox config profile list
knox config profile use workstation
knox --profile workstation key list
```

## Key Management

Create a key:

```bash
knox key create app:api_key --data "secret123"
echo "secret123" | knox key create app:api_key
knox key create app:api_key --data-file secret.txt
```

Create with ACL entries:

```bash
knox key create app:api_key --data "secret123" \
  --acl "User:alice:Read" \
  --acl "Machine:node-01:Write"
```

Read a key:

```bash
knox key get app:api_key
knox key get app:api_key --json
```

List keys:

```bash
knox key list
knox key list app:
knox key list --json
```

Rotate a key:

```bash
knox key rotate app:api_key --data "newsecret456"
echo "newsecret456" | knox key rotate app:api_key
knox key versions app:api_key
```

Delete a key:

```bash
knox key delete app:api_key
knox key delete app:api_key --force
```

## ACL Management

View ACLs:

```bash
knox acl get app:api_key
knox acl get app:api_key --json
```

Add access:

```bash
knox acl add app:api_key User:alice:Read
knox acl add app:api_key Machine:node-01:Write
knox acl add app:api_key User:admin:Admin
```

Remove access:

```bash
knox acl remove app:api_key User:alice
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

## Server Status

Check operational endpoints from the active profile:

```bash
knox server health
knox server ready
knox server info
knox server info --json
```

Profiles with explicit `http://` or `https://` server URLs use that scheme.
Profiles without a scheme use HTTPS when TLS files are configured and HTTP
otherwise.

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
knox auth login token-value
printf '%s\n' "token-value" | knox auth login
knox auth status
knox auth logout
```

The token file is read from the XDG config directory and must not be readable by
group or other users. `knox auth login` creates the file with owner-only
permissions. Trailing whitespace is ignored.

mTLS profile fields:

```bash
knox config profile add secure \
  --server 127.0.0.1:9000 \
  --ca-cert /etc/knox/ca.crt \
  --client-cert /etc/knox/client.crt \
  --client-key /etc/knox/client.key
```

## JSON Output

Use `--json` for scripting:

```bash
knox key get app:api_key --json
knox key list --json
knox acl get app:api_key --json
```

## Shell Completion

```bash
knox completion bash
knox completion zsh
knox completion fish
```

## Current Gaps

- Legacy `knox register` cache behavior still exists in the client library but
  is not exposed by the current Cobra CLI.

## See Also

- [Architecture](ARCHITECTURE.md)
- [D-Bus Guide](DBUS_GUIDE.md)
