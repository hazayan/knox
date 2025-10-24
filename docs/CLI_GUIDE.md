# Knox CLI Guide

## Overview

The Knox CLI (`knox`) is a production-ready command-line interface for managing secrets, keys, and passwords in Knox.

## Installation

```bash
# Build the CLI
cd /home/karpal/devel/system/knox
go build -o bin/knox ./cmd/knox

# Optional: Install to your PATH
sudo cp bin/knox /usr/local/bin/
```

## Quick Start

### 1. Initialize Configuration

```bash
# Create default configuration
knox config init

# With custom server
knox config init --server knox.example.com:9000

# With TLS certificates
knox config init --server knox.example.com:9000 \
  --ca-cert /path/to/ca.crt \
  --client-cert /path/to/client.crt \
  --client-key /path/to/client.key
```

This creates `~/.knox/config.yaml` with a default profile.

### 2. View Configuration

```bash
# Show current configuration
knox config show

# Output in JSON
knox config show --json
```

### 3. Manage Profiles

```bash
# Add a new profile
knox config profile add production --server knox.prod.example.com:9000

# List all profiles
knox config profile list

# Switch profiles
knox config profile use production

# Use a profile for a single command
knox --profile production key list
```

## Key Management

### Create a Key

```bash
# Create with inline data
knox key create myapp:api_key --data "secret123"

# Create from stdin
echo "secret123" | knox key create myapp:api_key

# Create from file
knox key create myapp:api_key --data-file secret.txt

# Create with ACL
knox key create myapp:api_key --data "secret123" \
  --acl "User:alice@example.com:Read" \
  --acl "Service:spiffe://example.com/myapp:Write"
```

### Get a Key

```bash
# Get primary version
knox key get myapp:api_key

# Get all active versions
knox key get myapp:api_key --all

# Get specific status
knox key get myapp:api_key --status Active

# JSON output
knox key get myapp:api_key --json
```

### List Keys

```bash
# List all keys
knox key list

# List with prefix filter
knox key list myapp:

# JSON output
knox key list --json
```

### Rotate a Key

```bash
# Add a new version
knox key rotate myapp:api_key --data "newsecret456"

# From stdin
echo "newsecret456" | knox key rotate myapp:api_key

# List versions
knox key versions myapp:api_key
```

### Delete a Key

```bash
# Delete with confirmation
knox key delete myapp:api_key

# Force delete (no confirmation)
knox key delete myapp:api_key --force
```

## ACL Management

### View ACL

```bash
# Get key's ACL
knox acl get myapp:api_key

# JSON output
knox acl get myapp:api_key --json
```

### Add ACL Entry

```bash
# Grant read access to a user
knox acl add myapp:api_key User:alice@example.com:Read

# Grant write access to a service
knox acl add myapp:api_key Service:spiffe://example.com/myapp:Write

# Grant admin access to a user group
knox acl add myapp:api_key UserGroup:developers:Admin
```

**ACL Format:** `TYPE:PRINCIPAL:ACCESS`

**Types:**
- `User` - Individual user
- `UserGroup` - Group of users
- `Machine` - Specific machine
- `MachinePrefix` - Machine prefix match
- `Service` - SPIFFE service ID
- `ServicePrefix` - SPIFFE service prefix

**Access Levels:**
- `Read` - Can read key data
- `Write` - Can add versions and rotate
- `Admin` - Can modify ACL and delete

### Remove ACL Entry

```bash
# Remove access
knox acl remove myapp:api_key User:alice@example.com
```

## Configuration Management

### Profiles

```bash
# Add a profile
knox config profile add staging --server knox.staging.example.com:9000

# Remove a profile
knox config profile remove staging

# Use a profile
knox config profile use staging

# List profiles
knox config profile list
```

### Configuration File

Default location: `~/.knox/config.yaml`

Example:
```yaml
current_profile: production

profiles:
  default:
    server: localhost:9000
    cache:
      enabled: true
      directory: /home/user/.knox/cache
      ttl: 5m
    tls:
      ca_cert: ""
      client_cert: ""
      client_key: ""
  
  production:
    server: knox.example.com:9000
    cache:
      enabled: true
      directory: /home/user/.knox/cache/production
      ttl: 5m
    tls:
      ca_cert: /etc/knox/ca.crt
      client_cert: /etc/knox/client.crt
      client_key: /etc/knox/client.key
```

## Authentication

Knox CLI supports multiple authentication methods:

### 1. Environment Variables

```bash
# User authentication
export KNOX_USER_AUTH="your-token-here"
knox key get myapp:api_key

# Machine authentication
export KNOX_MACHINE_AUTH="machine-token-here"
knox key get myapp:api_key
```

### 2. Token File

Store your token in `~/.knox/token`:
```bash
echo "your-token-here" > ~/.knox/token
chmod 600 ~/.knox/token
```

### 3. mTLS (Mutual TLS)

Configure client certificates in your profile:
```bash
knox config profile add secure \
  --server knox.example.com:9000 \
  --ca-cert /etc/knox/ca.crt \
  --client-cert /etc/knox/client.crt \
  --client-key /etc/knox/client.key
```

## Shell Completion

Generate shell completion for better UX:

### Bash

```bash
# Load for current session
source <(knox completion bash)

# Install permanently
knox completion bash > /etc/bash_completion.d/knox
```

### Zsh

```zsh
# Enable completion
echo "autoload -U compinit; compinit" >> ~/.zshrc

# Install
knox completion zsh > "${fpath[1]}/_knox"
```

### Fish

```fish
# Load for current session
knox completion fish | source

# Install permanently
knox completion fish > ~/.config/fish/completions/knox.fish
```

## Advanced Usage

### JSON Output Mode

Use `--json` flag for machine-readable output:

```bash
# Get key in JSON
knox key get myapp:api_key --json

# List keys in JSON
knox key list --json

# Parse with jq
knox key get myapp:api_key --json | jq -r '.VersionList[0].Data' | base64 -d
```

### Profile Override

Override profile for single command:

```bash
# Use production profile for one command
knox --profile production key list

# Use custom config file
knox --config /path/to/config.yaml key list
```

### Scripting Examples

```bash
#!/bin/bash

# Rotate all keys with prefix
for key in $(knox key list myapp: --json | jq -r '.keys[]'); do
  echo "Rotating $key..."
  NEW_SECRET=$(openssl rand -base64 32)
  echo "$NEW_SECRET" | knox key rotate "$key"
done

# Export all keys as JSON
knox key list --json | jq -r '.keys[]' | while read key; do
  knox key get "$key" --json > "backup/${key//\//_}.json"
done

# Backup ACLs
knox key list --json | jq -r '.keys[]' | while read key; do
  knox acl get "$key" --json > "acl-backup/${key//\//_}.json"
done
```

## Troubleshooting

### Config File Not Found

```bash
# Initialize config first
knox config init
```

### Authentication Errors

```bash
# Check your auth token
echo $KNOX_USER_AUTH

# Or check token file
cat ~/.knox/token

# Verify server connectivity
curl -k https://localhost:9000/health
```

### TLS Certificate Errors

```bash
# Verify certificates exist
ls -la /etc/knox/*.crt /etc/knox/*.key

# Test TLS connection
openssl s_client -connect knox.example.com:9000 \
  -CAfile /etc/knox/ca.crt \
  -cert /etc/knox/client.crt \
  -key /etc/knox/client.key
```

### Cache Issues

```bash
# Clear cache
rm -rf ~/.knox/cache/*

# Disable cache temporarily
# Edit ~/.knox/config.yaml and set cache.enabled to false
```

## Examples

### Complete Workflow

```bash
# 1. Initialize
knox config init --server localhost:9000

# 2. Create a key
knox key create myapp:database_password --data "super-secret-pw"

# 3. Grant access to service
knox acl add myapp:database_password Service:spiffe://example.com/myapp:Read

# 4. Retrieve the key
knox key get myapp:database_password

# 5. Rotate the key
knox key rotate myapp:database_password --data "new-super-secret-pw"

# 6. List versions
knox key versions myapp:database_password

# 7. View ACL
knox acl get myapp:database_password
```

### Multi-Environment Setup

```bash
# Set up multiple environments
knox config init --server localhost:9000
knox config profile add staging --server knox.staging.example.com:9000
knox config profile add production --server knox.prod.example.com:9000

# Use different profiles
knox --profile staging key list
knox --profile production key list

# Switch default
knox config profile use production
knox key list  # Uses production
```

## Tips

1. **Use shell completion** - It makes the CLI much easier to use
2. **Leverage profiles** - Set up separate profiles for different environments
3. **Enable caching** - Reduces latency for frequently accessed keys
4. **Use JSON output** - Makes scripting and automation easier
5. **Store tokens securely** - Use `~/.knox/token` with proper permissions (600)
6. **Prefix your keys** - Use namespaces like `myapp:` for organization

## See Also

- [Architecture Document](../ARCHITECTURE.md)
- [Server Configuration](SERVER_GUIDE.md) (TODO)
- [D-Bus Bridge Guide](DBUS_GUIDE.md) (TODO)
- [Knox API Documentation](https://github.com/hazayan/knox/wiki)
