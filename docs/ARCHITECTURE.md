# Knox Architecture: Enhanced Implementation

## Overview

This document describes the enhanced Knox architecture with three major additions:
1. Production-ready server implementation
2. Production-ready CLI client
3. FreeDesktop Secret Service D-Bus bridge

## Project Structure

```
knox/
├── client/                # Client CLI commands (existing)
├── server/                # Server core logic (existing)
│   ├── api.go
│   ├── auth/
│   ├── keydb/
│   └── ...
├── cmd/
│   ├── client/            # CLI client
│   ├── server/            # Server
│   └── dbus/              # FreeDesktop Secret Service bridge
├── pkg/
│   ├── config/            # Configuration management
│   ├── storage/           # Storage backend abstraction
│   │   ├── memory/
│   │   ├── filesystem/
│   │   ├── postgres/
│   │   └── etcd/
│   ├── observability/     # Metrics, logging, tracing
│   │   ├── metrics/
│   │   └── logging/
│   ├── dbus/              # D-Bus Secret Service implementation
│   │   ├── service.go     # Service interface
│   │   ├── collection.go  # Collection interface
│   │   ├── item.go        # Item interface
│   │   └── session.go     # Session interface
│   └── client/            # NEW: Enhanced client library
├── knox.go                # Core types (existing)
├── client.go              # Client library (existing)
└── docs/                  # NEW: Documentation
```

## Component Design

### 1. Production Server (cmd/knox-server)

**Features:**
- Multi-backend storage support (filesystem, PostgreSQL, etcd)
- High availability with leader election
- Prometheus metrics endpoint
- Structured JSON logging
- Health check endpoints (/health, /ready)
- Graceful shutdown
- TLS with certificate rotation support
- Rate limiting per principal
- Audit logging to separate stream

**Configuration:**
```yaml
server:
  bind_address: "0.0.0.0:9000"
  tls:
    cert_file: "/etc/knox/tls/server.crt"
    key_file: "/etc/knox/tls/server.key"
    client_ca: "/etc/knox/tls/ca.crt"

storage:
  backend: "postgres"  # memory, filesystem, postgres, etcd
  postgres:
    connection_string: "postgresql://knox:password@localhost/knox"
    max_connections: 100

auth:
  providers:
    - type: "spiffe"
      trust_domain: "example.com"
    - type: "mtls"
      ca_file: "/etc/knox/ca.crt"

observability:
  metrics:
    enabled: true
    endpoint: "/metrics"
  logging:
    level: "info"
    format: "json"
  audit:
    enabled: true
    output: "/var/log/knox/audit.log"

limits:
  rate_limit_per_principal: 100  # requests per second
  max_key_size: "1MB"
  max_keys_per_list: 1000
```

### 2. Production CLI Client (cmd/knox)

**Features:**
- Unified command interface (replacing dev_client)
- Configuration file support (~/.knox/config.yaml)
- Multiple profile support (dev, staging, prod)
- Interactive mode for sensitive operations
- Shell completion (bash, zsh, fish)
- JSON output mode for scripting
- Key version awareness and caching
- Offline mode with cached keys

**Command structure:**
```
knox
├── server        # Server management
│   ├── info      # Get server info
│   └── health    # Check server health
├── key           # Key operations
│   ├── create    # Create a new key
│   ├── get       # Get key value
│   ├── list      # List keys
│   ├── delete    # Delete a key
│   ├── rotate    # Rotate key (add version)
│   └── versions  # List key versions
├── acl           # ACL operations
│   ├── get       # Get key ACL
│   ├── add       # Add ACL entry
│   └── remove    # Remove ACL entry
├── config        # Configuration management
│   ├── init      # Initialize config
│   ├── profile   # Manage profiles
│   └── show      # Show current config
└── auth          # Authentication
    ├── login     # Authenticate user
    └── logout    # Clear credentials
```

**Configuration (~/.knox/config.yaml):**
```yaml
current_profile: "production"

profiles:
  development:
    server: "localhost:9000"
    tls:
      ca_cert: "/etc/knox/ca.crt"
      client_cert: "/etc/knox/dev-client.crt"
      client_key: "/etc/knox/dev-client.key"
    cache:
      enabled: true
      directory: "~/.knox/cache/dev"

  production:
    server: "knox.example.com:9000"
    tls:
      ca_cert: "/etc/knox/prod/ca.crt"
      client_cert: "/etc/knox/prod/client.crt"
      client_key: "/etc/knox/prod/client.key"
    cache:
      enabled: true
      directory: "~/.knox/cache/prod"
```

### 3. FreeDesktop Secret Service Bridge (cmd/knox-dbus)

**Architecture:**
```
┌─────────────────────────────────────────────┐
│         Desktop Applications                │
│  (Firefox, Chrome, SSH, Git, etc.)          │
└─────────────────┬───────────────────────────┘
                  │ D-Bus
                  │ (org.freedesktop.secrets)
┌─────────────────▼───────────────────────────┐
│         knox-dbus Bridge                    │
│  - Implements Secret Service API            │
│  - Session management & encryption          │
│  - Maps Collections ↔ Knox namespaces       │
│  - Maps Items ↔ Knox secrets                │
└─────────────────┬───────────────────────────┘
                  │ HTTPS
                  │ (Knox API)
┌─────────────────▼───────────────────────────┐
│         Knox Server                         │
│  - Stores secrets                           │
│  - Enforces ACLs                            │
│  - Audit logging                            │
└─────────────────────────────────────────────┘
```

**D-Bus Interfaces to Implement:**

1. **org.freedesktop.Secret.Service**
   - `/org/freedesktop/secrets`
   - Methods: OpenSession, CreateCollection, SearchItems, Unlock, Lock, GetSecrets
   - Properties: Collections

2. **org.freedesktop.Secret.Collection**
   - `/org/freedesktop/secrets/collection/<name>`
   - Methods: Delete, SearchItems, CreateItem
   - Properties: Items, Label, Locked, Created, Modified

3. **org.freedesktop.Secret.Item**
   - `/org/freedesktop/secrets/collection/<name>/<id>`
   - Methods: Delete, GetSecret, SetSecret
   - Properties: Locked, Attributes, Label, Created, Modified

4. **org.freedesktop.Secret.Session**
   - Methods: Close
   - Handles encryption negotiation

**Mapping Strategy:**

| FreeDesktop Concept | Knox Mapping |
|---------------------|--------------|
| Collection | Key namespace (e.g., `dbus:collection_name:*`) |
| Item | Individual Knox key (e.g., `dbus:collection_name:item_id`) |
| Item Attributes | Stored in Knox key metadata (new field) |
| Item Label | Stored in Knox key metadata (new field) |
| Locked state | Mapped to Knox ACL (user must authenticate) |
| Session encryption | Handled by D-Bus layer before sending to Knox |

**Configuration (/etc/knox/dbus-bridge.yaml):**
```yaml
dbus:
  bus_type: "session"  # or "system"
  service_name: "org.freedesktop.secrets"

knox:
  server: "localhost:9000"
  tls:
    ca_cert: "/etc/knox/ca.crt"
    client_cert: "/etc/knox/dbus-client.crt"
    client_key: "/etc/knox/dbus-client.key"
  namespace_prefix: "dbus"  # All keys prefixed with "dbus:"

encryption:
  algorithms:
    - "plain"       # No encryption (if Knox handles it)
    - "dh-ietf1024-sha256-aes128-cbc-pkcs7"  # Standard D-Bus encryption
```

## Storage Backend Abstraction

**Interface:**
```go
package storage

type Backend interface {
    // Key operations
    GetKey(ctx context.Context, keyID string) (*knox.Key, error)
    PutKey(ctx context.Context, key *knox.Key) error
    DeleteKey(ctx context.Context, keyID string) error
    ListKeys(ctx context.Context, prefix string) ([]string, error)

    // Transaction support
    BeginTx(ctx context.Context) (Transaction, error)

    // Health check
    Ping(ctx context.Context) error
}

type Transaction interface {
    GetKey(ctx context.Context, keyID string) (*knox.Key, error)
    PutKey(ctx context.Context, key *knox.Key) error
    DeleteKey(ctx context.Context, keyID string) error
    Commit() error
    Rollback() error
}
```

**Implementations:**
1. **Memory** - For testing and development
2. **Filesystem** - Compatible with existing Knox file cache
3. **PostgreSQL** - Production database backend
4. **etcd** - Distributed coordination and storage

## Observability

**Metrics (Prometheus):**
- `knox_requests_total{method, path, status}` - Request counts
- `knox_request_duration_seconds{method, path}` - Request latency
- `knox_keys_total` - Total number of keys
- `knox_storage_operations_total{backend, operation, status}` - Storage ops
- `knox_auth_attempts_total{provider, status}` - Auth attempts

**Logging (structured JSON):**
```json
{
  "timestamp": "2025-10-17T11:00:00Z",
  "level": "info",
  "msg": "key accessed",
  "key_id": "service:api_key",
  "principal": "user@example.com",
  "principal_type": "User",
  "access_type": "Read",
  "request_id": "abc123",
  "duration_ms": 15
}
```

**Audit Log:**
```json
{
  "timestamp": "2025-10-17T11:00:00Z",
  "event": "key.access",
  "key_id": "service:api_key",
  "principal": {"id": "user@example.com", "type": "User"},
  "action": "Read",
  "result": "success",
  "metadata": {
    "version_id": 42,
    "client_ip": "192.168.1.100",
    "user_agent": "knox-cli/2.0"
  }
}
```

## Security Enhancements

1. **Rate Limiting**: Per-principal rate limiting to prevent abuse
2. **Input Validation**: Strict validation of all inputs (key IDs, ACLs, etc.)
3. **Audit Trail**: All operations logged for compliance
4. **Encryption at Rest**: Storage backend encryption support
5. **TLS Everywhere**: All communication encrypted
6. **Principle of Least Privilege**: Minimal default permissions

## Deployment Models

### Single Server
- Suitable for small deployments
- Filesystem or PostgreSQL backend
- Simple to operate

### High Availability
- Multiple Knox servers behind load balancer
- Shared PostgreSQL or etcd backend
- Leader election for maintenance tasks
- Horizontal scaling for read operations

### Desktop Integration
- knox-dbus runs as user service (systemd user unit)
- Connects to local or remote Knox server
- Provides transparent secret management for desktop apps

## Implementation Phases

### Phase 1: Foundation (Week 1-2)
- [ ] Storage backend abstraction
- [ ] Configuration management
- [ ] Observability infrastructure
- [ ] Enhanced server with multi-backend support

### Phase 2: CLI Client (Week 3)
- [ ] Unified CLI command structure
- [ ] Configuration file support
- [ ] Profile management
- [ ] Enhanced UX (colors, progress bars, etc.)

### Phase 3: D-Bus Bridge (Week 4-5)
- [ ] D-Bus interface implementation
- [ ] Knox API client integration
- [ ] Session and encryption handling
- [ ] Collection/Item mapping

### Phase 4: Testing & Documentation (Week 6)
- [ ] Integration tests
- [ ] Performance benchmarks
- [ ] User documentation
- [ ] Operator documentation

## Dependencies

**New dependencies needed:**
```
github.com/godbus/dbus/v5              # D-Bus implementation
github.com/prometheus/client_golang    # Metrics
github.com/sirupsen/logrus             # Structured logging
github.com/spf13/cobra                 # CLI framework
github.com/spf13/viper                 # Configuration
github.com/lib/pq                      # PostgreSQL driver
go.etcd.io/etcd/client/v3             # etcd client
github.com/stretchr/testify           # Testing utilities
```

## Success Metrics

1. **Server**: Can handle 10k+ requests/sec with <10ms p99 latency
2. **CLI**: All operations complete in <100ms for cached keys
3. **D-Bus**: Transparent compatibility with GNOME Keyring/KWallet clients
4. **Storage**: Support at least 100k keys per server
5. **HA**: Zero downtime during server restarts with shared backend

## Future Considerations

- Kubernetes operator for automated deployment
- Secrets rotation automation (integrating with external systems)
- Knox plugin system for custom auth providers
- Web UI for key management
- Integration with cloud KMS (AWS KMS, Google Cloud KMS, Azure Key Vault)
