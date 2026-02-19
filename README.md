# Knox - Secret Management System
Knox started as a fork of [pinterest/knox](https://github.com/pinterest/knox) and has been refactored and improved to fit a narrower and more focused use-case: personal secret management service with a bridge to the freedesktop.org's secret service interface, that can also stretch to cater to small professional outfit.

## The Problem Knox Solves
Knox provides a comprehensive solution with reasonable security features.

## Key Features

### 🔒 Security First
- **AES-256-GCM Encryption**: All secrets encrypted at rest with envelope encryption
- **mTLS Authentication**: Mutual TLS for machine-to-machine authentication
- **SPIFFE Support**: Service identity verification with SPIFFE standards
- **Fine-grained ACLs**: Per-secret access control with Read/Write/Admin permissions
- **Comprehensive Audit Logging**: All operations logged for compliance
- **Input Validation**: Strict validation of all inputs to prevent injection attacks
- **Security Headers**: HTTP security headers to prevent common web vulnerabilities

### 🚀 Production Ready
- **Multiple Storage Backends**: PostgreSQL, filesystem, and in-memory storage
- **High Availability**: Support for distributed deployments with shared storage
- **Prometheus Metrics**: Built-in metrics for monitoring and alerting
- **Health Checks**: /health and /ready endpoints for orchestration
- **Structured Logging**: JSON and text logging with configurable levels
- **Rate Limiting**: Configurable rate limiting per principal

### 🖥️ Desktop Integration
- **FreeDesktop Secret Service**: Native integration with Linux desktop applications
- **Transparent Usage**: Works with Firefox, Chrome, SSH, Git, and other D-Bus clients
- **Secure Bridge**: D-Bus to Knox bridge with session encryption

### 🔧 Developer Experience
- **Modern CLI**: Intuitive command-line interface with shell completion
- **Multi-profile Support**: Separate configurations for dev/staging/prod environments
- **JSON Output**: Machine-readable output for scripting and automation
- **Smart Caching**: Configurable client-side caching with TTL

## Quick Start

### Prerequisites
- Go 1.21 or later
- PostgreSQL (optional, for production storage)

### Installation

```bash
# Clone the repository
git clone https://github.com/hazayan/knox.git
cd knox

# Build all components
go build -o bin/knox ./cmd/client
go build -o bin/knox-server ./cmd/server
go build -o bin/knox-dbus ./cmd/dbus

# Install to PATH (optional)
sudo cp bin/knox /usr/local/bin/knox
sudo cp bin/knox-server /usr/local/bin/knox-server
cp bin/knox-dbus ~/.local/bin/knox-dbus
```

### Running the Server

```bash
# Start with memory backend (development)
knox-server --bind-address localhost:9000

# Start with PostgreSQL backend (production)
knox-server --bind-address localhost:9000 \
  --storage-backend postgres \
  --postgres-connection-string "postgresql://user:password@localhost/knox"
```

### Using the CLI

```bash
# Initialize configuration
knox-client config init --server localhost:9000

# Create your first secret
echo "super-secret-password" | knox key create myapp:database_password

# Retrieve the secret
knox-client key get myapp:database_password

# List all keys
knox-client key list

# Manage access control
knox-client acl add myapp:database_password User:alice@example.com:Read
```

### Desktop Integration

```bash
# Start D-Bus bridge (for desktop app integration)
knox-dbus --config ~/.config/knox/dbus.yaml

# Firefox, Chrome, SSH, and other applications will now use Knox for secret storage
```

## Architecture Overview

### Project Structure

```
knox/
├── cmd/
│   ├── client/            # Production CLI client
│   ├── server/            # Production HTTP server
│   └── dbus/              # FreeDesktop Secret Service bridge
├── pkg/
│   ├── auth/              # Authentication providers (mTLS, SPIFFE)
│   ├── crypto/            # Cryptographic operations (AES-256-GCM)
│   ├── storage/           # Storage backends (PostgreSQL, filesystem, memory)
│   ├── config/            # Configuration management
│   ├── observability/     # Metrics and logging
│   └── dbus/              # D-Bus protocol implementation
├── server/                # Core server logic and API routes
├── client/                # Client library implementation
└── docs/                  # Comprehensive documentation
```

### Security Features

- **Encryption at Rest**: All secrets encrypted with AES-256-GCM using envelope encryption
- **Authentication**: Multiple providers including mTLS, SPIFFE, and token-based auth
- **Authorization**: Fine-grained ACLs with Read/Write/Admin permissions per principal
- **Audit Logging**: Comprehensive logging of all operations for compliance
- **Input Validation**: Strict validation of all inputs to prevent injection attacks
- **Rate Limiting**: Configurable rate limiting per principal to prevent abuse

### Storage Backends

- **PostgreSQL**: Production-ready with transaction support and high availability
- **Filesystem**: Simple file-based storage for development and testing
- **Memory**: In-memory storage for testing and ephemeral deployments

## Configuration

### Server Configuration

Create `server.yaml`:
```yaml
bind_address: "0.0.0.0:9000"
tls:
  cert_file: "/etc/knox/tls/server.crt"
  key_file: "/etc/knox/tls/server.key"
  client_ca: "/etc/knox/tls/ca.crt"

storage:
  backend: "postgres"
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
```

### Client Configuration

Initialize with:
```bash
knox config init --server knox.example.com:9000 \
  --ca-cert /etc/knox/ca.crt \
  --client-cert /etc/knox/client.crt \
  --client-key /etc/knox/client.key
```

## Documentation

### Quick Navigation
- **[Documentation Index](docs/INDEX.md)** - Complete navigation guide for all documentation

### Essential Guides
- [CLI Guide](docs/CLI_GUIDE.md) - Complete command reference
- [D-Bus Integration](docs/DBUS_GUIDE.md) - Desktop application integration
- [Production Guide](docs/PRODUCTION_GUIDE.md) - Deployment and operations
- [Architecture](docs/ARCHITECTURE.md) - System design and components

