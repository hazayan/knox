# Knox Production Deployment Guide

## 🎯 Overview

This guide covers everything needed to deploy Knox in a production environment with enterprise-grade security, reliability, and performance.

## 📋 Prerequisites

### Required
- Go 1.21+ (for building)
- PostgreSQL 13+ (recommended for production storage)
- TLS certificates (server + client CA for mTLS)
- 32-byte master encryption key (AES-256)

### Optional but Recommended
- AWS KMS or HashiCorp Vault (for master key protection)
- SPIFFE/SPIRE (for workload identity)
- Prometheus (for metrics)
- ELK/Loki stack (for centralized logging)

---

## 🔒 Step 1: Generate Master Encryption Key

### Option A: Direct Master Key (Development/Testing)

```bash
# Generate a random 32-byte key
openssl rand -base64 32 > /etc/knox/master.key
chmod 600 /etc/knox/master.key
chown knox:knox /etc/knox/master.key

# Set environment variable
export KNOX_MASTER_KEY=$(cat /etc/knox/master.key)
```

### Option B: KMS-Protected Key (Production Recommended)

```bash
# Generate master key
MASTER_KEY=$(openssl rand -base64 32)

# Encrypt with AWS KMS
aws kms encrypt \
  --key-id alias/knox-master-key \
  --plaintext "$MASTER_KEY" \
  --query CiphertextBlob \
  --output text > /etc/knox/master.key.encrypted

chmod 600 /etc/knox/master.key.encrypted
chown knox:knox /etc/knox/master.key.encrypted

# Set environment variable
export KNOX_MASTER_KEY_ENCRYPTED=$(cat /etc/knox/master.key.encrypted)
export AWS_REGION=us-east-1
```

**⚠️ CRITICAL**: Never commit the master key to version control!

---

## 🔐 Step 2: Configure TLS Certificates

### Generate Server Certificate

```bash
# Create private key
openssl genrsa -out /etc/knox/tls/server-key.pem 4096

# Create CSR
openssl req -new -key /etc/knox/tls/server-key.pem \
  -out /etc/knox/tls/server.csr \
  -subj "/CN=knox.example.com/O=Example Inc"

# Sign with your CA (or use Let's Encrypt)
openssl x509 -req -in /etc/knox/tls/server.csr \
  -CA /etc/pki/ca.pem \
  -CAkey /etc/pki/ca-key.pem \
  -CAcreateserial \
  -out /etc/knox/tls/server-cert.pem \
  -days 365

# Set permissions
chmod 600 /etc/knox/tls/server-key.pem
chmod 644 /etc/knox/tls/server-cert.pem
```

### Configure Client CA (for mTLS)

```bash
# Copy your client CA certificate
cp /path/to/client-ca.pem /etc/knox/tls/client-ca.pem
chmod 644 /etc/knox/tls/client-ca.pem
```

---

## 📝 Step 3: Configure Knox Server

Create `/etc/knox/server.yaml`:

```yaml
# Server configuration
bind_address: "0.0.0.0:9000"

# Storage backend
storage:
  backend: postgres
  postgres:
    connection_string: "postgresql://knox:PASSWORD@localhost:5432/knox?sslmode=require"
    max_connections: 50

# TLS configuration
tls:
  cert_file: /etc/knox/tls/server-cert.pem
  key_file: /etc/knox/tls/server-key.pem
  client_ca: /etc/knox/tls/client-ca.pem
  min_version: TLS1.3

# Authentication
auth:
  providers:
    - type: mtls
      ca_file: /etc/knox/tls/client-ca.pem
    - type: spiffe
      trust_domain: example.com

# Rate limiting
limits:
  rate_limit_per_principal: 100  # requests per second

# Observability
observability:
  metrics:
    enabled: true
    endpoint: /metrics
  logging:
    level: info
    format: json
  audit:
    enabled: true
    output: /var/log/knox/audit.log
```

---

## 🗄️ Step 4: Initialize PostgreSQL Database

```sql
-- Create database and user
CREATE DATABASE knox;
CREATE USER knox WITH ENCRYPTED PASSWORD 'CHANGE_ME';
GRANT ALL PRIVILEGES ON DATABASE knox TO knox;

-- Connect to knox database
\c knox

-- Grant schema privileges
GRANT ALL ON SCHEMA public TO knox;

-- The tables will be created automatically on first run
```

**Configure connection pooling in PostgreSQL** (`postgresql.conf`):

```ini
max_connections = 200
shared_buffers = 256MB
effective_cache_size = 1GB
```

---

## 🚀 Step 5: Deploy Knox Server

### SystemD Service

Create `/etc/systemd/system/knox-server.service`:

```ini
[Unit]
Description=Knox Secret Management Server
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=knox
Group=knox
WorkingDirectory=/var/lib/knox

# Environment
Environment="KNOX_MASTER_KEY_FILE=/etc/knox/master.key"
Environment="KNOX_METRICS_USERNAME=prometheus"
Environment="KNOX_METRICS_PASSWORD=CHANGE_ME"

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/knox /var/log/knox

# Limits
LimitNOFILE=65536
LimitNPROC=4096

# Execution
ExecStart=/usr/local/bin/knox-server --config /etc/knox/server.yaml
Restart=always
RestartSec=5s

# Health check
ExecStartPost=/bin/sleep 2
ExecStartPost=/usr/bin/curl -f http://localhost:9000/health

[Install]
WantedBy=multi-user.target
```

### Deploy and Start

```bash
# Create user
useradd -r -s /bin/false knox

# Install binary
cp bin/knox-server /usr/local/bin/
chmod 755 /usr/local/bin/knox-server

# Create directories
mkdir -p /var/lib/knox /var/log/knox /etc/knox/tls
chown knox:knox /var/lib/knox /var/log/knox

# Enable and start
systemctl daemon-reload
systemctl enable knox-server
systemctl start knox-server

# Check status
systemctl status knox-server
journalctl -u knox-server -f
```

---

## 🔍 Step 6: Verify Deployment

### Health Checks

```bash
# Health check (no auth required)
curl http://localhost:9000/health
# Expected: "healthy"

# Readiness check
curl http://localhost:9000/ready
# Expected: "ready"

# Metrics (requires basic auth)
curl -u prometheus:PASSWORD http://localhost:9000/metrics
# Expected: Prometheus metrics
```

### Test Authentication

```bash
# Test with client certificate
curl --cert client-cert.pem \
     --key client-key.pem \
     --cacert ca.pem \
     https://knox.example.com:9000/v0/keys/
```

---

## 📊 Step 7: Monitoring and Alerting

### Prometheus Scrape Config

```yaml
scrape_configs:
  - job_name: 'knox'
    scheme: https
    basic_auth:
      username: prometheus
      password: METRICS_PASSWORD
    static_configs:
      - targets: ['knox.example.com:9000']
```

### Key Metrics to Monitor

```promql
# Request rate
rate(knox_requests_total[5m])

# Error rate
rate(knox_requests_total{status=~"5.."}[5m])

# Storage operations
rate(knox_storage_operations_total[5m])

# Authentication failures
rate(knox_auth_failures_total[5m])

# Key access audit
knox_key_access_total
```

### Recommended Alerts

```yaml
groups:
  - name: knox
    rules:
      - alert: KnoxHighErrorRate
        expr: rate(knox_requests_total{status=~"5.."}[5m]) > 0.05
        for: 5m
        annotations:
          summary: "Knox error rate above 5%"
          
      - alert: KnoxStorageDown
        expr: up{job="knox"} == 0
        for: 1m
        annotations:
          summary: "Knox server is down"
          
      - alert: KnoxHighAuthFailures
        expr: rate(knox_auth_failures_total[5m]) > 1
        for: 5m
        annotations:
          summary: "High authentication failure rate"
```

---

## 🔄 Step 8: Key Rotation

### Rotate Master Encryption Key

```bash
# 1. Generate new master key
NEW_KEY=$(openssl rand -base64 32)

# 2. Encrypt with KMS (if using)
aws kms encrypt \
  --key-id alias/knox-master-key \
  --plaintext "$NEW_KEY" \
  --output text \
  --query CiphertextBlob > /etc/knox/master.key.new

# 3. Update Knox configuration to use rotation manager
# (This requires code changes - see pkg/crypto/rotation.go)

# 4. Re-encrypt all keys with new master key
knox-admin reencrypt --config /etc/knox/server.yaml

# 5. Replace old key after verification
mv /etc/knox/master.key.new /etc/knox/master.key.encrypted
systemctl reload knox-server
```

---

## 🔒 Step 9: Security Hardening

### Firewall Rules

```bash
# Allow only necessary ports
iptables -A INPUT -p tcp --dport 9000 -s TRUSTED_NETWORK -j ACCEPT
iptables -A INPUT -p tcp --dport 9000 -j DROP
```

### AppArmor/SELinux

```bash
# Example SELinux policy
semanage fcontext -a -t knox_exec_t "/usr/local/bin/knox-server"
semanage fcontext -a -t knox_data_t "/var/lib/knox(/.*)?"
semanage fcontext -a -t knox_log_t "/var/log/knox(/.*)?"
restorecon -Rv /usr/local/bin/knox-server /var/lib/knox /var/log/knox
```

### File Permissions Checklist

```bash
# Master key: owner read only
-rw------- knox:knox /etc/knox/master.key

# Config: owner read/write, group read
-rw-r----- knox:knox /etc/knox/server.yaml

# TLS private key: owner read only
-rw------- knox:knox /etc/knox/tls/server-key.pem

# TLS certificate: world readable
-rw-r--r-- knox:knox /etc/knox/tls/server-cert.pem

# Storage directory: owner only
drwx------ knox:knox /var/lib/knox

# Log directory: owner read/write
drwx------ knox:knox /var/log/knox
```

---

## 🎛️ Step 10: High Availability Setup

### PostgreSQL Replication

```bash
# Primary server
postgresql.conf:
  wal_level = replica
  max_wal_senders = 5
  archive_mode = on

# Standby server
recovery.conf:
  standby_mode = on
  primary_conninfo = 'host=primary port=5432'
```

### Load Balancing

```nginx
# Nginx configuration
upstream knox_backend {
    least_conn;
    server knox1.example.com:9000 max_fails=3 fail_timeout=30s;
    server knox2.example.com:9000 max_fails=3 fail_timeout=30s;
    server knox3.example.com:9000 max_fails=3 fail_timeout=30s;
}

server {
    listen 443 ssl http2;
    server_name knox.example.com;
    
    ssl_certificate /etc/nginx/ssl/knox.crt;
    ssl_certificate_key /etc/nginx/ssl/knox.key;
    
    location / {
        proxy_pass https://knox_backend;
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate /etc/nginx/ssl/ca.crt;
    }
}
```

---

## 📦 Step 11: Backup and Disaster Recovery

### Database Backup

```bash
# Daily backup script
#!/bin/bash
BACKUP_DIR=/var/backups/knox
DATE=$(date +%Y%m%d_%H%M%S)

pg_dump -h localhost -U knox knox | \
  gzip > $BACKUP_DIR/knox_$DATE.sql.gz

# Keep last 30 days
find $BACKUP_DIR -name "knox_*.sql.gz" -mtime +30 -delete

# Upload to S3
aws s3 cp $BACKUP_DIR/knox_$DATE.sql.gz \
  s3://knox-backups/postgres/
```

### Configuration Backup

```bash
# Backup Knox configuration
tar czf knox-config-$(date +%Y%m%d).tar.gz \
  /etc/knox/ \
  /etc/systemd/system/knox-server.service

# Store securely (encrypted)
gpg --encrypt --recipient admin@example.com \
  knox-config-$(date +%Y%m%d).tar.gz
```

### Recovery Procedure

1. Restore database from backup
2. Deploy Knox binaries
3. Restore configuration files
4. Restore master key (from KMS or backup)
5. Start Knox server
6. Verify health checks
7. Test key access

---

## ✅ Production Readiness Checklist

### Security
- [ ] Master key encrypted with KMS/HSM
- [ ] TLS 1.3 enabled with strong ciphers
- [ ] Client certificate validation configured
- [ ] Authentication providers configured (mTLS/SPIFFE)
- [ ] Rate limiting enabled
- [ ] Metrics endpoint secured with basic auth
- [ ] Audit logging enabled to separate file
- [ ] File permissions locked down
- [ ] Firewall rules configured
- [ ] SELinux/AppArmor policies applied

### Reliability
- [ ] PostgreSQL configured with replication
- [ ] Connection pooling tuned
- [ ] Health checks configured
- [ ] Graceful shutdown tested
- [ ] Automated backups scheduled
- [ ] Disaster recovery procedure documented
- [ ] Load balancer configured (if HA)

### Observability
- [ ] Metrics exposed and scraped by Prometheus
- [ ] Alerts configured for critical conditions
- [ ] Logs centralized to ELK/Loki
- [ ] Audit logs monitored
- [ ] On-call rotation established

### Operations
- [ ] SystemD service configured
- [ ] Automatic restart on failure
- [ ] Log rotation configured
- [ ] Key rotation procedure tested
- [ ] Runbook created for common issues
- [ ] Team trained on operations

---

## 🐛 Troubleshooting

### Server Won't Start

```bash
# Check logs
journalctl -u knox-server -n 100

# Common issues:
# 1. Master key not found
export KNOX_MASTER_KEY=$(cat /etc/knox/master.key)

# 2. PostgreSQL not reachable
psql -h localhost -U knox -d knox

# 3. Port already in use
lsof -i :9000
```

### High Memory Usage

```bash
# Check Go memory stats
curl http://localhost:9000/metrics | grep go_memstats

# Adjust GOMAXPROCS if needed
export GOMAXPROCS=4
```

### Authentication Failures

```bash
# Check certificate validity
openssl x509 -in client-cert.pem -text -noout

# Verify CA trust chain
openssl verify -CAfile ca.pem client-cert.pem

# Check audit logs
tail -f /var/log/knox/audit.log | jq '.event'
```

---

## 📚 Additional Resources

- [Knox Architecture](ARCHITECTURE.md)
- [API Documentation](docs/API.md)
- [Security Best Practices](docs/SECURITY.md)
- [D-Bus Integration Guide](docs/DBUS_GUIDE.md)
- [CLI Reference](docs/CLI_GUIDE.md)

---

## 🆘 Support

For production support:
- GitHub Issues: https://github.com/pinterest/knox/issues
- Security Issues: security@example.com
- Documentation: https://knox.example.com/docs

---

**Last Updated:** October 2025  
**Knox Version:** 2.0.0-dev (Production Ready)
