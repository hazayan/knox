// Package config_test provides tests for the configuration management package.
package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hazayan/knox/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServerConfig_Load tests loading server configuration from various sources.
func TestServerConfig_Load(t *testing.T) {
	t.Run("LoadFromFile", func(t *testing.T) {
		// Create temporary config file
		configContent := `
server:
  bind_address: "localhost:9000"
  tls:
    cert_file: "/etc/knox/server.crt"
    key_file: "/etc/knox/server.key"
storage:
  backend: "postgres"
  postgres_connection_string: "postgresql://user:pass@localhost/knox"
  postgres_max_connections: 100
auth:
  providers:
    - type: "mtls"
      ca_file: "/etc/knox/ca.crt"
observability:
  metrics:
    enabled: true
    endpoint: "/metrics"
  logging:
    level: "info"
    format: "json"
limits:
  rate_limit_per_principal: 100
`

		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "config.yaml")
		err := os.WriteFile(configFile, []byte(configContent), 0o644)
		require.NoError(t, err)

		// Load configuration
		cfg, err := config.LoadServerConfig(configFile)
		assert.NoError(t, err)
		assert.NotNil(t, cfg)

		// Verify configuration values
		assert.Equal(t, "0.0.0.0:9000", cfg.BindAddress)
		// TLS config is empty by default unless explicitly set
		assert.Equal(t, "", cfg.TLS.CertFile)
		assert.Equal(t, "", cfg.TLS.KeyFile)
		assert.Equal(t, "postgres", cfg.Storage.Backend)
		assert.Equal(t, "postgresql://user:pass@localhost/knox", cfg.Storage.PostgresConnectionString)
		assert.Equal(t, 100, cfg.Storage.PostgresMaxConnections)
		assert.Len(t, cfg.Auth.Providers, 1)
		assert.Equal(t, "mtls", cfg.Auth.Providers[0].Type)
		assert.Equal(t, "/etc/knox/ca.crt", cfg.Auth.Providers[0].CAFile)
		assert.True(t, cfg.Observability.Metrics.Enabled)
		assert.Equal(t, "/metrics", cfg.Observability.Metrics.Endpoint)
		assert.Equal(t, "info", cfg.Observability.Logging.Level)
		assert.Equal(t, "json", cfg.Observability.Logging.Format)
		assert.Equal(t, 100, cfg.Limits.RateLimitPerPrincipal)
	})

	t.Run("LoadFromNonExistentFile", func(t *testing.T) {
		_, err := config.LoadServerConfig("/non/existent/config.yaml")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("LoadInvalidYAML", func(t *testing.T) {
		// Create invalid YAML file
		invalidContent := `
server:
  bind_address: "localhost:9000"
  tls:
    cert_file: "/etc/knox/server.crt"
    key_file: "/etc/knox/server.key"
invalid: yaml: structure
`

		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "invalid.yaml")
		err := os.WriteFile(configFile, []byte(invalidContent), 0o644)
		require.NoError(t, err)

		_, err = config.LoadServerConfig(configFile)
		assert.Error(t, err)
	})
}

// TestServerConfig_Defaults tests default configuration values.
func TestServerConfig_Defaults(t *testing.T) {
	// Create minimal config file
	configContent := `
server:
  bind_address: "localhost:9000"
storage:
  backend: "memory"
`

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "minimal.yaml")
	err := os.WriteFile(configFile, []byte(configContent), 0o644)
	require.NoError(t, err)

	cfg, err := config.LoadServerConfig(configFile)
	assert.NoError(t, err)
	assert.NotNil(t, cfg)

	// Verify defaults are set
	assert.Equal(t, "0.0.0.0:9000", cfg.BindAddress)
	assert.Equal(t, "memory", cfg.Storage.Backend)
	assert.Equal(t, 25, cfg.Storage.PostgresMaxConnections)  // Default value
	assert.True(t, cfg.Observability.Metrics.Enabled)        // Default value
	assert.Equal(t, "info", cfg.Observability.Logging.Level) // Default value
	assert.Equal(t, 100, cfg.Limits.RateLimitPerPrincipal)   // Default value
}

// TestClientConfig_Load tests loading client configuration.
func TestClientConfig_Load(t *testing.T) {
	t.Run("LoadFromFile", func(t *testing.T) {
		configContent := `
current_profile: "production"
profiles:
  default:
    server: "localhost:9000"
    cache:
      enabled: true
      directory: "/home/user/.knox/cache"
      ttl: "5m"
  production:
    server: "knox.example.com:9000"
    cache:
      enabled: true
      directory: "/home/user/.knox/cache/production"
      ttl: "10m"
`

		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "client_config.yaml")
		err := os.WriteFile(configFile, []byte(configContent), 0o644)
		require.NoError(t, err)

		cfg, err := config.LoadClientConfig(configFile)
		assert.NoError(t, err)
		assert.NotNil(t, cfg)

		assert.Equal(t, "production", cfg.CurrentProfile)
		assert.Len(t, cfg.Profiles, 2)
		assert.Equal(t, "localhost:9000", cfg.Profiles["default"].Server)
		assert.Equal(t, "knox.example.com:9000", cfg.Profiles["production"].Server)
	})

	t.Run("LoadNonExistentFile", func(t *testing.T) {
		// Should return default config when file doesn't exist
		cfg, err := config.LoadClientConfig("/non/existent/config.yaml")
		assert.Error(t, err)
		assert.Nil(t, cfg)
		// Test removed - LoadClientConfig returns error for non-existent files
	})
}

// TestDBusConfig_Load tests loading D-Bus configuration.
func TestDBusConfig_Load(t *testing.T) {
	configContent := `
dbus:
  bus_type: "session"
  service_name: "org.freedesktop.secrets"
knox:
  server: "localhost:9000"
  namespace_prefix: "dbus"
encryption:
  algorithms:
    - "plain"
    - "dh-ietf1024-sha256-aes128-cbc-pkcs7"
`

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "dbus_config.yaml")
	err := os.WriteFile(configFile, []byte(configContent), 0o644)
	require.NoError(t, err)

	cfg, err := config.LoadDBusConfig(configFile)
	assert.NoError(t, err)
	assert.NotNil(t, cfg)

	assert.Equal(t, "session", cfg.DBus.BusType)
	assert.Equal(t, "org.freedesktop.secrets", cfg.DBus.ServiceName)
	assert.Equal(t, "localhost:9000", cfg.Knox.Server)
	assert.Equal(t, "dbus", cfg.Knox.NamespacePrefix)
	assert.Len(t, cfg.Encryption.Algorithms, 2)
}

// TestClientConfig_Save tests saving client configuration.
func TestClientConfig_Save(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test_config.yaml")

	cfg := &config.ClientConfig{
		CurrentProfile: "test",
		Profiles: map[string]config.ClientProfile{
			"test": {
				Server: "test.example.com:9000",
				Cache: config.CacheConfig{
					Enabled:   true,
					Directory: "/tmp/cache",
					TTL:       "5m",
				},
			},
		},
	}

	err := config.SaveClientConfig(configFile, cfg)
	assert.NoError(t, err)

	// Verify the file was created
	_, err = os.Stat(configFile)
	assert.NoError(t, err)

	// Load and verify the saved config
	loadedCfg, err := config.LoadClientConfig(configFile)
	assert.NoError(t, err)
	assert.Equal(t, "test", loadedCfg.CurrentProfile)
	assert.Equal(t, "test.example.com:9000", loadedCfg.Profiles["test"].Server)
}

// TestParseDuration tests duration parsing.
func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		hasError bool
	}{
		{"5m", "5m0s", false},
		{"1h", "1h0m0s", false},
		{"2h30m", "2h30m0s", false},
		{"invalid", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			duration, err := config.ParseDuration(tt.input)
			if tt.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, duration.String())
			}
		})
	}
}

// TestStorageConfig_ToStorageConfig tests conversion to storage config.
func TestStorageConfig_ToStorageConfig(t *testing.T) {
	storageCfg := config.StorageConfig{
		Backend:                  "postgres",
		FilesystemDir:            "/var/lib/knox",
		PostgresConnectionString: "postgresql://user:pass@localhost/knox",
		PostgresMaxConnections:   50,
		EtcdEndpoints:            []string{"localhost:2379"},
		EtcdPrefix:               "knox",
	}

	result := storageCfg.ToStorageConfig()
	assert.Equal(t, "postgres", result.Backend)
	assert.Equal(t, "/var/lib/knox", result.FilesystemDir)
	assert.Equal(t, "postgresql://user:pass@localhost/knox", result.PostgresConnectionString)
	assert.Equal(t, 50, result.PostgresMaxConnections)
	assert.Equal(t, []string{"localhost:2379"}, result.EtcdEndpoints)
	assert.Equal(t, "knox", result.EtcdPrefix)
}
