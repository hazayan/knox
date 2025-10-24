// Package config provides configuration management for Knox.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hazayan/knox/pkg/storage"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

// ServerConfig holds configuration for the Knox server.
type ServerConfig struct {
	BindAddress   string              `mapstructure:"bind_address"`
	TLS           TLSConfig           `mapstructure:"tls"`
	Storage       StorageConfig       `mapstructure:"storage"`
	Auth          AuthConfig          `mapstructure:"auth"`
	Observability ObservabilityConfig `mapstructure:"observability"`
	Limits        LimitsConfig        `mapstructure:"limits"`
}

// TLSConfig holds TLS configuration.
type TLSConfig struct {
	CertFile   string `mapstructure:"cert_file"`
	KeyFile    string `mapstructure:"key_file"`
	ClientCA   string `mapstructure:"client_ca"`
	MinVersion string `mapstructure:"min_version"` // TLS1.2, TLS1.3
}

// StorageConfig holds storage backend configuration.
type StorageConfig struct {
	Backend string `mapstructure:"backend"` // memory, filesystem, postgres, etcd

	// Filesystem backend
	FilesystemDir string `mapstructure:"filesystem_dir"`

	// PostgreSQL backend
	PostgresConnectionString string `mapstructure:"postgres_connection_string"`
	PostgresMaxConnections   int    `mapstructure:"postgres_max_connections"`

	// etcd backend
	EtcdEndpoints []string `mapstructure:"etcd_endpoints"`
	EtcdPrefix    string   `mapstructure:"etcd_prefix"`
}

// ToStorageConfig converts to storage.Config.
func (c StorageConfig) ToStorageConfig() storage.Config {
	return storage.Config{
		Backend:                  c.Backend,
		FilesystemDir:            c.FilesystemDir,
		PostgresConnectionString: c.PostgresConnectionString,
		PostgresMaxConnections:   c.PostgresMaxConnections,
		EtcdEndpoints:            c.EtcdEndpoints,
		EtcdPrefix:               c.EtcdPrefix,
	}
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	Providers []AuthProviderConfig `mapstructure:"providers"`
}

// AuthProviderConfig holds configuration for a single auth provider.
type AuthProviderConfig struct {
	Type        string `mapstructure:"type"` // spiffe, mtls, token
	TrustDomain string `mapstructure:"trust_domain"`
	CAFile      string `mapstructure:"ca_file"`
}

// ObservabilityConfig holds observability configuration.
type ObservabilityConfig struct {
	Metrics MetricsConfig `mapstructure:"metrics"`
	Logging LoggingConfig `mapstructure:"logging"`
	Audit   AuditConfig   `mapstructure:"audit"`
}

// MetricsConfig holds metrics configuration.
type MetricsConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Endpoint string `mapstructure:"endpoint"`
}

// LoggingConfig holds logging configuration.
type LoggingConfig struct {
	Level  string `mapstructure:"level"`  // debug, info, warn, error
	Format string `mapstructure:"format"` // text, json
}

// AuditConfig holds audit logging configuration.
type AuditConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Output  string `mapstructure:"output"` // file path or "stdout"
}

// LimitsConfig holds rate limiting and size limits.
type LimitsConfig struct {
	RateLimitPerPrincipal int    `mapstructure:"rate_limit_per_principal"`
	MaxKeySize            string `mapstructure:"max_key_size"`
	MaxKeysPerList        int    `mapstructure:"max_keys_per_list"`
}

// ClientConfig holds configuration for the Knox CLI client.
type ClientConfig struct {
	CurrentProfile string                   `mapstructure:"current_profile" json:"current_profile" yaml:"current_profile"`
	Profiles       map[string]ClientProfile `mapstructure:"profiles" json:"profiles" yaml:"profiles"`
}

// ClientProfile represents a client connection profile.
type ClientProfile struct {
	Server string          `mapstructure:"server" json:"server" yaml:"server"`
	TLS    ClientTLSConfig `mapstructure:"tls" json:"tls" yaml:"tls"`
	Cache  CacheConfig     `mapstructure:"cache" json:"cache" yaml:"cache"`
}

// ClientTLSConfig holds client TLS configuration.
type ClientTLSConfig struct {
	CACert     string `mapstructure:"ca_cert" json:"ca_cert" yaml:"ca_cert"`
	ClientCert string `mapstructure:"client_cert" json:"client_cert" yaml:"client_cert"`
	ClientKey  string `mapstructure:"client_key" json:"client_key" yaml:"client_key"`
}

// CacheConfig holds cache configuration.
type CacheConfig struct {
	Enabled   bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	Directory string `mapstructure:"directory" json:"directory" yaml:"directory"`
	TTL       string `mapstructure:"ttl" json:"ttl" yaml:"ttl"`
}

// DBusConfig holds configuration for the D-Bus bridge.
type DBusConfig struct {
	DBus       DBusConnectionConfig `mapstructure:"dbus"`
	Knox       DBusKnoxConfig       `mapstructure:"knox"`
	Encryption EncryptionConfig     `mapstructure:"encryption"`
}

// DBusConnectionConfig holds D-Bus connection configuration.
type DBusConnectionConfig struct {
	BusType     string `mapstructure:"bus_type"`     // session, system
	ServiceName string `mapstructure:"service_name"` // org.freedesktop.secrets
}

// DBusKnoxConfig holds Knox server configuration for the D-Bus bridge.
type DBusKnoxConfig struct {
	Server          string          `mapstructure:"server"`
	TLS             ClientTLSConfig `mapstructure:"tls"`
	NamespacePrefix string          `mapstructure:"namespace_prefix"`
}

// EncryptionConfig holds D-Bus encryption configuration.
type EncryptionConfig struct {
	Algorithms []string `mapstructure:"algorithms"`
}

// LoadServerConfig loads server configuration from a file.
func LoadServerConfig(path string) (*ServerConfig, error) {
	v := viper.New()
	v.SetConfigFile(path)

	// Set defaults
	v.SetDefault("bind_address", "0.0.0.0:9000")
	v.SetDefault("storage.backend", "filesystem")
	v.SetDefault("storage.filesystem_dir", "/var/lib/knox/keys")
	v.SetDefault("storage.postgres_max_connections", 25)
	v.SetDefault("observability.metrics.enabled", true)
	v.SetDefault("observability.metrics.endpoint", "/metrics")
	v.SetDefault("observability.logging.level", "info")
	v.SetDefault("observability.logging.format", "json")
	v.SetDefault("observability.audit.enabled", true)
	v.SetDefault("observability.audit.output", "/var/log/knox/audit.log")
	v.SetDefault("limits.rate_limit_per_principal", 100)
	v.SetDefault("limits.max_key_size", "1MB")
	v.SetDefault("limits.max_keys_per_list", 1000)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg ServerConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

// LoadClientConfig loads client configuration from a file.
// If the file doesn't exist, returns a default configuration.
func LoadClientConfig(path string) (*ClientConfig, error) {
	v := viper.New()
	v.SetConfigFile(path)

	// Try to read config, but don't fail if it doesn't exist
	if err := v.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if errors.As(err, &configFileNotFoundError) {
			// Return default config
			return &ClientConfig{
				CurrentProfile: "default",
				Profiles: map[string]ClientProfile{
					"default": {
						Server: "localhost:9000",
						Cache: CacheConfig{
							Enabled:   true,
							Directory: filepath.Join(os.Getenv("HOME"), ".knox", "cache"),
							TTL:       "5m",
						},
					},
				},
			}, nil
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg ClientConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

// LoadDBusConfig loads D-Bus bridge configuration from a file.
func LoadDBusConfig(path string) (*DBusConfig, error) {
	v := viper.New()
	v.SetConfigFile(path)

	// Set defaults
	v.SetDefault("dbus.bus_type", "session")
	v.SetDefault("dbus.service_name", "org.freedesktop.secrets")
	v.SetDefault("knox.server", "localhost:9000")
	v.SetDefault("knox.namespace_prefix", "dbus")
	v.SetDefault("encryption.algorithms", []string{"plain", "dh-ietf1024-sha256-aes128-cbc-pkcs7"})

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg DBusConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

// SaveClientConfig saves client configuration to a file.
func SaveClientConfig(path string, cfg *ClientConfig) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal config to YAML
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write config to file
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// ParseDuration parses a duration string with units (e.g., "5m", "1h").
func ParseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}
