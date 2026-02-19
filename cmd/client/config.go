package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/hazayan/knox/pkg/config"
	"github.com/hazayan/knox/pkg/xdg"
	"github.com/spf13/cobra"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage Knox configuration",
		Long:  "Initialize, view, and manage Knox CLI configuration and profiles.",
	}

	cmd.AddCommand(newConfigInitCmd())
	cmd.AddCommand(newConfigShowCmd())
	cmd.AddCommand(newConfigProfileCmd())
	cmd.AddCommand(newConfigGenerateCmd())

	return cmd
}

func newConfigInitCmd() *cobra.Command {
	var (
		server     string
		caCert     string
		clientCert string
		clientKey  string
		force      bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize Knox configuration",
		Long: `Create a new Knox configuration file with a default profile.

This will create a configuration file in the XDG config directory (typically ~/.config/knox/config.yaml) with a default profile configuration.

Examples:
  knox config init
  knox config init --server knox.example.com:9000
  knox config init --server localhost:9000 --force`,
		RunE: func(_ *cobra.Command, _ []string) error {
			// Check if config already exists
			if !force {
				if _, err := os.Stat(cfgFile); err == nil {
					logger.Printf("Config file already exists: %s\n", cfgFile)
					logger.Println("Use --force to overwrite")
					return nil
				}
			}

			// Create default config
			cacheDir, err := xdg.ProfileCacheDir("default")
			if err != nil {
				return fmt.Errorf("failed to get cache directory: %w", err)
			}

			cfg := &config.ClientConfig{
				CurrentProfile: "default",
				Profiles: map[string]config.ClientProfile{
					"default": {
						Server: server,
						TLS: config.ClientTLSConfig{
							CACert:     caCert,
							ClientCert: clientCert,
							ClientKey:  clientKey,
						},
						Cache: config.CacheConfig{
							Enabled:   true,
							Directory: cacheDir,
							TTL:       "5m",
						},
					},
				},
			}

			if err := config.SaveClientConfig(cfgFile, cfg); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}

			logger.Success(fmt.Sprintf("Configuration initialized: %s", cfgFile), map[string]any{
				"config_file": cfgFile,
				"profile":     "default",
				"server":      server,
				"cache_dir":   cacheDir,
			})

			return nil
		},
	}

	cmd.Flags().StringVar(&server, "server", "localhost:9000", "Knox server address")
	cmd.Flags().StringVar(&caCert, "ca-cert", "", "CA certificate file")
	cmd.Flags().StringVar(&clientCert, "client-cert", "", "Client certificate file")
	cmd.Flags().StringVar(&clientKey, "client-key", "", "Client key file")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Overwrite existing config")

	return cmd
}

func newConfigShowCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show current configuration",
		Long: `Display the current Knox configuration.

Examples:
  knox config show
  knox config show --json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Load config without the PersistentPreRun check
			localCfg, err := config.LoadClientConfig(cfgFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			if jsonOutput {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(localCfg)
			}

			logger.Printf("Configuration file: %s\n\n", cfgFile)
			logger.Printf("Current profile: %s\n\n", localCfg.CurrentProfile)

			logger.Println("Profiles:")
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tSERVER\tCACHE\tTLS")
			fmt.Fprintln(w, "----\t------\t-----\t---")

			for name, prof := range localCfg.Profiles {
				marker := " "
				if name == localCfg.CurrentProfile {
					marker = "*"
				}

				cacheStatus := "disabled"
				if prof.Cache.Enabled {
					cacheStatus = "enabled"
				}

				tlsStatus := "no"
				if prof.TLS.ClientCert != "" || prof.TLS.CACert != "" {
					tlsStatus = "yes"
				}

				fmt.Fprintf(w, "%s %s\t%s\t%s\t%s\n", marker, name, prof.Server, cacheStatus, tlsStatus)
			}

			if err := w.Flush(); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")

	return cmd
}

func newConfigProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage configuration profiles",
		Long:  "Add, remove, and switch between Knox configuration profiles.",
	}

	cmd.AddCommand(newConfigProfileAddCmd())
	cmd.AddCommand(newConfigProfileRemoveCmd())
	cmd.AddCommand(newConfigProfileUseCmd())
	cmd.AddCommand(newConfigProfileListCmd())

	return cmd
}

func newConfigProfileAddCmd() *cobra.Command {
	var (
		server     string
		caCert     string
		clientCert string
		clientKey  string
		cacheDir   string
	)

	cmd := &cobra.Command{
		Use:   "add NAME",
		Short: "Add a new profile",
		Long: `Add a new configuration profile.

Examples:
  knox config profile add production --server knox.prod.example.com:9000
  knox config profile add staging --server knox.staging.example.com:9000`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			profileName := args[0]

			// Load existing config
			localCfg, err := config.LoadClientConfig(cfgFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			// Check if profile already exists
			if _, exists := localCfg.Profiles[profileName]; exists {
				return fmt.Errorf("profile '%s' already exists", profileName)
			}

			// Set default cache dir if not specified
			if cacheDir == "" {
				var err error
				cacheDir, err = xdg.ProfileCacheDir(profileName)
				if err != nil {
					return fmt.Errorf("failed to get cache directory: %w", err)
				}
			}

			// Add new profile
			localCfg.Profiles[profileName] = config.ClientProfile{
				Server: server,
				TLS: config.ClientTLSConfig{
					CACert:     caCert,
					ClientCert: clientCert,
					ClientKey:  clientKey,
				},
				Cache: config.CacheConfig{
					Enabled:   true,
					Directory: cacheDir,
					TTL:       "5m",
				},
			}

			// Save config
			if err := config.SaveClientConfig(cfgFile, localCfg); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}

			logger.Success(fmt.Sprintf("Profile added: %s", profileName), map[string]any{
				"profile_name": profileName,
				"server":       server,
				"cache_dir":    cacheDir,
			})

			return nil
		},
	}

	cmd.Flags().StringVar(&server, "server", "", "Knox server address (required)")
	cmd.Flags().StringVar(&caCert, "ca-cert", "", "CA certificate file")
	cmd.Flags().StringVar(&clientCert, "client-cert", "", "Client certificate file")
	cmd.Flags().StringVar(&clientKey, "client-key", "", "Client key file")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "Cache directory")
	if err := cmd.MarkFlagRequired("server"); err != nil {
		// Log the error but continue - this is a configuration issue
		fmt.Fprintf(os.Stderr, "Warning: failed to mark server flag as required: %v\n", err)
	}

	return cmd
}

func newConfigProfileRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove NAME",
		Short: "Remove a profile",
		Long: `Remove a configuration profile.

Examples:
  knox config profile remove staging`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			profileName := args[0]

			// Load existing config
			localCfg, err := config.LoadClientConfig(cfgFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			// Check if profile exists
			if _, exists := localCfg.Profiles[profileName]; !exists {
				return fmt.Errorf("profile '%s' not found", profileName)
			}

			// Don't allow removing the current profile
			if localCfg.CurrentProfile == profileName {
				return errors.New("cannot remove current profile (use 'knox config profile use' to switch first)")
			}

			// Remove profile
			delete(localCfg.Profiles, profileName)

			// Save config
			if err := config.SaveClientConfig(cfgFile, localCfg); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}

			logger.Success(fmt.Sprintf("Profile removed: %s", profileName), map[string]any{
				"profile_name": profileName,
			})
			return nil
		},
	}

	return cmd
}

func newConfigProfileUseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "use NAME",
		Short: "Switch to a profile",
		Long: `Set the default profile to use.

Examples:
  knox config profile use production
  knox config profile use default`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			profileName := args[0]

			// Load existing config
			localCfg, err := config.LoadClientConfig(cfgFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			// Check if profile exists
			if _, exists := localCfg.Profiles[profileName]; !exists {
				return fmt.Errorf("profile '%s' not found", profileName)
			}

			// Update current profile
			localCfg.CurrentProfile = profileName

			// Save config
			if err := config.SaveClientConfig(cfgFile, localCfg); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}

			logger.Success(fmt.Sprintf("Switched to profile: %s", profileName), map[string]any{
				"profile_name": profileName,
			})
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")

	return cmd
}

func newConfigGenerateCmd() *cobra.Command {
	var (
		outputDir string
		force     bool
	)

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate configuration files",
		Long: `Generate example configuration files for server and D-Bus bridge.

This command creates example configuration files that can be used as templates
for setting up Knox server and D-Bus bridge.

Examples:
  knox config generate
  knox config generate --output /etc/knox
  knox config generate --force`,
		RunE: func(_ *cobra.Command, _ []string) error {
			// Create output directory if it doesn't exist
			if err := os.MkdirAll(outputDir, 0o750); err != nil {
				return fmt.Errorf("failed to create output directory: %w", err)
			}

			// Generate server config
			serverConfigPath := filepath.Join(outputDir, "server.yaml")
			if err := generateServerConfig(serverConfigPath, force); err != nil {
				return fmt.Errorf("failed to generate server config: %w", err)
			}

			// Generate D-Bus config
			dbusConfigPath := filepath.Join(outputDir, "dbus.yaml")
			if err := generateDBusConfig(dbusConfigPath, force); err != nil {
				return fmt.Errorf("failed to generate D-Bus config: %w", err)
			}

			logger.Success("Configuration files generated successfully", map[string]any{
				"output_dir":     outputDir,
				"server_config":  serverConfigPath,
				"dbus_config":    dbusConfigPath,
				"server_example": "knox-server -c " + serverConfigPath,
				"dbus_example":   "knox-dbus --config " + dbusConfigPath,
			})

			return nil
		},
	}

	cmd.Flags().StringVarP(&outputDir, "output", "o", ".", "Output directory for generated config files")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Overwrite existing config files")

	return cmd
}

func generateServerConfig(path string, force bool) error {
	// Check if file already exists
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("server config already exists: %s (use --force to overwrite)", path)
		}
	}

	serverConfig := `# Knox Server Configuration
server:
  bind_address: "0.0.0.0:9000"

  # TLS Configuration (optional)
  tls:
    cert_file: "/etc/knox/tls/server.crt"
    key_file: "/etc/knox/tls/server.key"
    client_ca: "/etc/knox/tls/ca.crt"
    min_version: "TLS1.2"

  # Storage Configuration
  storage:
    backend: "filesystem"  # memory, filesystem, postgres, etcd

    # Filesystem backend (default)
    filesystem_dir: "/var/lib/knox/keys"

    # PostgreSQL backend (production)
    # postgres_connection_string: "postgresql://knox:password@localhost/knox"
    # postgres_max_connections: 100

    # etcd backend (distributed)
    # etcd_endpoints: ["http://localhost:2379"]
    # etcd_prefix: "/knox"

  # Authentication Configuration
  auth:
    providers:
      - type: "mtls"
        ca_file: "/etc/knox/ca.crt"
      # - type: "spiffe"
      #   trust_domain: "example.com"

  # Observability Configuration
  observability:
    metrics:
      enabled: true
      endpoint: "/metrics"
    logging:
      level: "info"   # debug, info, warn, error
      format: "json"  # text, json
    audit:
      enabled: true
      output: "/var/log/knox/audit.log"

  # Rate Limiting and Limits
  limits:
    rate_limit_per_principal: 100
    max_key_size: "1MB"
    max_keys_per_list: 1000
`

	if err := os.WriteFile(path, []byte(serverConfig), 0o600); err != nil {
		return fmt.Errorf("failed to write server config: %w", err)
	}

	return nil
}

func generateDBusConfig(path string, force bool) error {
	// Check if file already exists
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("D-Bus config already exists: %s (use --force to overwrite)", path)
		}
	}

	dbusConfig := `# Knox D-Bus Bridge Configuration
# This configuration enables desktop application integration via FreeDesktop Secret Service

dbus:
  # D-Bus connection settings
  bus_type: "session"  # session, system
  service_name: "org.freedesktop.secrets"

knox:
  # Knox server connection
  server: "localhost:9000"

  # TLS Configuration (optional)
  tls:
    ca_cert: "/etc/knox/ca.crt"
    client_cert: "/etc/knox/client.crt"
    client_key: "/etc/knox/client.key"

  # Namespace prefix for D-Bus keys in Knox
  namespace_prefix: "dbus"

  # Prefix mappings from Knox key prefixes to D-Bus collection names (optional)
  # Format: "knox_prefix": "dbus_collection_name"
  # Example: "service:auth": "service_auth" means Knox keys starting with "service:auth:"
  # get exposed in D-Bus collection "service_auth"
  prefix_mappings: {}
  # Example mappings (uncomment and modify as needed):
  # prefix_mappings:
  #   "service:auth": "service_auth"
  #   "app:database": "database_credentials"
  #   "infra:secrets": "infrastructure"

encryption:
  # Supported encryption algorithms
  algorithms: ["plain", "dh-ietf1024-sha256-aes128-cbc-pkcs7"]

# Usage:
# 1. Start Knox server: knox-server -c /path/to/server.yaml
# 2. Start D-Bus bridge: knox-dbus --config /path/to/dbus.yaml
# 3. Applications like Firefox, Chrome, SSH will automatically use Knox for secret storage
`

	if err := os.WriteFile(path, []byte(dbusConfig), 0o600); err != nil {
		return fmt.Errorf("failed to write D-Bus config: %w", err)
	}

	return nil
}

func newConfigProfileListCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all profiles",
		Long: `List all available configuration profiles.

Examples:
  knox config profile list
  knox config profile list --json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Load config
			localCfg, err := config.LoadClientConfig(cfgFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			if jsonOutput {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(localCfg.Profiles)
			}

			logger.Println("Available profiles:")

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tSERVER\tCACHE")
			fmt.Fprintln(w, "----\t------\t-----")

			for name, prof := range localCfg.Profiles {
				marker := " "
				if name == localCfg.CurrentProfile {
					marker = "*"
				}

				cacheStatus := "disabled"
				if prof.Cache.Enabled {
					cacheStatus = "enabled"
				}

				fmt.Fprintf(w, "%s %s\t%s\t%s\n", marker, name, prof.Server, cacheStatus)
			}

			if err := w.Flush(); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")

	return cmd
}
