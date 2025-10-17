package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/pinterest/knox/pkg/config"
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

This will create ~/.knox/config.yaml with a default profile configuration.

Examples:
  knox config init
  knox config init --server knox.example.com:9000
  knox config init --server localhost:9000 --force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if config already exists
			if !force {
				if _, err := os.Stat(cfgFile); err == nil {
					fmt.Printf("Config file already exists: %s\n", cfgFile)
					fmt.Println("Use --force to overwrite")
					return nil
				}
			}

			// Create default config
			homeDir, _ := os.UserHomeDir()
			cacheDir := filepath.Join(homeDir, ".knox", "cache")

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

			fmt.Printf("✓ Configuration initialized: %s\n", cfgFile)
			fmt.Printf("  Profile: default\n")
			fmt.Printf("  Server: %s\n", server)
			fmt.Printf("  Cache: %s\n", cacheDir)

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
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show current configuration",
		Long: `Display the current Knox configuration.

Examples:
  knox config show
  knox config show --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load config without the PersistentPreRun check
			localCfg, err := config.LoadClientConfig(cfgFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			if jsonOutput {
				return json.NewEncoder(os.Stdout).Encode(localCfg)
			}

			fmt.Printf("Configuration file: %s\n\n", cfgFile)
			fmt.Printf("Current profile: %s\n\n", localCfg.CurrentProfile)

			fmt.Println("Profiles:")
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
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

				fmt.Fprintf(w, "%s %s\t%s\t%s\t%s\n",
					marker, name, prof.Server, cacheStatus, tlsStatus)
			}

			w.Flush()
			return nil
		},
	}

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
		RunE: func(cmd *cobra.Command, args []string) error {
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
				homeDir, _ := os.UserHomeDir()
				cacheDir = filepath.Join(homeDir, ".knox", "cache", profileName)
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

			fmt.Printf("✓ Profile added: %s\n", profileName)
			fmt.Printf("  Server: %s\n", server)
			fmt.Printf("  Cache: %s\n", cacheDir)

			return nil
		},
	}

	cmd.Flags().StringVar(&server, "server", "", "Knox server address (required)")
	cmd.Flags().StringVar(&caCert, "ca-cert", "", "CA certificate file")
	cmd.Flags().StringVar(&clientCert, "client-cert", "", "Client certificate file")
	cmd.Flags().StringVar(&clientKey, "client-key", "", "Client key file")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "Cache directory")
	cmd.MarkFlagRequired("server")

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
		RunE: func(cmd *cobra.Command, args []string) error {
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
				return fmt.Errorf("cannot remove current profile (use 'knox config profile use' to switch first)")
			}

			// Remove profile
			delete(localCfg.Profiles, profileName)

			// Save config
			if err := config.SaveClientConfig(cfgFile, localCfg); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}

			fmt.Printf("✓ Profile removed: %s\n", profileName)
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
		RunE: func(cmd *cobra.Command, args []string) error {
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

			fmt.Printf("✓ Switched to profile: %s\n", profileName)
			return nil
		},
	}

	return cmd
}

func newConfigProfileListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all profiles",
		Long: `List all available configuration profiles.

Examples:
  knox config profile list
  knox config profile list --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load config
			localCfg, err := config.LoadClientConfig(cfgFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			if jsonOutput {
				return json.NewEncoder(os.Stdout).Encode(localCfg.Profiles)
			}

			fmt.Println("Available profiles:\n")

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
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

				fmt.Fprintf(w, "%s %s\t%s\t%s\n",
					marker, name, prof.Server, cacheStatus)
			}

			w.Flush()
			return nil
		},
	}

	return cmd
}
