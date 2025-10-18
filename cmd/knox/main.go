// Package main provides the production Knox CLI client.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hazayan/knox/pkg/config"
	"github.com/spf13/cobra"
)

var (
	version    = "2.0.0-dev"
	cfgFile    string
	profile    string
	jsonOutput bool
	cfg        *config.ClientConfig
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "knox",
		Short: "Knox secret management CLI",
		Long: `Knox is a command-line interface for managing secrets, keys, and passwords.

Knox provides secure storage and rotation of credentials with fine-grained
access control and comprehensive audit logging.`,
		Version: version,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Skip config loading for config, version, and completion commands
			cmdName := cmd.Name()
			if cmdName == "config" || cmdName == "version" || cmdName == "completion" || cmdName == "help" {
				return nil
			}
			// Also skip for subcommands of config
			if cmd.Parent() != nil && cmd.Parent().Name() == "config" {
				return nil
			}
			return loadConfig()
		},
	}

	// Global flags
	homeDir, _ := os.UserHomeDir()
	defaultCfgFile := filepath.Join(homeDir, ".knox", "config.yaml")

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", defaultCfgFile, "Path to config file")
	rootCmd.PersistentFlags().StringVarP(&profile, "profile", "p", "", "Profile to use (overrides config)")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")

	// Add command groups
	rootCmd.AddCommand(newKeyCmd())
	rootCmd.AddCommand(newACLCmd())
	rootCmd.AddCommand(newConfigCmd())
	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newCompletionCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadConfig() error {
	var err error
	cfg, err = config.LoadClientConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Override profile if specified
	if profile != "" {
		cfg.CurrentProfile = profile
	}

	// Validate that the current profile exists
	if _, ok := cfg.Profiles[cfg.CurrentProfile]; !ok {
		return fmt.Errorf("profile '%s' not found in config", cfg.CurrentProfile)
	}

	return nil
}

func getCurrentProfile() (*config.ClientProfile, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}

	prof, ok := cfg.Profiles[cfg.CurrentProfile]
	if !ok {
		return nil, fmt.Errorf("profile '%s' not found", cfg.CurrentProfile)
	}

	return &prof, nil
}
