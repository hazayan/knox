// Package main provides the production Knox CLI client.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/hazayan/knox/pkg/config"
	"github.com/hazayan/knox/pkg/observability/logging"
	"github.com/spf13/cobra"
)

var (
	version    = "2.0.0-dev"
	commit     = "dev"
	date       = "unknown"
	cfgFile    string
	profile    string
	jsonOutput bool
	cfg        *config.ClientConfig
	logger     *logging.CLILogger
)

func main() {
	// Initialize logger
	logger = logging.NewCLILogger(jsonOutput, os.Stdout)

	rootCmd := &cobra.Command{
		Use:   "knox",
		Short: "Knox secret management CLI",
		Long: `Knox is a command-line interface for managing secrets, keys, and passwords.

Knox provides secure storage and rotation of credentials with fine-grained
access control and comprehensive audit logging.`,
		Version: version,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
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

	// Global flags - use XDG Base Directory Specification (with legacy fallback)
	defaultCfgFile := getDefaultConfigPath()

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", defaultCfgFile, "Path to config file (default follows XDG Base Directory Specification)")
	rootCmd.PersistentFlags().StringVarP(&profile, "profile", "p", "", "Profile to use (overrides config)")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")

	// Update logger when json flag changes
	rootCmd.PersistentPreRun = func(_ *cobra.Command, _ []string) {
		logger = logging.NewCLILogger(jsonOutput, os.Stdout)
	}

	// Add command groups
	rootCmd.AddCommand(newKeyCmd())
	rootCmd.AddCommand(newACLCmd())
	rootCmd.AddCommand(newConfigCmd())
	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newCompletionCmd())

	if err := rootCmd.Execute(); err != nil {
		logger.Error("Command execution failed", err)
		os.Exit(1)
	}
}

func loadConfig() error {
	var err error
	cfg, err = config.LoadClientConfig(cfgFile)
	if err != nil {
		logger.Error("Failed to load configuration", err, map[string]any{
			"config_file": cfgFile,
		})
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Override profile if specified
	if profile != "" {
		logger.Debug("Overriding profile", map[string]any{
			"from": cfg.CurrentProfile,
			"to":   profile,
		})
		cfg.CurrentProfile = profile
	}

	// Validate that the current profile exists
	if _, ok := cfg.Profiles[cfg.CurrentProfile]; !ok {
		logger.Error("Profile not found", nil, map[string]any{
			"profile":            cfg.CurrentProfile,
			"available_profiles": getProfileNames(cfg),
		})
		return fmt.Errorf("profile '%s' not found in config", cfg.CurrentProfile)
	}

	logger.Debug("Configuration loaded successfully", map[string]any{
		"profile": cfg.CurrentProfile,
		"server":  cfg.Profiles[cfg.CurrentProfile].Server,
	})
	return nil
}

func getCurrentProfile() (*config.ClientProfile, error) {
	if cfg == nil {
		logger.Error("Configuration not loaded", errors.New("configuration is nil"))
		return nil, errors.New("configuration not loaded")
	}

	prof, ok := cfg.Profiles[cfg.CurrentProfile]
	if !ok {
		logger.Error("Profile not found", nil, map[string]any{
			"profile":            cfg.CurrentProfile,
			"available_profiles": getProfileNames(cfg),
		})
		return nil, fmt.Errorf("profile '%s' not found", cfg.CurrentProfile)
	}

	return &prof, nil
}

// getProfileNames returns a list of available profile names.
func getProfileNames(cfg *config.ClientConfig) []string {
	names := make([]string, 0, len(cfg.Profiles))
	for name := range cfg.Profiles {
		names = append(names, name)
	}
	return names
}

// getDefaultConfigPath returns the default configuration file path.
// It uses XDG Base Directory Specification.
func getDefaultConfigPath() string {
	path, err := config.GetDefaultClientConfigPath()
	if err != nil {
		// No fallback - return error
		logger.Error("Failed to get XDG config path", err)
		os.Exit(1)
	}
	return path
}
