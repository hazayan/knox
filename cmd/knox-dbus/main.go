// Package main provides the Knox D-Bus Secret Service bridge daemon.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/hazayan/knox/client"
	"github.com/hazayan/knox/pkg/config"
	"github.com/hazayan/knox/pkg/dbus"
	"github.com/hazayan/knox/pkg/observability/logging"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	version = "2.0.0-dev"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "knox-dbus",
		Short: "Knox D-Bus Secret Service bridge",
		Long: `Knox D-Bus bridge provides FreeDesktop Secret Service API compatibility,
allowing desktop applications (Firefox, Chrome, SSH, etc.) to store secrets in Knox.`,
		Version: version,
		RunE:    runDaemon,
	}

	homeDir, _ := os.UserHomeDir()
	defaultCfgFile := filepath.Join(homeDir, ".config", "knox", "dbus.yaml")

	rootCmd.Flags().StringVarP(&cfgFile, "config", "c", defaultCfgFile, "Path to configuration file")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runDaemon(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := config.LoadDBusConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize logging
	if err := logging.Initialize(logging.Config{
		Level:  "info",
		Format: "text",
	}); err != nil {
		log.Fatalf("Failed to initialize logging: %v", err)
	}

	logging.Infof("Knox D-Bus bridge %s starting...", version)
	logging.Infof("Configuration: %s", cfgFile)

	// Create Knox API client
	knoxClient, err := createKnoxClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create Knox client: %w", err)
	}

	// Test Knox connectivity
	logging.Info("Testing Knox connectivity...")
	if _, err := knoxClient.GetKeys(map[string]string{}); err != nil {
		logging.Warnf("Knox connectivity test failed: %v", err)
		logging.Warn("Bridge will continue but may not function properly")
	} else {
		logging.Info("Knox connectivity OK")
	}

	// Create and start D-Bus bridge
	logging.Infof("Starting D-Bus service: %s", cfg.DBus.ServiceName)
	logging.Infof("Bus type: %s", cfg.DBus.BusType)

	bridge, err := dbus.NewBridge(cfg, knoxClient)
	if err != nil {
		return fmt.Errorf("failed to create bridge: %w", err)
	}

	if err := bridge.Start(); err != nil {
		return fmt.Errorf("failed to start bridge: %w", err)
	}
	defer func() {
		if err := bridge.Stop(); err != nil {
			log.Printf("Error stopping bridge: %v", err)
		}
	}()

	logging.Info("D-Bus bridge started successfully")
	logging.Infof("Namespace prefix: %s", cfg.Knox.NamespacePrefix)
	logging.Info("Ready to serve requests")

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	sig := <-sigChan
	logging.Infof("Received signal: %v, shutting down...", sig)

	return nil
}

func createKnoxClient(cfg *config.DBusConfig) (client.APIClient, error) {
	// Create HTTP client with TLS
	httpClient, err := createHTTPClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Create auth handlers
	authHandlers := createAuthHandlers(cfg)

	// Create Knox client
	knoxClient := client.NewClient(
		cfg.Knox.Server,
		httpClient,
		authHandlers,
		"", // No cache for D-Bus bridge
		version,
	)

	return knoxClient, nil
}

func createHTTPClient(cfg *config.DBusConfig) (*http.Client, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Load CA certificate if specified
	if cfg.Knox.TLS.CACert != "" {
		// Validate CA cert path for security
		if !filepath.IsAbs(cfg.Knox.TLS.CACert) || strings.Contains(cfg.Knox.TLS.CACert, "..") {
			return nil, errors.New("CA certificate path must be absolute and not contain '..'")
		}
		caCert, err := os.ReadFile(cfg.Knox.TLS.CACert) // #nosec G304 -- path is validated above
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to parse CA certificate")
		}

		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate if specified
	if cfg.Knox.TLS.ClientCert != "" && cfg.Knox.TLS.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Knox.TLS.ClientCert, cfg.Knox.TLS.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &http.Client{
		Transport: transport,
	}, nil
}

func createAuthHandlers(cfg *config.DBusConfig) []client.AuthHandler {
	var handlers []client.AuthHandler

	// mTLS auth handler (if client cert is configured)
	if cfg.Knox.TLS.ClientCert != "" {
		handlers = append(handlers, func() (string, string, client.HTTP) {
			return "0m", "mtls", nil
		})
	}

	// Environment variable auth handler
	handlers = append(handlers, func() (string, string, client.HTTP) {
		// Check for user auth token in environment
		if token := os.Getenv("KNOX_USER_AUTH"); token != "" {
			return "0u" + token, "user_token", nil
		}

		// Check for machine auth token in environment
		if token := os.Getenv("KNOX_MACHINE_AUTH"); token != "" {
			return "0m" + token, "machine_token", nil
		}

		return "", "", nil
	})

	// File-based auth handler
	handlers = append(handlers, func() (string, string, client.HTTP) {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", "", nil
		}

		tokenFile := filepath.Join(homeDir, ".knox", "token")

		// Validate token file path for security
		if !filepath.IsAbs(tokenFile) {
			return "", "", nil
		}
		if strings.Contains(tokenFile, "..") {
			return "", "", nil
		}

		// Validate token file path for security
		if !filepath.IsAbs(tokenFile) || strings.Contains(tokenFile, "..") {
			return "", "", nil
		}
		token, err := os.ReadFile(tokenFile) // #nosec G304 -- path is validated above
		if err != nil {
			return "", "", nil
		}

		tokenStr := strings.TrimSpace(string(token))
		return "0u" + tokenStr, "user_token_file", nil
	})

	return handlers
}
