package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/hazayan/knox/client"
	"github.com/hazayan/knox/pkg/config"
	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Knox CLI version %s\n", version)
		},
	}
}

func newCompletionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts",
		Long: `Generate shell completion scripts for Knox CLI.

To load completions:

Bash:
  $ source <(knox completion bash)
  # To load completions for each session, add to ~/.bashrc:
  $ knox completion bash > /etc/bash_completion.d/knox

Zsh:
  # If shell completion is not already enabled, enable it:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc
  # To load completions for each session, add to ~/.zshrc:
  $ knox completion zsh > "${fpath[1]}/_knox"

Fish:
  $ knox completion fish | source
  # To load completions for each session, add to ~/.config/fish/config.fish:
  $ knox completion fish > ~/.config/fish/completions/types.fish

PowerShell:
  PS> knox completion powershell | Out-String | Invoke-Expression
  # To load completions for every new session, add to your PowerShell profile:
  PS> knox completion powershell > types.ps1`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			switch args[0] {
			case "bash":
				cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				cmd.Root().GenPowerShellCompletion(os.Stdout)
			}
		},
	}
}

// createHTTPClient creates an HTTP client with TLS configuration.
func createHTTPClient(prof *config.ClientProfile) (*http.Client, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Load CA certificate if specified
	if prof.TLS.CACert != "" {
		caCert, err := os.ReadFile(prof.TLS.CACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate if specified
	if prof.TLS.ClientCert != "" && prof.TLS.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(prof.TLS.ClientCert, prof.TLS.ClientKey)
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

// createAuthHandlers creates authentication handlers for the client.
func createAuthHandlers(prof *config.ClientProfile) []client.AuthHandler {
	var handlers []client.AuthHandler

	// mTLS auth handler (if client cert is configured)
	if prof.TLS.ClientCert != "" {
		handlers = append(handlers, func() (string, string, client.HTTP) {
			// mTLS auth is handled by the HTTP client
			// Return a marker token to indicate mTLS is being used
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

	// File-based auth handler (check for token in ~/.knox/token)
	handlers = append(handlers, func() (string, string, client.HTTP) {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", "", nil
		}

		tokenFile := filepath.Join(homeDir, ".knox", "token")
		token, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", "", nil
		}

		return "0u" + string(token), "user_token_file", nil
	})

	return handlers
}
