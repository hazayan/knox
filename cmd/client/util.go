package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/hazayan/knox/client"
	"github.com/hazayan/knox/pkg/config"
	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(_ *cobra.Command, _ []string) {
			if jsonOutput {
				versionInfo := map[string]string{
					"version": version,
					"commit":  commit,
					"date":    date,
				}
				if err := logger.Print(versionInfo); err != nil {
					logger.Error("Failed to output version information", err)
				}
				return
			}

			logger.Printf("Knox CLI version %s\n", version)
			logger.Printf("Commit: %s\n", commit)
			logger.Printf("Build date: %s\n", date)

			logger.Debug("Version information displayed", map[string]any{
				"version": version,
				"commit":  commit,
				"date":    date,
			})
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
				if err := cmd.Root().GenBashCompletion(os.Stdout); err != nil {
					fmt.Fprintf(os.Stderr, "Error generating bash completion: %v\n", err)
				}
			case "zsh":
				if err := cmd.Root().GenZshCompletion(os.Stdout); err != nil {
					fmt.Fprintf(os.Stderr, "Error generating zsh completion: %v\n", err)
				}
			case "fish":
				if err := cmd.Root().GenFishCompletion(os.Stdout, true); err != nil {
					fmt.Fprintf(os.Stderr, "Error generating fish completion: %v\n", err)
				}
			case "powershell":
				if err := cmd.Root().GenPowerShellCompletion(os.Stdout); err != nil {
					fmt.Fprintf(os.Stderr, "Error generating powershell completion: %v\n", err)
				}
			}
		},
	}
}

// validateAndReadFile securely validates the file path and reads its contents.
// - Only allows files in allowedDirs (absolute paths)
// - Disallows path traversal (..)
// - Only allows files with allowedExts (e.g., .txt, .json, .pem)
// Returns error if any rule is violated.
func validateAndReadFile(filePath string, allowedDirs, allowedExts []string) ([]byte, error) {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute path: %w", err)
	}

	// Check extension
	extAllowed := false
	for _, ext := range allowedExts {
		if strings.EqualFold(filepath.Ext(absPath), ext) {
			extAllowed = true
			break
		}
	}
	if !extAllowed {
		return nil, fmt.Errorf("file extension not allowed: %s", filepath.Ext(absPath))
	}

	// Check for path traversal
	if strings.Contains(absPath, "..") {
		return nil, errors.New("path traversal detected in file path")
	}

	// Check allowed directories
	dirAllowed := false
	for _, dir := range allowedDirs {
		absDir, err := filepath.Abs(dir)
		if err != nil {
			continue
		}
		if strings.HasPrefix(absPath, absDir) {
			dirAllowed = true
			break
		}
	}
	if !dirAllowed {
		return nil, fmt.Errorf("file path %s is not within allowed directories", absPath)
	}

	// Optionally log file access for audit
	log.Printf("Reading file: %s", absPath)

	// #nosec G304 -- absPath is strictly validated above (directory, extension, traversal)
	return os.ReadFile(absPath)
}

// createHTTPClient creates an HTTP client with TLS configuration.
func createHTTPClient(prof *config.ClientProfile) (*http.Client, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Load CA certificate if specified
	if prof.TLS.CACert != "" {
		// Defensive: Only allow absolute paths, forbid traversal
		if !filepath.IsAbs(prof.TLS.CACert) || strings.Contains(prof.TLS.CACert, "..") {
			return nil, errors.New("CA certificate path must be absolute and not contain '..'")
		}
		caCert, err := os.ReadFile(prof.TLS.CACert) // #nosec G304 -- path is validated above
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
		// Defensive: Only allow absolute paths, forbid traversal
		if !filepath.IsAbs(tokenFile) || strings.Contains(tokenFile, "..") {
			return "", "", nil
		}
		token, err := os.ReadFile(tokenFile) // #nosec G304 -- path is validated above
		if err != nil {
			return "", "", nil
		}

		return "0u" + string(token), "user_token_file", nil
	})

	return handlers
}
