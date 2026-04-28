package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hazayan/knox/pkg/xdg"
	"github.com/spf13/cobra"
)

func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage local Knox authentication",
		Long:  "Manage local Knox authentication material used by the CLI.",
	}

	cmd.AddCommand(newAuthLoginCmd())
	cmd.AddCommand(newAuthLogoutCmd())
	cmd.AddCommand(newAuthStatusCmd())

	return cmd
}

func newAuthLoginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login [TOKEN]",
		Short: "Store a user auth token",
		Long:  "Store a user auth token in the XDG Knox token file with owner-only permissions.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			token := ""
			if len(args) == 1 {
				token = args[0]
			} else {
				data, err := io.ReadAll(cmd.InOrStdin())
				if err != nil {
					return fmt.Errorf("failed to read token from stdin: %w", err)
				}
				token = string(data)
			}

			token = strings.TrimSpace(token)
			if token == "" {
				return errors.New("token cannot be empty")
			}

			tokenFile, err := authTokenPath()
			if err != nil {
				return err
			}
			if err := writeAuthTokenFile(tokenFile, token); err != nil {
				return err
			}

			if jsonOutput {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
					"status": "stored",
					"path":   tokenFile,
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Stored token: %s\n", tokenFile)
			return nil
		},
	}
}

func newAuthLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove the stored user auth token",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tokenFile, err := authTokenPath()
			if err != nil {
				return err
			}

			removed, err := removeAuthTokenFile(tokenFile)
			if err != nil {
				return err
			}

			if jsonOutput {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
					"status":  "removed",
					"path":    tokenFile,
					"removed": removed,
				})
			}
			if removed {
				fmt.Fprintf(cmd.OutOrStdout(), "Removed token: %s\n", tokenFile)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "No stored token: %s\n", tokenFile)
			}
			return nil
		},
	}
}

func newAuthStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show local auth token status",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tokenFile, err := authTokenPath()
			if err != nil {
				return err
			}

			_, err = readAuthTokenFile(tokenFile)
			present := err == nil
			status := "missing"
			errorMessage := ""
			if present {
				status = "present"
			} else if !os.IsNotExist(err) {
				status = "invalid"
				errorMessage = err.Error()
			}

			if jsonOutput {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
					"status":  status,
					"path":    tokenFile,
					"present": present,
					"error":   errorMessage,
				})
			}
			if errorMessage != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "%s: %s (%s)\n", status, tokenFile, errorMessage)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", status, tokenFile)
			}
			return nil
		},
	}
}

func authTokenPath() (string, error) {
	tokenFile, err := xdg.ConfigFile("token")
	if err != nil {
		return "", fmt.Errorf("failed to resolve token file path: %w", err)
	}
	if !filepath.IsAbs(tokenFile) || strings.Contains(tokenFile, "..") {
		return "", errors.New("token file path must be absolute and not contain parent directory references")
	}
	return tokenFile, nil
}

func writeAuthTokenFile(tokenFile, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("token cannot be empty")
	}

	tokenDir := filepath.Dir(tokenFile)
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		return fmt.Errorf("failed to create token directory: %w", err)
	}
	if err := os.Chmod(tokenDir, 0o700); err != nil {
		return fmt.Errorf("failed to secure token directory: %w", err)
	}

	if info, err := os.Lstat(tokenFile); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("token file must not be a symlink")
		}
		if info.IsDir() {
			return errors.New("token file path must be a regular file")
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to inspect token file: %w", err)
	}

	file, err := os.OpenFile(tokenFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(token + "\n"); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("failed to secure token file permissions: %w", err)
	}

	return nil
}

func removeAuthTokenFile(tokenFile string) (bool, error) {
	if info, err := os.Lstat(tokenFile); err == nil {
		if info.IsDir() {
			return false, errors.New("token file path must be a regular file")
		}
	} else if os.IsNotExist(err) {
		return false, nil
	} else {
		return false, fmt.Errorf("failed to inspect token file: %w", err)
	}

	if err := os.Remove(tokenFile); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to remove token file: %w", err)
	}
	return true, nil
}
