package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hazayan/knox/pkg/config"
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
	cmd.AddCommand(newAuthFido2Cmd())

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

func newAuthFido2Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fido2",
		Short: "Run Knox FIDO2 authentication ceremonies",
	}
	cmd.AddCommand(newAuthFido2BeginCmd())
	cmd.AddCommand(newAuthFido2FinishCmd())
	cmd.AddCommand(newAuthFido2LoginCmd())
	cmd.AddCommand(newAuthFido2RegisterCmd())
	cmd.AddCommand(newAuthFido2ImportCmd())
	return cmd
}

func newAuthFido2BeginCmd() *cobra.Command {
	var principalType string
	var subject string

	cmd := &cobra.Command{
		Use:   "begin",
		Short: "Begin a FIDO2 login ceremony",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(principalType) == "" || strings.TrimSpace(subject) == "" {
				return errors.New("principal type and subject are required")
			}
			prof, httpClient, err := unauthenticatedProfileClient()
			if err != nil {
				return err
			}
			req := map[string]string{
				"principal_type": principalType,
				"subject":        subject,
			}
			var resp fido2BeginResponse
			if err := postJSON(httpClient, profileURL(prof, "/v0/auth/fido2/login/begin"), req, &resp); err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(resp)
		},
	}
	cmd.Flags().StringVar(&principalType, "principal-type", "user", "Knox principal type")
	cmd.Flags().StringVar(&subject, "subject", "", "Knox principal subject")
	return cmd
}

func newAuthFido2FinishCmd() *cobra.Command {
	var sessionID string
	var assertionFile string

	cmd := &cobra.Command{
		Use:   "finish",
		Short: "Finish a FIDO2 login ceremony and store the Knox token",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(sessionID) == "" {
				return errors.New("session id is required")
			}
			assertion, err := readAssertion(assertionFile, cmd.InOrStdin())
			if err != nil {
				return err
			}
			prof, httpClient, err := unauthenticatedProfileClient()
			if err != nil {
				return err
			}
			req := fido2FinishRequest{
				SessionID: sessionID,
				Assertion: json.RawMessage(assertion),
			}
			var resp fido2FinishResponse
			if err := postJSON(httpClient, profileURL(prof, "/v0/auth/fido2/login/finish"), req, &resp); err != nil {
				return err
			}
			tokenFile, err := authTokenPath()
			if err != nil {
				return err
			}
			if err := writeAuthTokenFile(tokenFile, resp.Token); err != nil {
				return err
			}
			if jsonOutput {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
					"status":     "stored",
					"path":       tokenFile,
					"expires_at": resp.ExpiresAt,
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Stored token: %s\n", tokenFile)
			return nil
		},
	}
	cmd.Flags().StringVar(&sessionID, "session-id", "", "FIDO2 login session ID")
	cmd.Flags().StringVar(&assertionFile, "assertion-file", "-", "JSON assertion file, or - for stdin")
	return cmd
}

func newAuthFido2LoginCmd() *cobra.Command {
	var principalType string
	var subject string
	var device string
	var pinFile string
	var origin string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Run a FIDO2 hardware login ceremony and store the Knox token",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(principalType) == "" || strings.TrimSpace(subject) == "" {
				return errors.New("principal type and subject are required")
			}
			prof, httpClient, err := unauthenticatedProfileClient()
			if err != nil {
				return err
			}
			req := map[string]string{
				"principal_type": principalType,
				"subject":        subject,
			}
			var begin fido2BeginResponse
			if err := postJSON(httpClient, profileURL(prof, "/v0/auth/fido2/login/begin"), req, &begin); err != nil {
				return err
			}
			assertion, err := fido2HardwareLoginAssertion(begin.Options, fido2HardwareOptions{
				Device:  device,
				PINFile: pinFile,
				Origin:  profileOrigin(prof, origin),
			})
			if err != nil {
				return err
			}
			finish := fido2FinishRequest{
				SessionID: begin.SessionID,
				Assertion: json.RawMessage(assertion),
			}
			var resp fido2FinishResponse
			if err := postJSON(httpClient, profileURL(prof, "/v0/auth/fido2/login/finish"), finish, &resp); err != nil {
				return err
			}
			tokenFile, err := authTokenPath()
			if err != nil {
				return err
			}
			if err := writeAuthTokenFile(tokenFile, resp.Token); err != nil {
				return err
			}
			if jsonOutput {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
					"status":     "stored",
					"path":       tokenFile,
					"expires_at": resp.ExpiresAt,
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Stored token: %s\n", tokenFile)
			return nil
		},
	}
	cmd.Flags().StringVar(&principalType, "principal-type", "user", "Knox principal type")
	cmd.Flags().StringVar(&subject, "subject", "", "Knox principal subject")
	cmd.Flags().StringVar(&device, "device", "auto", "FIDO2 device path or auto")
	cmd.Flags().StringVar(&pinFile, "pin-file", "", "File containing the FIDO2 PIN")
	cmd.Flags().StringVar(&origin, "origin", "", "WebAuthn origin override")
	return cmd
}

func newAuthFido2RegisterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register Knox FIDO2 credentials",
	}
	cmd.AddCommand(newAuthFido2RegisterBeginCmd())
	cmd.AddCommand(newAuthFido2RegisterFinishCmd())
	cmd.AddCommand(newAuthFido2RegisterHardwareCmd())
	return cmd
}

func newAuthFido2RegisterBeginCmd() *cobra.Command {
	var principalType string
	var subject string
	var displayName string
	var groups []string

	cmd := &cobra.Command{
		Use:   "begin",
		Short: "Begin an authenticated FIDO2 credential registration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(principalType) == "" || strings.TrimSpace(subject) == "" {
				return errors.New("principal type and subject are required")
			}
			prof, httpClient, authToken, err := authenticatedProfileClient()
			if err != nil {
				return err
			}
			req := map[string]any{
				"principal_type": principalType,
				"subject":        subject,
				"display_name":   displayName,
				"groups":         compactStrings(groups),
			}
			var resp fido2BeginResponse
			if err := postJSONWithAuth(httpClient, profileURL(prof, "/v0/auth/fido2/credentials/begin"), authToken, req, &resp); err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(resp)
		},
	}
	cmd.Flags().StringVar(&principalType, "principal-type", "user", "Knox principal type")
	cmd.Flags().StringVar(&subject, "subject", "", "Knox principal subject")
	cmd.Flags().StringVar(&displayName, "display-name", "", "FIDO2 display name")
	cmd.Flags().StringSliceVar(&groups, "group", nil, "Group to attach to a user principal")
	return cmd
}

func newAuthFido2RegisterFinishCmd() *cobra.Command {
	var sessionID string
	var credentialFile string

	cmd := &cobra.Command{
		Use:   "finish",
		Short: "Finish an authenticated FIDO2 credential registration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(sessionID) == "" {
				return errors.New("session id is required")
			}
			credential, err := readAssertion(credentialFile, cmd.InOrStdin())
			if err != nil {
				return err
			}
			prof, httpClient, authToken, err := authenticatedProfileClient()
			if err != nil {
				return err
			}
			req := map[string]any{
				"session_id": sessionID,
				"credential": json.RawMessage(credential),
			}
			var resp fido2CredentialResponse
			if err := postJSONWithAuth(httpClient, profileURL(prof, "/v0/auth/fido2/credentials/finish"), authToken, req, &resp); err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(resp)
		},
	}
	cmd.Flags().StringVar(&sessionID, "session-id", "", "FIDO2 registration session ID")
	cmd.Flags().StringVar(&credentialFile, "credential-file", "-", "JSON credential file, or - for stdin")
	return cmd
}

func newAuthFido2RegisterHardwareCmd() *cobra.Command {
	var principalType string
	var subject string
	var displayName string
	var groups []string
	var device string
	var pinFile string
	var origin string

	cmd := &cobra.Command{
		Use:   "hardware",
		Short: "Run an authenticated FIDO2 hardware credential registration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(principalType) == "" || strings.TrimSpace(subject) == "" {
				return errors.New("principal type and subject are required")
			}
			prof, httpClient, authToken, err := authenticatedProfileClient()
			if err != nil {
				return err
			}
			req := map[string]any{
				"principal_type": principalType,
				"subject":        subject,
				"display_name":   displayName,
				"groups":         compactStrings(groups),
			}
			var begin fido2BeginResponse
			if err := postJSONWithAuth(httpClient, profileURL(prof, "/v0/auth/fido2/credentials/begin"), authToken, req, &begin); err != nil {
				return err
			}
			credential, err := fido2HardwareRegistrationCredential(begin.Options, fido2HardwareOptions{
				Device:  device,
				PINFile: pinFile,
				Origin:  profileOrigin(prof, origin),
			})
			if err != nil {
				return err
			}
			finish := map[string]any{
				"session_id": begin.SessionID,
				"credential": json.RawMessage(credential),
			}
			var resp fido2CredentialResponse
			if err := postJSONWithAuth(httpClient, profileURL(prof, "/v0/auth/fido2/credentials/finish"), authToken, finish, &resp); err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(resp)
		},
	}
	cmd.Flags().StringVar(&principalType, "principal-type", "user", "Knox principal type")
	cmd.Flags().StringVar(&subject, "subject", "", "Knox principal subject")
	cmd.Flags().StringVar(&displayName, "display-name", "", "FIDO2 display name")
	cmd.Flags().StringSliceVar(&groups, "group", nil, "Group to attach to a user principal")
	cmd.Flags().StringVar(&device, "device", "auto", "FIDO2 device path or auto")
	cmd.Flags().StringVar(&pinFile, "pin-file", "", "File containing the FIDO2 PIN")
	cmd.Flags().StringVar(&origin, "origin", "", "WebAuthn origin override")
	return cmd
}

func newAuthFido2ImportCmd() *cobra.Command {
	var principalType string
	var subject string
	var displayName string
	var groups []string
	var userHandle string
	var credentialFile string

	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import a Knox FIDO2 credential record",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(principalType) == "" || strings.TrimSpace(subject) == "" {
				return errors.New("principal type and subject are required")
			}
			credential, err := readAssertion(credentialFile, cmd.InOrStdin())
			if err != nil {
				return err
			}
			prof, httpClient, authToken, err := authenticatedProfileClient()
			if err != nil {
				return err
			}
			req := map[string]any{
				"principal_type": principalType,
				"subject":        subject,
				"display_name":   displayName,
				"groups":         compactStrings(groups),
				"user_handle":    strings.TrimSpace(userHandle),
				"credential":     json.RawMessage(credential),
			}
			var resp fido2CredentialResponse
			if err := postJSONWithAuth(httpClient, profileURL(prof, "/v0/auth/fido2/credentials/import"), authToken, req, &resp); err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(resp)
		},
	}
	cmd.Flags().StringVar(&principalType, "principal-type", "user", "Knox principal type")
	cmd.Flags().StringVar(&subject, "subject", "", "Knox principal subject")
	cmd.Flags().StringVar(&displayName, "display-name", "", "FIDO2 display name")
	cmd.Flags().StringSliceVar(&groups, "group", nil, "Group to attach to a user principal")
	cmd.Flags().StringVar(&userHandle, "user-handle", "", "Base64url WebAuthn user handle")
	cmd.Flags().StringVar(&credentialFile, "credential-file", "-", "JSON credential record file, or - for stdin")
	return cmd
}

type fido2BeginResponse struct {
	SessionID string          `json:"session_id"`
	Options   json.RawMessage `json:"options"`
}

type fido2CredentialResponse struct {
	PrincipalType string `json:"principal_type"`
	Subject       string `json:"subject"`
	CredentialID  string `json:"credential_id"`
}

type fido2FinishRequest struct {
	SessionID string          `json:"session_id"`
	Assertion json.RawMessage `json:"assertion"`
}

type fido2FinishResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func unauthenticatedProfileClient() (*config.ClientProfile, *http.Client, error) {
	if err := loadConfig(); err != nil {
		return nil, nil, err
	}
	prof, err := getCurrentProfile()
	if err != nil {
		return nil, nil, err
	}
	httpClient, err := createHTTPClient(prof)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}
	return prof, httpClient, nil
}

func authenticatedProfileClient() (*config.ClientProfile, *http.Client, string, error) {
	prof, httpClient, err := unauthenticatedProfileClient()
	if err != nil {
		return nil, nil, "", err
	}
	for _, handler := range createAuthHandlers(prof) {
		token, _, _ := handler()
		if strings.TrimSpace(token) != "" {
			return prof, httpClient, token, nil
		}
	}
	return nil, nil, "", errors.New("no Knox auth token available")
}

func profileURL(prof *config.ClientProfile, path string) string {
	scheme := strings.TrimSpace(prof.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	return scheme + "://" + strings.TrimRight(prof.Server, "/") + path
}

func profileOrigin(prof *config.ClientProfile, override string) string {
	override = strings.TrimSpace(override)
	if override != "" {
		return strings.TrimRight(override, "/")
	}
	return strings.TrimRight(profileURL(prof, ""), "/")
}

func relyingPartyIDFromOrigin(origin string) string {
	parsed, err := neturl.Parse(origin)
	if err != nil || parsed.Hostname() == "" {
		return origin
	}
	return parsed.Hostname()
}

func decodeBase64URL(value string, field string) ([]byte, error) {
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", field, err)
	}
	return data, nil
}

func postJSON(httpClient *http.Client, url string, req any, resp any) error {
	return postJSONWithAuth(httpClient, url, "", req, resp)
}

func postJSONWithAuth(httpClient *http.Client, url string, authToken string, req any, resp any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to encode request: %w", err)
	}
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		httpReq.Header.Set("Authorization", authToken)
	}
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(httpResp.Body, 4096))
		return fmt.Errorf("server returned %s: %s", httpResp.Status, strings.TrimSpace(string(data)))
	}
	if err := json.NewDecoder(httpResp.Body).Decode(resp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	return nil
}

func readAssertion(path string, stdin io.Reader) ([]byte, error) {
	if path == "" || path == "-" {
		data, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("failed to read assertion from stdin: %w", err)
		}
		return validateAssertion(data)
	}
	if strings.Contains(path, "..") {
		return nil, errors.New("assertion file cannot contain parent directory references")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read assertion file: %w", err)
	}
	return validateAssertion(data)
}

func compactStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func validateAssertion(data []byte) ([]byte, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("assertion cannot be empty")
	}
	if !json.Valid(data) {
		return nil, errors.New("assertion must be valid JSON")
	}
	return data, nil
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
