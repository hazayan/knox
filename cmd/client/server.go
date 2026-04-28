package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/hazayan/knox/pkg/config"
	"github.com/spf13/cobra"
)

type serverProbeResult struct {
	Endpoint string `json:"endpoint"`
	Status   string `json:"status"`
	Code     int    `json:"code"`
	Body     string `json:"body,omitempty"`
	Error    string `json:"error,omitempty"`
}

func newServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Inspect Knox server status",
		Long:  "Inspect the configured Knox server and its operational endpoints.",
	}

	cmd.AddCommand(newServerHealthCmd())
	cmd.AddCommand(newServerReadyCmd())
	cmd.AddCommand(newServerInfoCmd())

	return cmd
}

func newServerHealthCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "health",
		Short: "Check server health",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServerProbe(cmd, "/health")
		},
	}
}

func newServerReadyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ready",
		Short: "Check server readiness",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServerProbe(cmd, "/ready")
		},
	}
}

func newServerInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show configured server information",
		RunE: func(cmd *cobra.Command, _ []string) error {
			prof, err := getCurrentProfile()
			if err != nil {
				return err
			}

			health := probeServerEndpoint(prof, "/health")
			ready := probeServerEndpoint(prof, "/ready")

			info := map[string]any{
				"profile":   cfg.CurrentProfile,
				"server":    prof.Server,
				"base_url":  serverBaseURL(prof),
				"tls":       profileUsesTLS(prof),
				"cache":     prof.Cache.Enabled,
				"health":    health,
				"readiness": ready,
			}

			if jsonOutput {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(info)
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "FIELD\tVALUE")
			fmt.Fprintln(w, "-----\t-----")
			fmt.Fprintf(w, "profile\t%s\n", cfg.CurrentProfile)
			fmt.Fprintf(w, "server\t%s\n", prof.Server)
			fmt.Fprintf(w, "base_url\t%s\n", serverBaseURL(prof))
			fmt.Fprintf(w, "tls\t%t\n", profileUsesTLS(prof))
			fmt.Fprintf(w, "cache\t%t\n", prof.Cache.Enabled)
			fmt.Fprintf(w, "health\t%s (%d)\n", health.Status, health.Code)
			fmt.Fprintf(w, "readiness\t%s (%d)\n", ready.Status, ready.Code)
			return w.Flush()
		},
	}
}

func runServerProbe(cmd *cobra.Command, endpoint string) error {
	prof, err := getCurrentProfile()
	if err != nil {
		return err
	}

	result := probeServerEndpoint(prof, endpoint)
	if jsonOutput {
		if err := json.NewEncoder(cmd.OutOrStdout()).Encode(result); err != nil {
			return err
		}
	} else if result.Error != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", result.Status, result.Error)
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", result.Status, result.Body)
	}

	if result.Status != "ok" {
		return fmt.Errorf("%s returned %s", endpoint, result.Status)
	}
	return nil
}

func probeServerEndpoint(prof *config.ClientProfile, endpoint string) serverProbeResult {
	result := serverProbeResult{
		Endpoint: endpoint,
		Status:   "error",
	}

	httpClient, err := createHTTPClient(prof)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	httpClient.Timeout = 5 * time.Second

	url := serverBaseURL(prof) + endpoint
	resp, err := httpClient.Get(url) //nolint:gosec // URL is from local Knox client configuration.
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Code = resp.StatusCode
	result.Body = strings.TrimSpace(string(body))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		result.Status = "ok"
	} else {
		result.Status = "failed"
	}

	return result
}

func serverBaseURL(prof *config.ClientProfile) string {
	server := strings.TrimRight(prof.Server, "/")
	if strings.HasPrefix(server, "http://") || strings.HasPrefix(server, "https://") {
		return server
	}
	if profileUsesTLS(prof) {
		return "https://" + server
	}
	return "http://" + server
}

func profileUsesTLS(prof *config.ClientProfile) bool {
	return prof.TLS.CACert != "" || prof.TLS.ClientCert != "" || prof.TLS.ClientKey != ""
}
