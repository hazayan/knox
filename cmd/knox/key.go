package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/pinterest/knox"
	"github.com/spf13/cobra"
)

func newKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Manage Knox keys",
		Long:  "Create, retrieve, list, delete, and manage Knox keys.",
	}

	cmd.AddCommand(newKeyCreateCmd())
	cmd.AddCommand(newKeyGetCmd())
	cmd.AddCommand(newKeyListCmd())
	cmd.AddCommand(newKeyDeleteCmd())
	cmd.AddCommand(newKeyRotateCmd())
	cmd.AddCommand(newKeyVersionsCmd())

	return cmd
}

func newKeyCreateCmd() *cobra.Command {
	var (
		data     string
		dataFile string
		acl      []string
	)

	cmd := &cobra.Command{
		Use:   "create KEY_ID",
		Short: "Create a new key",
		Long: `Create a new key with the specified ID and data.

Data can be provided via --data flag or read from stdin/file.
ACL entries should be in the format: TYPE:ID:ACCESS

Examples:
  knox key create myapp:api_key --data "secret123"
  echo "secret123" | knox key create myapp:api_key
  knox key create myapp:api_key --data-file secret.txt
  knox key create myapp:api_key --data "secret" --acl "User:alice@example.com:Read"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			keyID := args[0]

			// Get data from various sources
			var keyData []byte
			var err error

			if dataFile != "" {
				keyData, err = os.ReadFile(dataFile)
				if err != nil {
					return fmt.Errorf("failed to read data file: %w", err)
				}
			} else if data != "" {
				keyData = []byte(data)
			} else {
				// Read from stdin
				keyData, err = io.ReadAll(os.Stdin)
				if err != nil {
					return fmt.Errorf("failed to read from stdin: %w", err)
				}
			}

			if len(keyData) == 0 {
				return fmt.Errorf("no data provided")
			}

			// Parse ACL entries
			parsedACL, err := parseACL(acl)
			if err != nil {
				return fmt.Errorf("failed to parse ACL: %w", err)
			}

			// Get API client
			client, err := getAPIClient()
			if err != nil {
				return err
			}

			// Create the key
			versionID, err := client.CreateKey(keyID, keyData, parsedACL)
			if err != nil {
				return fmt.Errorf("failed to create key: %w", err)
			}

			if jsonOutput {
				return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
					"key_id":     keyID,
					"version_id": versionID,
					"status":     "created",
				})
			}

			fmt.Printf("✓ Key created: %s (version %d)\n", keyID, versionID)
			return nil
		},
	}

	cmd.Flags().StringVarP(&data, "data", "d", "", "Key data (if not reading from stdin)")
	cmd.Flags().StringVarP(&dataFile, "data-file", "f", "", "Read key data from file")
	cmd.Flags().StringSliceVarP(&acl, "acl", "a", []string{}, "ACL entries (can be specified multiple times)")

	return cmd
}

func newKeyGetCmd() *cobra.Command {
	var (
		versionStatus string
		showAll       bool
	)

	cmd := &cobra.Command{
		Use:   "get KEY_ID",
		Short: "Get a key's value",
		Long: `Retrieve a key's value from Knox.

By default, returns the primary version. Use --all to see all active versions.

Examples:
  knox key get myapp:api_key
  knox key get myapp:api_key --all
  knox key get myapp:api_key --status Primary`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			keyID := args[0]

			client, err := getAPIClient()
			if err != nil {
				return err
			}

			// Parse version status if provided
			var status knox.VersionStatus
			if versionStatus != "" {
				switch strings.ToLower(versionStatus) {
				case "primary":
					status = knox.Primary
				case "active":
					status = knox.Active
				case "inactive":
					status = knox.Inactive
				default:
					return fmt.Errorf("invalid status: %s (must be Primary, Active, or Inactive)", versionStatus)
				}

				key, err := client.GetKeyWithStatus(keyID, status)
				if err != nil {
					return fmt.Errorf("failed to get key: %w", err)
				}

				return displayKey(key, showAll)
			}

			key, err := client.GetKey(keyID)
			if err != nil {
				return fmt.Errorf("failed to get key: %w", err)
			}

			return displayKey(key, showAll)
		},
	}

	cmd.Flags().StringVar(&versionStatus, "status", "", "Version status filter (Primary, Active, Inactive)")
	cmd.Flags().BoolVarP(&showAll, "all", "A", false, "Show all active versions")

	return cmd
}

func newKeyListCmd() *cobra.Command {
	var prefix string

	cmd := &cobra.Command{
		Use:   "list [PREFIX]",
		Short: "List keys",
		Long: `List all keys, optionally filtered by prefix.

Examples:
  knox key list
  knox key list myapp:
  knox key list --json`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				prefix = args[0]
			}

			client, err := getAPIClient()
			if err != nil {
				return err
			}

			// List keys
			keys, err := client.GetKeys(map[string]string{})
			if err != nil {
				return fmt.Errorf("failed to list keys: %w", err)
			}

			// Filter by prefix if specified
			if prefix != "" {
				var filtered []string
				for _, key := range keys {
					if strings.HasPrefix(key, prefix) {
						filtered = append(filtered, key)
					}
				}
				keys = filtered
			}

			if jsonOutput {
				return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
					"keys":  keys,
					"count": len(keys),
				})
			}

			if len(keys) == 0 {
				fmt.Println("No keys found")
				return nil
			}

			fmt.Printf("Found %d key(s):\n\n", len(keys))
			for _, key := range keys {
				fmt.Printf("  %s\n", key)
			}

			return nil
		},
	}

	return cmd
}

func newKeyDeleteCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "delete KEY_ID",
		Short: "Delete a key",
		Long: `Delete a key from Knox.

This is a destructive operation and cannot be undone. Use with caution.

Examples:
  knox key delete myapp:api_key
  knox key delete myapp:api_key --force`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			keyID := args[0]

			if !force {
				fmt.Printf("Are you sure you want to delete key '%s'? (y/N): ", keyID)
				var response string
				fmt.Scanln(&response)
				if strings.ToLower(response) != "y" {
					fmt.Println("Deletion cancelled")
					return nil
				}
			}

			client, err := getAPIClient()
			if err != nil {
				return err
			}

			if err := client.DeleteKey(keyID); err != nil {
				return fmt.Errorf("failed to delete key: %w", err)
			}

			if jsonOutput {
				return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
					"key_id": keyID,
					"status": "deleted",
				})
			}

			fmt.Printf("✓ Key deleted: %s\n", keyID)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation prompt")

	return cmd
}

func newKeyRotateCmd() *cobra.Command {
	var (
		data     string
		dataFile string
	)

	cmd := &cobra.Command{
		Use:   "rotate KEY_ID",
		Short: "Rotate a key (add new version)",
		Long: `Add a new version to an existing key.

The new version will become active but not primary. Use 'knox key promote'
to make it the primary version.

Examples:
  knox key rotate myapp:api_key --data "newsecret123"
  echo "newsecret123" | knox key rotate myapp:api_key`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			keyID := args[0]

			// Get data
			var keyData []byte
			var err error

			if dataFile != "" {
				keyData, err = os.ReadFile(dataFile)
				if err != nil {
					return fmt.Errorf("failed to read data file: %w", err)
				}
			} else if data != "" {
				keyData = []byte(data)
			} else {
				keyData, err = io.ReadAll(os.Stdin)
				if err != nil {
					return fmt.Errorf("failed to read from stdin: %w", err)
				}
			}

			if len(keyData) == 0 {
				return fmt.Errorf("no data provided")
			}

			client, err := getAPIClient()
			if err != nil {
				return err
			}

			versionID, err := client.AddVersion(keyID, keyData)
			if err != nil {
				return fmt.Errorf("failed to add version: %w", err)
			}

			if jsonOutput {
				return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
					"key_id":     keyID,
					"version_id": versionID,
					"status":     "added",
				})
			}

			fmt.Printf("✓ New version added: %s (version %d)\n", keyID, versionID)
			fmt.Println("  Use 'knox key promote' to make this the primary version")
			return nil
		},
	}

	cmd.Flags().StringVarP(&data, "data", "d", "", "New key data")
	cmd.Flags().StringVarP(&dataFile, "data-file", "f", "", "Read data from file")

	return cmd
}

func newKeyVersionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "versions KEY_ID",
		Short: "List key versions",
		Long: `List all versions of a key with their status.

Examples:
  knox key versions myapp:api_key
  knox key versions myapp:api_key --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			keyID := args[0]

			client, err := getAPIClient()
			if err != nil {
				return err
			}

			key, err := client.GetKey(keyID)
			if err != nil {
				return fmt.Errorf("failed to get key: %w", err)
			}

			if jsonOutput {
				return json.NewEncoder(os.Stdout).Encode(key.VersionList)
			}

			fmt.Printf("Versions for key: %s\n\n", keyID)

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "VERSION\tSTATUS\tCREATED")
			fmt.Fprintln(w, "-------\t------\t-------")

			for _, v := range key.VersionList {
				status := "Active"
				if v.Status == knox.Primary {
					status = "Primary"
				} else if v.Status == knox.Inactive {
					status = "Inactive"
				}

				fmt.Fprintf(w, "%d\t%s\t%d\n", v.ID, status, v.CreationTime)
			}

			w.Flush()
			return nil
		},
	}

	return cmd
}

// Helper functions

func displayKey(key *knox.Key, showAll bool) error {
	if jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(key)
	}

	if showAll {
		fmt.Printf("Key: %s\n\n", key.ID)
		for _, v := range key.VersionList.GetActive() {
			status := "Active"
			if v.Status == knox.Primary {
				status = "Primary"
			}
			fmt.Printf("[%s] Version %d: %s\n", status, v.ID, string(v.Data))
		}
	} else {
		primary := key.VersionList.GetPrimary()
		if primary != nil {
			fmt.Println(string(primary.Data))
		} else {
			return fmt.Errorf("no primary version found")
		}
	}

	return nil
}

func parseACL(entries []string) (knox.ACL, error) {
	var acl knox.ACL

	for _, entry := range entries {
		parts := strings.Split(entry, ":")
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid ACL entry format: %s (expected TYPE:ID:ACCESS)", entry)
		}

		// Parse principal type
		var principalType knox.PrincipalType
		switch strings.ToLower(parts[0]) {
		case "user":
			principalType = knox.User
		case "usergroup":
			principalType = knox.UserGroup
		case "machine":
			principalType = knox.Machine
		case "machineprefix":
			principalType = knox.MachinePrefix
		case "service":
			principalType = knox.Service
		case "serviceprefix":
			principalType = knox.ServicePrefix
		default:
			return nil, fmt.Errorf("invalid principal type: %s", parts[0])
		}

		// Parse access type
		var accessType knox.AccessType
		switch strings.ToLower(parts[2]) {
		case "read":
			accessType = knox.Read
		case "write":
			accessType = knox.Write
		case "admin":
			accessType = knox.Admin
		default:
			return nil, fmt.Errorf("invalid access type: %s", parts[2])
		}

		acl = append(acl, knox.Access{
			Type:       principalType,
			ID:         parts[1],
			AccessType: accessType,
		})
	}

	return acl, nil
}

func getAPIClient() (knox.APIClient, error) {
	prof, err := getCurrentProfile()
	if err != nil {
		return nil, err
	}

	// Create HTTP client with TLS config
	httpClient, err := createHTTPClient(prof)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Create auth handlers
	authHandlers := createAuthHandlers(prof)

	// Determine cache folder
	cacheFolder := ""
	if prof.Cache.Enabled {
		cacheFolder = prof.Cache.Directory
		// Expand ~ to home directory
		if strings.HasPrefix(cacheFolder, "~/") {
			home, _ := os.UserHomeDir()
			cacheFolder = filepath.Join(home, cacheFolder[2:])
		}
		// Create cache directory if it doesn't exist
		os.MkdirAll(cacheFolder, 0700)
	}

	client := knox.NewClient(prof.Server, httpClient, authHandlers, cacheFolder, version)
	return client, nil
}
