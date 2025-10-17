package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/pinterest/knox"
	"github.com/spf13/cobra"
)

func newACLCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "acl",
		Short: "Manage key ACLs",
		Long:  "View and modify access control lists for Knox keys.",
	}

	cmd.AddCommand(newACLGetCmd())
	cmd.AddCommand(newACLAddCmd())
	cmd.AddCommand(newACLRemoveCmd())

	return cmd
}

func newACLGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get KEY_ID",
		Short: "Get a key's ACL",
		Long: `Display the access control list for a key.

Examples:
  knox acl get myapp:api_key
  knox acl get myapp:api_key --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			keyID := args[0]

			client, err := getAPIClient()
			if err != nil {
				return err
			}

			acl, err := client.GetACL(keyID)
			if err != nil {
				return fmt.Errorf("failed to get ACL: %w", err)
			}

			if jsonOutput {
				return json.NewEncoder(os.Stdout).Encode(acl)
			}

			fmt.Printf("ACL for key: %s\n\n", keyID)

			if len(*acl) == 0 {
				fmt.Println("No ACL entries")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "TYPE\tPRINCIPAL\tACCESS")
			fmt.Fprintln(w, "----\t---------\t------")

			for _, entry := range *acl {
				principalType := formatPrincipalType(entry.Type)
				accessType := formatAccessType(entry.AccessType)
				fmt.Fprintf(w, "%s\t%s\t%s\n", principalType, entry.ID, accessType)
			}

			w.Flush()
			return nil
		},
	}

	return cmd
}

func newACLAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add KEY_ID TYPE:PRINCIPAL:ACCESS",
		Short: "Add an ACL entry",
		Long: `Add an access control entry to a key.

Format: TYPE:PRINCIPAL:ACCESS

Types:
  User, UserGroup, Machine, MachinePrefix, Service, ServicePrefix

Access levels:
  Read, Write, Admin

Examples:
  knox acl add myapp:api_key User:alice@example.com:Read
  knox acl add myapp:api_key Service:spiffe://example.com/myservice:Write
  knox acl add myapp:api_key UserGroup:developers:Admin`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			keyID := args[0]
			aclEntry := args[1]

			// Parse the ACL entry
			acl, err := parseACL([]string{aclEntry})
			if err != nil {
				return err
			}

			if len(acl) != 1 {
				return fmt.Errorf("expected exactly one ACL entry")
			}

			client, err := getAPIClient()
			if err != nil {
				return err
			}

			if err := client.PutAccess(keyID, acl[0]); err != nil {
				return fmt.Errorf("failed to add ACL entry: %w", err)
			}

			if jsonOutput {
				return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
					"key_id": keyID,
					"acl":    acl[0],
					"status": "added",
				})
			}

			fmt.Printf("✓ ACL entry added to %s:\n", keyID)
			fmt.Printf("  %s: %s -> %s\n",
				formatPrincipalType(acl[0].Type),
				acl[0].ID,
				formatAccessType(acl[0].AccessType))

			return nil
		},
	}

	return cmd
}

func newACLRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove KEY_ID TYPE:PRINCIPAL",
		Short: "Remove an ACL entry",
		Long: `Remove an access control entry from a key.

Format: TYPE:PRINCIPAL

Examples:
  knox acl remove myapp:api_key User:alice@example.com
  knox acl remove myapp:api_key Service:spiffe://example.com/myservice`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			keyID := args[0]
			aclEntry := args[1] + ":None" // Add None access to remove

			// Parse the ACL entry
			acl, err := parseACL([]string{aclEntry})
			if err != nil {
				return err
			}

			if len(acl) != 1 {
				return fmt.Errorf("expected exactly one ACL entry")
			}

			client, err := getAPIClient()
			if err != nil {
				return err
			}

			if err := client.PutAccess(keyID, acl[0]); err != nil {
				return fmt.Errorf("failed to remove ACL entry: %w", err)
			}

			if jsonOutput {
				return json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
					"key_id": keyID,
					"acl":    acl[0],
					"status": "removed",
				})
			}

			fmt.Printf("✓ ACL entry removed from %s:\n", keyID)
			fmt.Printf("  %s: %s\n",
				formatPrincipalType(acl[0].Type),
				acl[0].ID)

			return nil
		},
	}

	return cmd
}

// Helper functions

func formatPrincipalType(pt knox.PrincipalType) string {
	switch pt {
	case knox.User:
		return "User"
	case knox.UserGroup:
		return "UserGroup"
	case knox.Machine:
		return "Machine"
	case knox.MachinePrefix:
		return "MachinePrefix"
	case knox.Service:
		return "Service"
	case knox.ServicePrefix:
		return "ServicePrefix"
	default:
		return "Unknown"
	}
}

func formatAccessType(at knox.AccessType) string {
	switch at {
	case knox.Read:
		return "Read"
	case knox.Write:
		return "Write"
	case knox.Admin:
		return "Admin"
	default:
		return "None"
	}
}
