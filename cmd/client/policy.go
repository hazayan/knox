package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/hazayan/knox/pkg/types"
	"github.com/spf13/cobra"
)

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage ACL policies",
		Long:  "Manage named ACL policies that apply default ACL grants when matching keys are created.",
	}
	cmd.AddCommand(newPolicyListCmd())
	cmd.AddCommand(newPolicyGetCmd())
	cmd.AddCommand(newPolicyPutCmd())
	cmd.AddCommand(newPolicyDeleteCmd())
	return cmd
}

func newPolicyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List ACL policies",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			client, err := getAPIClient()
			if err != nil {
				return err
			}
			names, err := client.ListPolicies()
			if err != nil {
				return fmt.Errorf("failed to list policies: %w", err)
			}
			if jsonOutput {
				return json.NewEncoder(os.Stdout).Encode(names)
			}
			for _, name := range names {
				logger.Println(name)
			}
			return nil
		},
	}
}

func newPolicyGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get NAME",
		Short: "Get an ACL policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			client, err := getAPIClient()
			if err != nil {
				return err
			}
			policy, err := client.GetPolicy(args[0])
			if err != nil {
				return fmt.Errorf("failed to get policy: %w", err)
			}
			if jsonOutput {
				return json.NewEncoder(os.Stdout).Encode(policy)
			}
			printPolicy(policy)
			return nil
		},
	}
}

func newPolicyPutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "put FILE",
		Short: "Create or update an ACL policy from a JSON file",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("failed to read policy file: %w", err)
			}
			var policy types.ACLPolicy
			if err := json.Unmarshal(data, &policy); err != nil {
				return fmt.Errorf("failed to parse policy file: %w", err)
			}
			client, err := getAPIClient()
			if err != nil {
				return err
			}
			if err := client.PutPolicy(policy); err != nil {
				return fmt.Errorf("failed to put policy: %w", err)
			}
			if jsonOutput {
				return json.NewEncoder(os.Stdout).Encode(policy)
			}
			logger.Success(fmt.Sprintf("Policy %s updated", policy.Name), map[string]any{"policy": policy.Name})
			return nil
		},
	}
}

func newPolicyDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete NAME",
		Short: "Delete an ACL policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			client, err := getAPIClient()
			if err != nil {
				return err
			}
			if err := client.DeletePolicy(args[0]); err != nil {
				return fmt.Errorf("failed to delete policy: %w", err)
			}
			if jsonOutput {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{"policy": args[0], "status": "deleted"})
			}
			logger.Success(fmt.Sprintf("Policy %s deleted", args[0]), map[string]any{"policy": args[0]})
			return nil
		},
	}
}

func printPolicy(policy *types.ACLPolicy) {
	logger.Printf("Policy: %s\n\n", policy.Name)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	logger.Println("PATTERN\tTYPE\tPRINCIPAL\tACCESS")
	logger.Println("-------\t----\t---------\t------")
	for _, rule := range policy.Rules {
		for _, grant := range rule.Grants {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", rule.Pattern, formatPrincipalType(grant.Type), grant.ID, formatAccessType(grant.AccessType))
		}
	}
	_ = w.Flush()
}
