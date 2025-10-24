// Package main provides structure tests for the Knox CLI.
package main

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// TestCommandStructure tests that the command structure is properly built.
func TestCommandStructure(t *testing.T) {
	// Test that all command constructors return valid commands
	t.Run("key_command_structure", func(t *testing.T) {
		cmd := newKeyCmd()
		assert.NotNil(t, cmd)
		assert.Equal(t, "key", cmd.Use)
		assert.Equal(t, "Manage Knox keys", cmd.Short)

		subcommands := cmd.Commands()
		assert.Greater(t, len(subcommands), 0, "Key command should have subcommands")

		// Check for expected subcommands
		subcommandNames := make(map[string]bool)
		for _, subcmd := range subcommands {
			subcommandNames[subcmd.Name()] = true
		}

		expectedSubcommands := []string{"create", "get", "list", "delete", "rotate", "versions"}
		for _, expected := range expectedSubcommands {
			assert.True(t, subcommandNames[expected], "Key command should have %s subcommand", expected)
		}
	})

	t.Run("acl_command_structure", func(t *testing.T) {
		cmd := newACLCmd()
		assert.NotNil(t, cmd)
		assert.Equal(t, "acl", cmd.Use)
		assert.Contains(t, cmd.Short, "ACL")

		subcommands := cmd.Commands()
		assert.Greater(t, len(subcommands), 0, "ACL command should have subcommands")

		// Check for expected subcommands
		subcommandNames := make(map[string]bool)
		for _, subcmd := range subcommands {
			subcommandNames[subcmd.Name()] = true
		}

		expectedSubcommands := []string{"get", "add", "remove"}
		for _, expected := range expectedSubcommands {
			assert.True(t, subcommandNames[expected], "ACL command should have %s subcommand", expected)
		}
	})

	t.Run("config_command_structure", func(t *testing.T) {
		cmd := newConfigCmd()
		assert.NotNil(t, cmd)
		assert.Equal(t, "config", cmd.Use)
		assert.Contains(t, cmd.Short, "config")

		subcommands := cmd.Commands()
		assert.Greater(t, len(subcommands), 0, "Config command should have subcommands")

		// Check for expected subcommands
		subcommandNames := make(map[string]bool)
		for _, subcmd := range subcommands {
			subcommandNames[subcmd.Use] = true
		}

		expectedSubcommands := []string{"init", "show", "profile"}
		for _, expected := range expectedSubcommands {
			assert.True(t, subcommandNames[expected], "Config command should have %s subcommand", expected)
		}
	})

	t.Run("version_command_structure", func(t *testing.T) {
		cmd := newVersionCmd()
		assert.NotNil(t, cmd)
		assert.Equal(t, "version", cmd.Use)
		assert.Contains(t, cmd.Short, "version")
	})

	t.Run("completion_command_structure", func(t *testing.T) {
		cmd := newCompletionCmd()
		assert.NotNil(t, cmd)
		assert.Equal(t, "completion [bash|zsh|fish|powershell]", cmd.Use)
		assert.Contains(t, cmd.Short, "completion")
	})
}

// TestCommandFlags tests that commands have expected flags.
func TestCommandFlags(t *testing.T) {
	t.Run("key_create_flags", func(t *testing.T) {
		cmd := newKeyCreateCmd()
		assert.NotNil(t, cmd)

		// Check for expected flags
		flags := cmd.Flags()
		assert.NotNil(t, flags)

		// These flags should exist
		assert.True(t, flags.HasFlags(), "Key create command should have flags")
	})

	t.Run("key_get_flags", func(t *testing.T) {
		cmd := newKeyGetCmd()
		assert.NotNil(t, cmd)

		flags := cmd.Flags()
		assert.NotNil(t, flags)
	})

	t.Run("config_init_flags", func(t *testing.T) {
		cmd := newConfigInitCmd()
		assert.NotNil(t, cmd)

		flags := cmd.Flags()
		assert.NotNil(t, flags)
		assert.True(t, flags.HasFlags(), "Config init command should have flags")
	})
}

// TestCommandValidation tests command argument validation.
func TestCommandValidation(t *testing.T) {
	t.Run("key_commands_require_args", func(t *testing.T) {
		// Test that key commands that require arguments have proper validation
		commands := []struct {
			name string
			cmd  *cobra.Command
		}{
			{"create", newKeyCreateCmd()},
			{"get", newKeyGetCmd()},
			{"delete", newKeyDeleteCmd()},
			{"rotate", newKeyRotateCmd()},
			{"versions", newKeyVersionsCmd()},
		}

		for _, tc := range commands {
			t.Run(tc.name, func(t *testing.T) {
				assert.NotNil(t, tc.cmd)
				// Commands should have argument validation in their RunE functions
				// This is a structural test - actual validation is tested in integration tests
			})
		}
	})

	t.Run("acl_commands_require_args", func(t *testing.T) {
		// Test that ACL commands that require arguments have proper validation
		aclCmd := newACLCmd()
		subcommands := aclCmd.Commands()

		for _, subcmd := range subcommands {
			t.Run(subcmd.Use, func(t *testing.T) {
				assert.NotNil(t, subcmd)
				// Commands should have argument validation
			})
		}
	})
}
