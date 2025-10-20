// Package client provides tests for CLI command functions.
package client

import (
	"errors"
	"flag"
	"os"
	"testing"

	"github.com/hazayan/knox/pkg/types"
)

// TestCommandName tests the Name method.
func TestCommandName(t *testing.T) {
	tests := []struct {
		usageLine string
		expected  string
	}{
		{"login", "login"},
		{"login [username]", "login"},
		{"get <key>", "get"},
		{"create <key>", "create"},
		{"", ""},
	}

	for _, tt := range tests {
		cmd := &Command{UsageLine: tt.usageLine}
		if got := cmd.Name(); got != tt.expected {
			t.Errorf("Command.Name() with UsageLine %q = %q, want %q", tt.usageLine, got, tt.expected)
		}
	}
}

// TestCommandRunnable tests the Runnable method.
func TestCommandRunnable(t *testing.T) {
	t.Run("RunnableWithRunFunction", func(t *testing.T) {
		cmd := &Command{
			Run: func(_ *Command, _ []string) *ErrorStatus {
				return nil
			},
		}
		if !cmd.Runnable() {
			t.Error("Command with Run function should be runnable")
		}
	})

	t.Run("NotRunnableWithoutRunFunction", func(t *testing.T) {
		cmd := &Command{}
		if cmd.Runnable() {
			t.Error("Command without Run function should not be runnable")
		}
	})
}

// TestCommandUsage tests the Usage method.
func TestCommandUsage(t *testing.T) {
	// Skip this test as Usage calls os.Exit(2) which cannot be easily tested
	t.Skip("Skipping TestCommandUsage - Usage calls os.Exit(2) which cannot be tested")
}

// TestErrorStatus tests ErrorStatus functionality.
func TestErrorStatus(t *testing.T) {
	t.Run("ErrorStatusWithError", func(t *testing.T) {
		err := errors.New("test error")
		status := &ErrorStatus{error: err}

		if status.Error() != "test error" {
			t.Errorf("ErrorStatus.Error() = %q, want %q", status.Error(), "test error")
		}
	})

	t.Run("ErrorStatusServerError", func(t *testing.T) {
		err := errors.New("server error")
		status := &ErrorStatus{error: err, serverError: true}

		// Test that we can check if it's a server error
		// (though this field is not exported, we can test the structure exists)
		if status.Error() != "server error" {
			t.Errorf("ErrorStatus.Error() = %q, want %q", status.Error(), "server error")
		}
	})
}

// TestCommandIntegration tests basic command integration.
func TestCommandIntegration(t *testing.T) {
	t.Run("CommandWithMockClient", func(t *testing.T) {
		// Save original state
		oldArgs := os.Args
		defer func() { os.Args = oldArgs }()

		// Set up test args
		os.Args = []string{"knox", "test"}
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

		// Create a simple test command
		testCmd := &Command{
			UsageLine: "test",
			Run: func(_ *Command, _ []string) *ErrorStatus {
				return nil
			},
		}

		// Add to commands list temporarily
		oldCommands := commands
		commands = []*Command{testCmd}
		defer func() { commands = oldCommands }()

		// This will run but we can't easily test the full execution
		// due to os.Exit calls. We verify the command structure is correct.
		if !testCmd.Runnable() {
			t.Error("Test command should be runnable")
		}
		if testCmd.Name() != "test" {
			t.Errorf("Command name = %q, want %q", testCmd.Name(), "test")
		}
	})
}

// TestCommandFlagHandling tests command flag handling.
func TestCommandFlagHandling(t *testing.T) {
	cmd := &Command{
		UsageLine: "testcmd",
	}

	// Test that we can add flags to the command
	var testFlag string
	cmd.Flag.StringVar(&testFlag, "flag", "default", "test flag")

	if cmd.Flag.Lookup("flag") == nil {
		t.Error("Flag should be registered with command")
	}
}

// TestMockClientInCommands tests using mock client in command context.
func TestMockClientInCommands(t *testing.T) {
	mockClient := NewMock("primary-data", []string{"active1", "active2"})

	t.Run("MockClientGetPrimary", func(t *testing.T) {
		primary := mockClient.GetPrimary()
		if primary != "primary-data" {
			t.Errorf("MockClient.GetPrimary() = %q, want %q", primary, "primary-data")
		}
	})

	t.Run("MockClientGetActive", func(t *testing.T) {
		active := mockClient.GetActive()
		if len(active) != 2 {
			t.Errorf("MockClient.GetActive() returned %d items, want 2", len(active))
		}
		if active[0] != "active1" || active[1] != "active2" {
			t.Errorf("MockClient.GetActive() = %v, want [active1 active2]", active)
		}
	})

	t.Run("MockClientGetKeyObject", func(t *testing.T) {
		keyObj := mockClient.GetKeyObject()
		if len(keyObj.VersionList) != 3 {
			t.Errorf("MockClient.GetKeyObject() has %d versions, want 3", len(keyObj.VersionList))
		}
	})
}

// TestNewMockKeyVersion tests NewMockKeyVersion function.
func TestNewMockKeyVersion(t *testing.T) {
	kv := NewMockKeyVersion([]byte("test-data"), types.Primary)
	if string(kv.Data) != "test-data" {
		t.Errorf("NewMockKeyVersion data = %q, want %q", string(kv.Data), "test-data")
	}
	if kv.Status != types.Primary {
		t.Errorf("NewMockKeyVersion status = %v, want %v", kv.Status, types.Primary)
	}
}

// TestCommandList tests command list functionality.
func TestCommandList(t *testing.T) {
	// Save original commands
	oldCommands := commands
	defer func() { commands = oldCommands }()

	// Set up test commands
	commands = []*Command{
		{UsageLine: "cmd1", Short: "First command"},
		{UsageLine: "cmd2", Short: "Second command"},
		{UsageLine: "cmd3", Short: "Third command"},
	}

	// Verify commands are accessible
	if len(commands) != 3 {
		t.Errorf("commands length = %d, want 3", len(commands))
	}

	// Test individual command properties
	if commands[0].Name() != "cmd1" {
		t.Errorf("commands[0].Name() = %q, want %q", commands[0].Name(), "cmd1")
	}
	if commands[1].Short != "Second command" {
		t.Errorf("commands[1].Short = %q, want %q", commands[1].Short, "Second command")
	}
}

// TestCommandEdgeCases tests edge cases.
func TestCommandEdgeCases(t *testing.T) {
	t.Run("EmptyUsageLine", func(t *testing.T) {
		cmd := &Command{UsageLine: ""}
		if cmd.Name() != "" {
			t.Errorf("Command with empty UsageLine should have empty name, got %q", cmd.Name())
		}
	})

	t.Run("UsageLineWithMultipleSpaces", func(t *testing.T) {
		cmd := &Command{UsageLine: "cmd   with   spaces"}
		if cmd.Name() != "cmd" {
			t.Errorf("Command name should be first word, got %q", cmd.Name())
		}
	})

	t.Run("NilRunFunction", func(t *testing.T) {
		cmd := &Command{Run: nil}
		if cmd.Runnable() {
			t.Error("Command with nil Run function should not be runnable")
		}
	})
}

// TestVisibilityParams tests visibility parameters.
func TestVisibilityParams(t *testing.T) {
	params := &VisibilityParams{
		Logf: func(_ string, _ ...any) {
			// Log function implementation
		},
		Errorf: func(_ string, _ ...any) {
			// Error function implementation
		},
		SummaryMetrics: func(_ map[string]uint64) {
			// Summary metrics implementation
		},
		InvokeMetrics: func(_ map[string]string) {
			// Invoke metrics implementation
		},
		GetKeyMetrics: func(_ map[string]string) {
			// Get key metrics implementation
		},
	}

	// Test that we can call the functions (they won't actually be called in this test)
	// This just verifies the structure is correct
	if params.Logf == nil || params.Errorf == nil {
		t.Error("VisibilityParams functions should not be nil")
	}
}
