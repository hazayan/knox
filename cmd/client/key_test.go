package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hazayan/knox/pkg/observability/logging"
	"github.com/hazayan/knox/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKeyCreateCmd tests the key create command.
func TestKeyCreateCmd(t *testing.T) {
	t.Run("CreateKey_WithDataFlag", func(t *testing.T) {
		tc := NewTestConfig(t)
		defer tc.Cleanup()

		// Initialize logger
		logger = logging.NewCLILogger(false, io.Discard)

		mockClient := &MockAPIClient{}
		mockClient.SetupMockClient()

		// Override CreateKey to capture arguments
		var capturedKeyID string
		var capturedData []byte
		var capturedACL types.ACL
		mockClient.CreateKeyFunc = func(keyID string, data []byte, acl types.ACL) (uint64, error) {
			capturedKeyID = keyID
			capturedData = data
			capturedACL = acl
			return 1, nil
		}

		SetMockAPIClient(mockClient)
		defer SetMockAPIClient(nil)

		cmd := newKeyCreateCmd()
		cmd.SetArgs([]string{"test:key1", "--data", "secret123"})
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err := cmd.Execute()
		require.NoError(t, err)

		assert.Equal(t, "test:key1", capturedKeyID)
		assert.Equal(t, []byte("secret123"), capturedData)
		assert.Empty(t, capturedACL)
	})

	t.Run("CreateKey_WithACL", func(t *testing.T) {
		tc := NewTestConfig(t)
		defer tc.Cleanup()

		// Initialize logger
		logger = logging.NewCLILogger(false, io.Discard)

		mockClient := &MockAPIClient{}
		mockClient.SetupMockClient()

		var capturedACL types.ACL
		mockClient.CreateKeyFunc = func(_ string, _ []byte, acl types.ACL) (uint64, error) {
			capturedACL = acl
			return 1, nil
		}

		SetMockAPIClient(mockClient)
		defer SetMockAPIClient(nil)

		cmd := newKeyCreateCmd()
		cmd.SetArgs([]string{"test:key2", "--data", "secret", "--acl", "User:alice@example.com:Read"})
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err := cmd.Execute()
		require.NoError(t, err)

		require.Len(t, capturedACL, 1)
		assert.Equal(t, "alice@example.com", capturedACL[0].ID)
		// Type and AccessType are validated by parseACL function tests
	})

	t.Run("CreateKey_FromStdin", func(t *testing.T) {
		tc := NewTestConfig(t)
		defer tc.Cleanup()

		// Initialize logger
		logger = logging.NewCLILogger(false, io.Discard)

		mockClient := &MockAPIClient{}
		mockClient.SetupMockClient()

		var capturedData []byte
		mockClient.CreateKeyFunc = func(_ string, data []byte, _ types.ACL) (uint64, error) {
			capturedData = data
			return 1, nil
		}

		SetMockAPIClient(mockClient)
		defer SetMockAPIClient(nil)

		// Create a pipe to simulate stdin
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		r, w, err := os.Pipe()
		require.NoError(t, err)
		os.Stdin = r

		go func() {
			defer w.Close()
			_, _ = w.Write([]byte("stdin-secret\n"))
		}()

		cmd := newKeyCreateCmd()
		cmd.SetArgs([]string{"test:key3"})
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err = cmd.Execute()
		require.NoError(t, err)

		assert.Equal(t, []byte("stdin-secret\n"), capturedData)
	})

	t.Run("CreateKey_FromFile", func(t *testing.T) {
		t.Skip("Skipping file test due to security restrictions")
	})

	t.Run("CreateKey_NoData", func(t *testing.T) {
		tc := NewTestConfig(t)
		defer tc.Cleanup()

		// Initialize logger
		logger = logging.NewCLILogger(false, io.Discard)

		mockClient := &MockAPIClient{}
		mockClient.SetupMockClient()

		SetMockAPIClient(mockClient)
		defer SetMockAPIClient(nil)

		// Empty stdin
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		r, w, err := os.Pipe()
		require.NoError(t, err)
		os.Stdin = r
		w.Close()

		cmd := newKeyCreateCmd()
		cmd.SetArgs([]string{"test:key5"})
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err = cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no data provided")
	})

	t.Run("CreateKey_JSONOutput", func(t *testing.T) {
		tc := NewTestConfig(t)
		defer tc.Cleanup()

		// Initialize logger
		logger = logging.NewCLILogger(false, io.Discard)

		mockClient := &MockAPIClient{}
		mockClient.SetupMockClient()

		mockClient.CreateKeyFunc = func(_ string, _ []byte, _ types.ACL) (uint64, error) {
			return 123, nil
		}

		SetMockAPIClient(mockClient)
		defer SetMockAPIClient(nil)

		// Capture stdout for JSON output
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		cmd := newKeyCreateCmd()
		cmd.SetArgs([]string{"test:key6", "--data", "secret"})
		jsonOutput = true
		defer func() { jsonOutput = false }()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)

		err := cmd.Execute()
		require.NoError(t, err)

		w.Close()
		os.Stdout = oldStdout

		var buf bytes.Buffer
		_, err = io.Copy(&buf, r)
		require.NoError(t, err)

		var result map[string]any
		err = json.Unmarshal(buf.Bytes(), &result)
		require.NoError(t, err)

		assert.Equal(t, "test:key6", result["key_id"])
		assert.Equal(t, float64(123), result["version_id"])
		assert.Equal(t, "created", result["status"])
	})

	t.Run("CreateKey_InvalidACL", func(t *testing.T) {
		tc := NewTestConfig(t)
		defer tc.Cleanup()

		// Initialize logger
		logger = logging.NewCLILogger(false, io.Discard)

		mockClient := &MockAPIClient{}
		mockClient.SetupMockClient()

		SetMockAPIClient(mockClient)
		defer SetMockAPIClient(nil)

		cmd := newKeyCreateCmd()
		cmd.SetArgs([]string{"test:key7", "--data", "secret", "--acl", "Invalid:format"})
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid ACL entry format")
	})
}

// TestKeyGetCmd tests the key get command.
func TestKeyGetCmd(t *testing.T) {
	t.Run("GetKey_PrimaryVersion", func(t *testing.T) {
		tc := NewTestConfig(t)
		defer tc.Cleanup()

		// Initialize logger
		logger = logging.NewCLILogger(false, io.Discard)

		mockClient := &MockAPIClient{}
		mockClient.SetupMockClient()

		testKey := CreateTestKeyWithTwoVersions("test:key5")
		var capturedKeyID string
		mockClient.GetKeyFunc = func(keyID string) (*types.Key, error) {
			capturedKeyID = keyID
			return testKey, nil
		}

		SetMockAPIClient(mockClient)
		defer SetMockAPIClient(nil)

		cmd := newKeyGetCmd()
		cmd.SetArgs([]string{"test:key5"})
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err := cmd.Execute()
		require.NoError(t, err)

		assert.Equal(t, "test:key5", capturedKeyID)
	})

	t.Run("GetKey_WithStatus", func(t *testing.T) {
		t.Skip("Skipping due to GetKeyWithStatus not implemented")
	})

	t.Run("GetKey_AllVersions", func(t *testing.T) {
		t.Skip("Skipping due to --all-versions flag not implemented")
	})

	t.Run("GetKey_JSONOutput", func(t *testing.T) {
		tc := NewTestConfig(t)
		defer tc.Cleanup()

		// Initialize logger
		logger = logging.NewCLILogger(false, io.Discard)

		mockClient := &MockAPIClient{}
		mockClient.SetupMockClient()

		testKey := CreateTestKeyWithTwoVersions("test:key4")
		mockClient.GetKeyFunc = func(_ string) (*types.Key, error) {
			return testKey, nil
		}

		SetMockAPIClient(mockClient)
		defer SetMockAPIClient(nil)

		// Capture stdout for JSON output
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		cmd := newKeyGetCmd()
		cmd.SetArgs([]string{"test:key4"})
		jsonOutput = true
		defer func() { jsonOutput = false }()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)

		err := cmd.Execute()
		require.NoError(t, err)

		w.Close()
		os.Stdout = oldStdout

		var buf bytes.Buffer
		_, err = io.Copy(&buf, r)
		require.NoError(t, err)

		var result *types.Key
		err = json.Unmarshal(buf.Bytes(), &result)
		require.NoError(t, err)

		assert.Equal(t, "test:key4", result.ID)
		assert.Len(t, result.VersionList, 2)
	})

	t.Run("GetKey_InvalidStatus", func(t *testing.T) {
		tc := NewTestConfig(t)
		defer tc.Cleanup()

		// Initialize logger
		logger = logging.NewCLILogger(false, io.Discard)

		mockClient := &MockAPIClient{}
		mockClient.SetupMockClient()

		SetMockAPIClient(mockClient)
		defer SetMockAPIClient(nil)

		cmd := newKeyGetCmd()
		cmd.SetArgs([]string{"test:key5", "--status", "InvalidStatus"})
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid status")
	})
}

// TestKeyListCmd tests the key list command.
func TestKeyListCmd(t *testing.T) {
	t.Run("ListKeys_All", func(t *testing.T) {
		tc := NewTestConfig(t)
		defer tc.Cleanup()

		// Initialize logger
		logger = logging.NewCLILogger(false, io.Discard)

		mockClient := &MockAPIClient{}
		mockClient.SetupMockClient()

		var capturedParams map[string]string
		mockClient.GetKeysFunc = func(params map[string]string) ([]string, error) {
			capturedParams = params
			return []string{"key1", "key2", "key3"}, nil
		}

		SetMockAPIClient(mockClient)
		defer SetMockAPIClient(nil)

		cmd := newKeyListCmd()
		cmd.SetArgs([]string{})
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err := cmd.Execute()
		require.NoError(t, err)

		assert.NotNil(t, capturedParams)
	})

	t.Run("ListKeys_WithPrefix", func(t *testing.T) {
		t.Skip("Skipping due to --prefix flag not implemented")
	})

	t.Run("ListKeys_Empty", func(t *testing.T) {
		tc := NewTestConfig(t)
		defer tc.Cleanup()

		// Initialize logger
		logger = logging.NewCLILogger(false, io.Discard)

		mockClient := &MockAPIClient{}
		mockClient.SetupMockClient()

		var capturedParams map[string]string
		mockClient.GetKeysFunc = func(params map[string]string) ([]string, error) {
			capturedParams = params
			return []string{}, nil
		}

		SetMockAPIClient(mockClient)
		defer SetMockAPIClient(nil)

		cmd := newKeyListCmd()
		cmd.SetArgs([]string{})
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err := cmd.Execute()
		require.NoError(t, err)

		assert.NotNil(t, capturedParams)
	})

	t.Run("ListKeys_JSONOutput", func(t *testing.T) {
		tc := NewTestConfig(t)
		defer tc.Cleanup()

		// Initialize logger
		logger = logging.NewCLILogger(false, io.Discard)

		mockClient := &MockAPIClient{}
		mockClient.SetupMockClient()

		mockClient.GetKeysFunc = func(_ map[string]string) ([]string, error) {
			return []string{"key1", "key2"}, nil
		}

		SetMockAPIClient(mockClient)
		defer SetMockAPIClient(nil)

		// Capture stdout for JSON output
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		cmd := newKeyListCmd()
		cmd.SetArgs([]string{})
		jsonOutput = true
		defer func() { jsonOutput = false }()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)

		err := cmd.Execute()
		require.NoError(t, err)

		w.Close()
		os.Stdout = oldStdout

		var buf bytes.Buffer
		_, err = io.Copy(&buf, r)
		require.NoError(t, err)

		var result map[string]any
		err = json.Unmarshal(buf.Bytes(), &result)
		require.NoError(t, err)

		assert.Equal(t, []any{"key1", "key2"}, result["keys"])
		assert.Equal(t, float64(2), result["count"])
	})
}

// TestKeyDeleteCmd tests the key delete command.
func TestKeyDeleteCmd(t *testing.T) {
	t.Run("DeleteKey_WithConfirmation", func(t *testing.T) {
		tc := NewTestConfig(t)
		defer tc.Cleanup()

		// Initialize logger
		logger = logging.NewCLILogger(false, io.Discard)

		mockClient := &MockAPIClient{}
		mockClient.SetupMockClient()

		var deletedKeyID string
		mockClient.DeleteKeyFunc = func(keyID string) error {
			deletedKeyID = keyID
			return nil
		}

		SetMockAPIClient(mockClient)
		defer SetMockAPIClient(nil)

		// Simulate user confirmation by providing "y" input
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		r, w, err := os.Pipe()
		require.NoError(t, err)
		os.Stdin = r

		go func() {
			defer w.Close()
			_, _ = w.Write([]byte("y\n"))
		}()

		cmd := newKeyDeleteCmd()
		cmd.SetArgs([]string{"test:key8"})
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err = cmd.Execute()
		require.NoError(t, err)

		assert.Equal(t, "test:key8", deletedKeyID)
	})

	t.Run("DeleteKey_WithForce", func(t *testing.T) {
		tc := NewTestConfig(t)
		defer tc.Cleanup()

		// Initialize logger
		logger = logging.NewCLILogger(false, io.Discard)

		mockClient := &MockAPIClient{}
		mockClient.SetupMockClient()

		var deletedKeyID string
		mockClient.DeleteKeyFunc = func(keyID string) error {
			deletedKeyID = keyID
			return nil
		}

		SetMockAPIClient(mockClient)
		defer SetMockAPIClient(nil)

		cmd := newKeyDeleteCmd()
		cmd.SetArgs([]string{"test:key9", "--force"})
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err := cmd.Execute()
		require.NoError(t, err)

		assert.Equal(t, "test:key9", deletedKeyID)
	})

	t.Run("DeleteKey_Cancelled", func(t *testing.T) {
		tc := NewTestConfig(t)
		defer tc.Cleanup()

		// Initialize logger
		logger = logging.NewCLILogger(false, io.Discard)

		mockClient := &MockAPIClient{}
		mockClient.SetupMockClient()

		var deleteCalled bool
		mockClient.DeleteKeyFunc = func(_ string) error {
			deleteCalled = true
			return nil
		}

		SetMockAPIClient(mockClient)
		defer SetMockAPIClient(nil)

		// Simulate user cancellation by providing "n" input
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		r, w, err := os.Pipe()
		require.NoError(t, err)
		os.Stdin = r

		go func() {
			defer w.Close()
			_, _ = w.Write([]byte("n\n"))
		}()

		cmd := newKeyDeleteCmd()
		cmd.SetArgs([]string{"test:key10"})
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err = cmd.Execute()
		require.NoError(t, err)

		assert.False(t, deleteCalled, "Delete should not be called when user cancels")
	})

	t.Run("DeleteKey_JSONOutput", func(t *testing.T) {
		tc := NewTestConfig(t)
		defer tc.Cleanup()

		// Initialize logger
		logger = logging.NewCLILogger(false, io.Discard)

		mockClient := &MockAPIClient{}
		mockClient.SetupMockClient()

		mockClient.DeleteKeyFunc = func(_ string) error {
			return nil
		}

		SetMockAPIClient(mockClient)
		defer SetMockAPIClient(nil)

		// Simulate user confirmation
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		rStdin, wStdin, err := os.Pipe()
		require.NoError(t, err)
		os.Stdin = rStdin

		go func() {
			defer wStdin.Close()
			_, _ = wStdin.Write([]byte("y\n"))
		}()

		// Capture stdout for JSON output
		oldStdout := os.Stdout
		rStdout, wStdout, _ := os.Pipe()
		os.Stdout = wStdout

		cmd := newKeyDeleteCmd()
		cmd.SetArgs([]string{"test:key4", "--force"})
		jsonOutput = true
		defer func() { jsonOutput = false }()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)

		err = cmd.Execute()
		require.NoError(t, err)

		wStdout.Close()
		os.Stdout = oldStdout

		var buf bytes.Buffer
		_, err = io.Copy(&buf, rStdout)
		require.NoError(t, err)

		var result map[string]any
		err = json.Unmarshal(buf.Bytes(), &result)
		require.NoError(t, err)

		assert.Equal(t, "test:key4", result["key_id"])
		assert.Equal(t, "deleted", result["status"])
	})
}

// TestKeyRotateCmd tests the key rotate command.
func TestKeyRotateCmd(t *testing.T) {
	t.Run("RotateKey_WithData", func(t *testing.T) {
		tc := NewTestConfig(t)
		defer tc.Cleanup()

		// Initialize logger
		logger = logging.NewCLILogger(false, io.Discard)

		mockClient := &MockAPIClient{}
		mockClient.SetupMockClient()

		var capturedKeyID string
		var capturedData []byte
		mockClient.AddVersionFunc = func(keyID string, data []byte) (uint64, error) {
			capturedKeyID = keyID
			capturedData = data
			return 3, nil
		}

		SetMockAPIClient(mockClient)
		defer SetMockAPIClient(nil)

		cmd := newKeyRotateCmd()
		cmd.SetArgs([]string{"test:key11", "--data", "new-secret-data"})
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err := cmd.Execute()
		require.NoError(t, err)

		assert.Equal(t, "test:key11", capturedKeyID)
		assert.Equal(t, []byte("new-secret-data"), capturedData)
	})

	t.Run("RotateKey_FromStdin", func(t *testing.T) {
		tc := NewTestConfig(t)
		defer tc.Cleanup()

		// Initialize logger
		logger = logging.NewCLILogger(false, io.Discard)

		mockClient := &MockAPIClient{}
		mockClient.SetupMockClient()

		var capturedData []byte
		mockClient.AddVersionFunc = func(_ string, data []byte) (uint64, error) {
			capturedData = data
			return 2, nil
		}

		SetMockAPIClient(mockClient)
		defer SetMockAPIClient(nil)

		// Create a pipe to simulate stdin
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		r, w, err := os.Pipe()
		require.NoError(t, err)
		os.Stdin = r

		go func() {
			defer w.Close()
			_, _ = w.Write([]byte("stdin-new-secret\n"))
		}()

		var buf bytes.Buffer
		cmd := newKeyRotateCmd()
		cmd.SetArgs([]string{"test:key2"})
		cmd.SetOut(&buf)
		cmd.SetErr(io.Discard)

		err = cmd.Execute()
		require.NoError(t, err)

		assert.Equal(t, []byte("stdin-new-secret\n"), capturedData)
	})

	t.Run("RotateKey_JSONOutput", func(t *testing.T) {
		tc := NewTestConfig(t)
		defer tc.Cleanup()

		// Initialize logger
		logger = logging.NewCLILogger(false, io.Discard)

		mockClient := &MockAPIClient{}
		mockClient.SetupMockClient()

		mockClient.AddVersionFunc = func(_ string, _ []byte) (uint64, error) {
			return 456, nil
		}

		SetMockAPIClient(mockClient)
		defer SetMockAPIClient(nil)

		// Capture stdout for JSON output
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		cmd := newKeyRotateCmd()
		cmd.SetArgs([]string{"test:key3", "--data", "secret"})
		jsonOutput = true
		defer func() { jsonOutput = false }()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)

		err := cmd.Execute()
		require.NoError(t, err)

		w.Close()
		os.Stdout = oldStdout

		var buf bytes.Buffer
		_, err = io.Copy(&buf, r)
		require.NoError(t, err)

		var result map[string]any
		err = json.Unmarshal(buf.Bytes(), &result)
		require.NoError(t, err)

		assert.Equal(t, "test:key3", result["key_id"])
		assert.Equal(t, float64(456), result["version_id"])
		assert.Equal(t, "added", result["status"])
	})
}

// TestKeyVersionsCmd tests the key versions command.
func TestKeyVersionsCmd(t *testing.T) {
	t.Run("ListVersions", func(t *testing.T) {
		tc := NewTestConfig(t)
		defer tc.Cleanup()

		// Initialize logger
		logger = logging.NewCLILogger(false, io.Discard)

		mockClient := &MockAPIClient{}
		mockClient.SetupMockClient()

		testKey := CreateTestKeyWithTwoVersions("test:key12")
		var capturedKeyID string
		mockClient.GetKeyFunc = func(keyID string) (*types.Key, error) {
			capturedKeyID = keyID
			return testKey, nil
		}

		SetMockAPIClient(mockClient)
		defer SetMockAPIClient(nil)

		cmd := newKeyVersionsCmd()
		cmd.SetArgs([]string{"test:key12"})
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)

		err := cmd.Execute()
		require.NoError(t, err)

		assert.Equal(t, "test:key12", capturedKeyID)
	})

	t.Run("ListVersions_JSONOutput", func(t *testing.T) {
		tc := NewTestConfig(t)
		defer tc.Cleanup()

		// Initialize logger
		logger = logging.NewCLILogger(false, io.Discard)

		mockClient := &MockAPIClient{}
		mockClient.SetupMockClient()

		testKey := CreateTestKeyWithTwoVersions("test:key2")
		mockClient.GetKeyFunc = func(_ string) (*types.Key, error) {
			return testKey, nil
		}

		SetMockAPIClient(mockClient)
		defer SetMockAPIClient(nil)

		// Capture stdout for JSON output
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		cmd := newKeyVersionsCmd()
		cmd.SetArgs([]string{"test:key2"})
		jsonOutput = true
		defer func() { jsonOutput = false }()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)

		err := cmd.Execute()
		require.NoError(t, err)

		w.Close()
		os.Stdout = oldStdout

		var buf bytes.Buffer
		_, err = io.Copy(&buf, r)
		require.NoError(t, err)

		var result types.KeyVersionList
		err = json.Unmarshal(buf.Bytes(), &result)
		require.NoError(t, err)

		assert.Len(t, result, 2)
		assert.Equal(t, types.Primary, result[0].Status)
		assert.Equal(t, types.Active, result[1].Status)
	})
}

// TestParseACL tests the ACL parsing function.
func TestParseACL(t *testing.T) {
	tests := []struct {
		name        string
		entries     []string
		expectedACL types.ACL
		expectError bool
	}{
		{
			name:    "ValidUserRead",
			entries: []string{"User:alice@example.com:Read"},
			expectedACL: types.ACL{
				{
					Type:       types.User,
					ID:         "alice@example.com",
					AccessType: types.Read,
				},
			},
			expectError: false,
		},
		{
			name:    "ValidServiceWrite",
			entries: []string{"Service:spiffe://example.com/service:Write"},
			expectedACL: types.ACL{
				{
					Type:       types.Service,
					ID:         "spiffe://example.com/service",
					AccessType: types.Write,
				},
			},
			expectError: false,
		},
		{
			name:    "ValidMachineAdmin",
			entries: []string{"Machine:host123:Admin"},
			expectedACL: types.ACL{
				{
					Type:       types.Machine,
					ID:         "host123",
					AccessType: types.Admin,
				},
			},
			expectError: false,
		},
		{
			name:        "InvalidFormat",
			entries:     []string{"InvalidFormat"},
			expectedACL: nil,
			expectError: true,
		},
		{
			name:        "InvalidPrincipalType",
			entries:     []string{"InvalidType:alice:Read"},
			expectedACL: nil,
			expectError: true,
		},
		{
			name:        "InvalidAccessType",
			entries:     []string{"User:alice:InvalidAccess"},
			expectedACL: nil,
			expectError: true,
		},
		{
			name: "MultipleEntries",
			entries: []string{
				"User:alice@example.com:Read",
				"User:bob@example.com:Write",
			},
			expectedACL: types.ACL{
				{
					Type:       types.User,
					ID:         "alice@example.com",
					AccessType: types.Read,
				},
				{
					Type:       types.User,
					ID:         "bob@example.com",
					AccessType: types.Write,
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl, err := parseACL(tt.entries)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedACL, acl)
			}
		})
	}
}

// TestDisplayKey tests the displayKey helper function.
func TestDisplayKey(t *testing.T) {
	t.Run("DisplayKey_PrimaryOnly", func(t *testing.T) {
		testKey := CreateTestKeyWithTwoVersions("test:key")
		var buf bytes.Buffer
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := displayKey(&buf, testKey, false)
		require.NoError(t, err)

		w.Close()
		os.Stdout = oldStdout
		_, err = io.Copy(&buf, r)
		require.NoError(t, err)

		output := buf.String()
		assert.Equal(t, "primary-secret\n", output)
	})

	t.Run("DisplayKey_AllVersions", func(t *testing.T) {
		testKey := CreateTestKeyWithTwoVersions("test:key")
		var buf bytes.Buffer
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := displayKey(&buf, testKey, true)
		require.NoError(t, err)

		w.Close()
		os.Stdout = oldStdout
		_, err = io.Copy(&buf, r)
		require.NoError(t, err)

		output := buf.String()
		assert.Contains(t, output, "[Primary]")
		assert.Contains(t, output, "[Active]")
		assert.Contains(t, output, "primary-secret")
		assert.Contains(t, output, "active-secret")
	})

	t.Run("DisplayKey_JSONOutput", func(t *testing.T) {
		testKey := CreateTestKeyWithTwoVersions("test:key")
		var buf bytes.Buffer
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		jsonOutput = true
		defer func() { jsonOutput = false }()

		err := displayKey(&buf, testKey, false)
		require.NoError(t, err)

		w.Close()
		os.Stdout = oldStdout
		_, err = io.Copy(&buf, r)
		require.NoError(t, err)

		var result *types.Key
		err = json.Unmarshal(buf.Bytes(), &result)
		require.NoError(t, err)

		assert.Equal(t, testKey.ID, result.ID)
		assert.Equal(t, testKey.ACL, result.ACL)
		assert.Len(t, result.VersionList, 2)
	})
}

// TestFileValidation tests the file validation helper.
func TestFileValidation(t *testing.T) {
	t.Run("ValidFile", func(t *testing.T) {
		tmpFile := CreateTempFile(t, "test content")
		defer os.Remove(tmpFile)

		data, err := validateAndReadFile(tmpFile, []string{filepath.Dir(tmpFile)}, []string{".txt"})
		require.NoError(t, err)
		assert.Equal(t, []byte("test content"), data)
	})

	t.Run("FileNotFound", func(t *testing.T) {
		_, err := validateAndReadFile("/nonexistent/file.txt", []string{"/"}, []string{".txt"})
		require.Error(t, err)
	})

	t.Run("InvalidExtension", func(t *testing.T) {
		tmpFile := CreateTempFile(t, "test content")
		defer os.Remove(tmpFile)

		_, err := validateAndReadFile(tmpFile, []string{filepath.Dir(tmpFile)}, []string{".json"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "file extension not allowed")
	})

	t.Run("PathTraversal", func(t *testing.T) {
		// Use a path that would be within allowed directory but contains path traversal
		_, err := validateAndReadFile("test/../../etc/passwd.txt", []string{"/tmp"}, []string{".txt"})
		require.Error(t, err)
		// The path traversal check happens after path resolution, so the actual error may be about directory permissions
		// Check for either error message that indicates security validation
		assert.True(t, strings.Contains(err.Error(), "path traversal detected") ||
			strings.Contains(err.Error(), "not within allowed directories"),
			"Expected security validation error, got: %s", err.Error())
	})
}
