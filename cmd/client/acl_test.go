package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/hazayan/knox/pkg/observability/logging"
	"github.com/hazayan/knox/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestACLCommands(t *testing.T) {
	t.Run("ACLGetCommand", func(t *testing.T) {
		t.Run("GetACL_Success", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			// Initialize logger
			logger = logging.NewCLILogger(false, io.Discard)

			mockClient := &MockAPIClient{}
			mockClient.SetupMockClient()

			expectedACL := types.ACL{
				{
					ID:         "user@example.com",
					Type:       types.User,
					AccessType: types.Read,
				},
				{
					ID:         "service:myservice",
					Type:       types.Service,
					AccessType: types.Write,
				},
			}

			mockClient.GetACLFunc = func(keyID string) (*types.ACL, error) {
				if keyID != "testkey" {
					return nil, assert.AnError
				}
				return &expectedACL, nil
			}

			SetMockAPIClient(mockClient)
			defer SetMockAPIClient(nil)

			cmd := newACLGetCmd()
			cmd.SetArgs([]string{"testkey"})
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)

			err := cmd.Execute()
			assert.NoError(t, err)

			// Note: The output goes to stdout, not the logger
			// The actual output verification would depend on the command implementation
			_ = buf.String() // Capture but don't verify output in this test
		})

		t.Run("GetACL_JSONOutput", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			logger = logging.NewCLILogger(false, io.Discard)

			mockClient := &MockAPIClient{}
			mockClient.SetupMockClient()

			expectedACL := types.ACL{
				{
					ID:         "user@example.com",
					Type:       types.User,
					AccessType: types.Read,
				},
			}

			mockClient.GetACLFunc = func(_ string) (*types.ACL, error) {
				return &expectedACL, nil
			}

			SetMockAPIClient(mockClient)
			defer SetMockAPIClient(nil)

			// Capture stdout for JSON output
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			cmd := newACLGetCmd()
			cmd.SetArgs([]string{"testkey"})
			jsonOutput = true
			defer func() { jsonOutput = false }()
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)

			err := cmd.Execute()
			assert.NoError(t, err)

			w.Close()
			os.Stdout = oldStdout

			var buf bytes.Buffer
			_, err = io.Copy(&buf, r)
			assert.NoError(t, err)

			var result types.ACL
			err = json.Unmarshal(buf.Bytes(), &result)
			assert.NoError(t, err)

			assert.Len(t, result, 1)
			assert.Equal(t, "user@example.com", result[0].ID)
		})

		t.Run("GetACL_ClientError", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			logger = logging.NewCLILogger(false, io.Discard)

			mockClient := &MockAPIClient{}
			mockClient.SetupMockClient()

			mockClient.GetACLFunc = func(_ string) (*types.ACL, error) {
				return nil, assert.AnError
			}

			SetMockAPIClient(mockClient)
			defer SetMockAPIClient(nil)

			cmd := newACLGetCmd()
			cmd.SetArgs([]string{"testkey"})
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)

			err := cmd.Execute()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failed to get ACL")
		})

		t.Run("GetACL_NoACLEntries", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			logger = logging.NewCLILogger(false, io.Discard)

			mockClient := &MockAPIClient{}
			mockClient.SetupMockClient()

			emptyACL := types.ACL{}

			mockClient.GetACLFunc = func(_ string) (*types.ACL, error) {
				return &emptyACL, nil
			}

			SetMockAPIClient(mockClient)
			defer SetMockAPIClient(nil)

			cmd := newACLGetCmd()
			cmd.SetArgs([]string{"testkey"})
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)

			err := cmd.Execute()
			assert.NoError(t, err)

			// Note: The output goes to stdout, not the logger
			_ = buf.String() // Capture but don't verify output in this test
		})
	})

	t.Run("ACLAddCommand", func(t *testing.T) {
		t.Run("AddACL_Success", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			logger = logging.NewCLILogger(false, io.Discard)

			mockClient := &MockAPIClient{}
			mockClient.SetupMockClient()

			var capturedKeyID string
			var capturedACL types.Access

			mockClient.PutAccessFunc = func(keyID string, access ...types.Access) error {
				if len(access) > 0 {
					capturedKeyID = keyID
					capturedACL = access[0]
				}
				return nil
			}

			SetMockAPIClient(mockClient)
			defer SetMockAPIClient(nil)

			cmd := newACLAddCmd()
			cmd.SetArgs([]string{"testkey", "User:alice@example.com:Read"})
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)

			err := cmd.Execute()
			assert.NoError(t, err)

			assert.Equal(t, "testkey", capturedKeyID)
			assert.Equal(t, "alice@example.com", capturedACL.ID)

			assert.EqualValues(t, types.User, capturedACL.Type)
			assert.EqualValues(t, types.Read, capturedACL.AccessType)
		})

		t.Run("AddACL_JSONOutput", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			logger = logging.NewCLILogger(false, io.Discard)

			mockClient := &MockAPIClient{}
			mockClient.SetupMockClient()

			mockClient.PutAccessFunc = func(_ string, _ ...types.Access) error {
				return nil
			}

			SetMockAPIClient(mockClient)
			defer SetMockAPIClient(nil)

			// Capture stdout for JSON output
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			cmd := newACLAddCmd()
			cmd.SetArgs([]string{"testkey", "User:alice@example.com:Read"})
			jsonOutput = true
			defer func() { jsonOutput = false }()
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)

			err := cmd.Execute()
			assert.NoError(t, err)

			w.Close()
			os.Stdout = oldStdout

			var buf bytes.Buffer
			_, err = io.Copy(&buf, r)
			assert.NoError(t, err)

			var result map[string]any
			err = json.Unmarshal(buf.Bytes(), &result)
			assert.NoError(t, err)

			assert.Equal(t, "testkey", result["key_id"])
			assert.Equal(t, "added", result["status"])
		})

		t.Run("AddACL_InvalidFormat", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			logger = logging.NewCLILogger(false, io.Discard)

			cmd := newACLAddCmd()
			cmd.SetArgs([]string{"testkey", "InvalidFormat"})
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)

			err := cmd.Execute()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid ACL entry format")
		})

		t.Run("AddACL_ClientError", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			logger = logging.NewCLILogger(false, io.Discard)

			mockClient := &MockAPIClient{}
			mockClient.SetupMockClient()

			mockClient.PutAccessFunc = func(_ string, _ ...types.Access) error {
				return assert.AnError
			}

			SetMockAPIClient(mockClient)
			defer SetMockAPIClient(nil)

			cmd := newACLAddCmd()
			cmd.SetArgs([]string{"testkey", "User:alice@example.com:Read"})
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)

			err := cmd.Execute()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failed to add ACL entry")
		})
	})

	t.Run("ACLRemoveCommand", func(t *testing.T) {
		t.Run("RemoveACL_Success", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			logger = logging.NewCLILogger(false, io.Discard)

			mockClient := &MockAPIClient{}
			mockClient.SetupMockClient()

			var capturedKeyID string
			var capturedACL types.Access

			mockClient.PutAccessFunc = func(keyID string, access ...types.Access) error {
				if len(access) > 0 {
					capturedKeyID = keyID
					capturedACL = access[0]
				}
				return nil
			}

			SetMockAPIClient(mockClient)
			defer SetMockAPIClient(nil)

			cmd := newACLRemoveCmd()
			cmd.SetArgs([]string{"testkey", "User:alice@example.com"})
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)

			err := cmd.Execute()
			assert.NoError(t, err)

			assert.Equal(t, "testkey", capturedKeyID)
			assert.Equal(t, "alice@example.com", capturedACL.ID)

			assert.EqualValues(t, types.User, capturedACL.Type)
			assert.EqualValues(t, types.None, capturedACL.AccessType)
		})

		t.Run("RemoveACL_JSONOutput", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			logger = logging.NewCLILogger(false, io.Discard)

			mockClient := &MockAPIClient{}
			mockClient.SetupMockClient()

			mockClient.PutAccessFunc = func(_ string, _ ...types.Access) error {
				return nil
			}

			SetMockAPIClient(mockClient)
			defer SetMockAPIClient(nil)

			// Capture stdout for JSON output
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			cmd := newACLRemoveCmd()
			cmd.SetArgs([]string{"testkey", "User:alice@example.com"})
			jsonOutput = true
			defer func() { jsonOutput = false }()
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)

			err := cmd.Execute()
			assert.NoError(t, err)

			w.Close()
			os.Stdout = oldStdout

			var buf bytes.Buffer
			_, err = io.Copy(&buf, r)
			assert.NoError(t, err)

			var result map[string]any
			err = json.Unmarshal(buf.Bytes(), &result)
			assert.NoError(t, err)

			assert.Equal(t, "testkey", result["key_id"])
			assert.Equal(t, "removed", result["status"])
		})

		t.Run("RemoveACL_InvalidFormat", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			logger = logging.NewCLILogger(false, io.Discard)

			cmd := newACLRemoveCmd()
			cmd.SetArgs([]string{"testkey", "InvalidFormat"})
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)

			err := cmd.Execute()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid ACL entry format")
		})

		t.Run("RemoveACL_ClientError", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			logger = logging.NewCLILogger(false, io.Discard)

			mockClient := &MockAPIClient{}
			mockClient.SetupMockClient()

			mockClient.PutAccessFunc = func(_ string, _ ...types.Access) error {
				return assert.AnError
			}

			SetMockAPIClient(mockClient)
			defer SetMockAPIClient(nil)

			cmd := newACLRemoveCmd()
			cmd.SetArgs([]string{"testkey", "User:alice@example.com"})
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)

			err := cmd.Execute()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "failed to remove ACL entry")
		})
	})

	t.Run("ACLCommandValidation", func(t *testing.T) {
		t.Run("ACLGet_NoArgs", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			logger = logging.NewCLILogger(false, io.Discard)

			cmd := newACLGetCmd()
			cmd.SetArgs([]string{})
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)

			err := cmd.Execute()
			assert.Error(t, err)
		})

		t.Run("ACLAdd_NoArgs", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			logger = logging.NewCLILogger(false, io.Discard)

			cmd := newACLAddCmd()
			cmd.SetArgs([]string{})
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)

			err := cmd.Execute()
			assert.Error(t, err)
		})

		t.Run("ACLRemove_NoArgs", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			logger = logging.NewCLILogger(false, io.Discard)

			cmd := newACLRemoveCmd()
			cmd.SetArgs([]string{})
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)

			err := cmd.Execute()
			assert.Error(t, err)
		})
	})
}

func TestACLParsing(t *testing.T) {
	tests := []struct {
		name        string
		input       []string
		expected    types.ACL
		expectError bool
	}{
		{
			name:  "ValidUserRead",
			input: []string{"User:alice@example.com:Read"},
			expected: types.ACL{
				{
					ID:         "alice@example.com",
					Type:       types.User,
					AccessType: types.Read,
				},
			},
			expectError: false,
		},
		{
			name:  "ValidServiceWrite",
			input: []string{"Service:spiffe://example.com/myservice:Write"},
			expected: types.ACL{
				{
					ID:         "spiffe://example.com/myservice",
					Type:       types.Service,
					AccessType: types.Write,
				},
			},
			expectError: false,
		},
		{
			name:  "ValidUserGroupAdmin",
			input: []string{"UserGroup:developers:Admin"},
			expected: types.ACL{
				{
					ID:         "developers",
					Type:       types.UserGroup,
					AccessType: types.Admin,
				},
			},
			expectError: false,
		},
		{
			name:        "InvalidFormat",
			input:       []string{"InvalidFormat"},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "EmptyParts",
			input:       []string{"::"},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "InvalidType",
			input:       []string{"InvalidType:principal:Read"},
			expected:    nil,
			expectError: true,
		},
		{
			name:        "InvalidAccessType",
			input:       []string{"User:alice@example.com:InvalidAccess"},
			expected:    nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseACL(tt.input)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Len(t, result, len(tt.expected))

			for i, expected := range tt.expected {
				assert.Equal(t, expected.ID, result[i].ID)
				assert.Equal(t, expected.Type, result[i].Type)
				assert.Equal(t, expected.AccessType, result[i].AccessType)
			}
		})
	}
}
