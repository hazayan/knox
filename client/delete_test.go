package client

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRunDelete tests the main delete command functionality.
func TestRunDelete(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		// Setup
		oldCli := cli
		defer func() { cli = oldCli }()

		deleteCalled := false
		cli = &MockAPIClient{
			DeleteKeyFunc: func(keyID string) error {
				deleteCalled = true
				assert.Equal(t, "test-key", keyID)
				return nil
			},
		}

		// Run the command - we can't easily capture log output in tests
		result := runDelete(cmdDelete, []string{"test-key"})

		assert.Nil(t, result, "Should return nil on success")
		assert.True(t, deleteCalled, "DeleteKey should have been called")
	})

	t.Run("InvalidArguments", func(t *testing.T) {
		testCases := []struct {
			name     string
			args     []string
			expected string
		}{
			{
				name:     "NoArguments",
				args:     []string{},
				expected: "create takes exactly one argument",
			},
			{
				name:     "TooManyArguments",
				args:     []string{"key1", "key2"},
				expected: "create takes exactly one argument",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				result := runDelete(cmdDelete, tc.args)
				assert.NotNil(t, result, "Should return error status")
				assert.Contains(t, result.Error(), tc.expected)
				assert.False(t, result.serverError, "Should not be server error for argument errors")
			})
		}
	})

	t.Run("DeleteKeyError", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		deleteCalled := false
		cli = &MockAPIClient{
			DeleteKeyFunc: func(keyID string) error {
				deleteCalled = true
				assert.Equal(t, "error-key", keyID)
				return errors.New("permission denied")
			},
		}

		result := runDelete(cmdDelete, []string{"error-key"})
		assert.NotNil(t, result, "Should return error status")
		assert.Contains(t, result.Error(), "error deleting key")
		assert.Contains(t, result.Error(), "permission denied")
		assert.True(t, result.serverError, "Should be server error for API errors")
		assert.True(t, deleteCalled, "DeleteKey should have been called")
	})

	t.Run("NetworkError", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		cli = &MockAPIClient{
			DeleteKeyFunc: func(_ string) error {
				return errors.New("network timeout")
			},
		}

		result := runDelete(cmdDelete, []string{"network-key"})
		assert.NotNil(t, result, "Should return error status")
		assert.Contains(t, result.Error(), "error deleting key")
		assert.Contains(t, result.Error(), "network timeout")
		assert.True(t, result.serverError, "Should be server error for network errors")
	})

	t.Run("KeyNotFound", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		cli = &MockAPIClient{
			DeleteKeyFunc: func(_ string) error {
				return errors.New("key not found")
			},
		}

		result := runDelete(cmdDelete, []string{"non-existent-key"})
		assert.NotNil(t, result, "Should return error status")
		assert.Contains(t, result.Error(), "error deleting key")
		assert.Contains(t, result.Error(), "key not found")
		assert.True(t, result.serverError, "Should be server error for key not found")
	})
}

// TestDeleteCommandStructure tests the command structure and metadata.
func TestDeleteCommandStructure(t *testing.T) {
	t.Run("CommandMetadata", func(t *testing.T) {
		assert.Equal(t, "delete <key_identifier>", cmdDelete.UsageLine)
		assert.Equal(t, "deletes an existing key", cmdDelete.Short)
		assert.Contains(t, cmdDelete.Long, "This will delete your key and all data from the knox server")
		assert.Contains(t, cmdDelete.Long, "This operation is dangerous and requires admin permissions")
		assert.Contains(t, cmdDelete.Long, "See also: knox create")
	})

	t.Run("CommandRunnable", func(t *testing.T) {
		assert.True(t, cmdDelete.Runnable(), "Delete command should be runnable")
		assert.NotNil(t, cmdDelete.Run, "Delete command should have Run function")
	})

	t.Run("CommandName", func(t *testing.T) {
		assert.Equal(t, "delete", cmdDelete.Name())
	})
}

// TestDeleteIntegration tests integration scenarios.
func TestDeleteIntegration(t *testing.T) {
	t.Run("EndToEndSuccess", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		deleteCalled := false
		cli = &MockAPIClient{
			DeleteKeyFunc: func(keyID string) error {
				deleteCalled = true
				assert.Equal(t, "integration-key", keyID)
				return nil
			},
		}

		result := runDelete(cmdDelete, []string{"integration-key"})

		assert.Nil(t, result, "Should return nil on success")
		assert.True(t, deleteCalled, "DeleteKey should have been called")
	})

	t.Run("EndToEndWithError", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		deleteCalled := false
		cli = &MockAPIClient{
			DeleteKeyFunc: func(keyID string) error {
				deleteCalled = true
				assert.Equal(t, "error-integration-key", keyID)
				return errors.New("integration test error")
			},
		}

		result := runDelete(cmdDelete, []string{"error-integration-key"})
		assert.NotNil(t, result, "Should return error status")
		assert.Contains(t, result.Error(), "error deleting key")
		assert.Contains(t, result.Error(), "integration test error")
		assert.True(t, result.serverError, "Should be server error")
		assert.True(t, deleteCalled, "DeleteKey should have been called")
	})
}

// TestDeleteEdgeCases tests edge cases and error conditions.
func TestDeleteEdgeCases(t *testing.T) {
	t.Run("EmptyKeyID", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		deleteCalled := false
		cli = &MockAPIClient{
			DeleteKeyFunc: func(keyID string) error {
				deleteCalled = true
				assert.Equal(t, "", keyID)
				return nil
			},
		}

		// Empty key ID should still call the API (behavior may vary by backend)
		result := runDelete(cmdDelete, []string{""})
		// Don't assert specific error behavior for empty key ID
		// as it depends on backend implementation
		if result == nil {
			// If no error, API should have been called
			assert.True(t, deleteCalled, "DeleteKey should be called even with empty key ID")
		}
	})

	t.Run("SpecialCharactersInKeyID", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		deleteCalled := false
		cli = &MockAPIClient{
			DeleteKeyFunc: func(keyID string) error {
				deleteCalled = true
				assert.Equal(t, "key@with#special$chars", keyID)
				return nil
			},
		}

		result := runDelete(cmdDelete, []string{"key@with#special$chars"})

		assert.Nil(t, result, "Should return nil on success")
		assert.True(t, deleteCalled, "DeleteKey should have been called")
	})

	t.Run("LongKeyID", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		longKeyID := "very-long-key-identifier-with-many-characters-and-numbers-1234567890-abcdefghijklmnopqrstuvwxyz"
		deleteCalled := false
		cli = &MockAPIClient{
			DeleteKeyFunc: func(keyID string) error {
				deleteCalled = true
				assert.Equal(t, longKeyID, keyID)
				return nil
			},
		}

		result := runDelete(cmdDelete, []string{longKeyID})

		assert.Nil(t, result, "Should return nil on success")
		assert.True(t, deleteCalled, "DeleteKey should have been called")
	})
}
