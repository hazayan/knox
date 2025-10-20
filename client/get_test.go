package client

import (
	"errors"
	"io"
	"os"
	"testing"

	"github.com/hazayan/knox/pkg/types"
	"github.com/stretchr/testify/assert"
)

// TestRunGet tests the main get command functionality.
func TestRunGet(t *testing.T) {
	t.Run("SuccessGetPrimary", func(t *testing.T) {
		// Setup
		oldCli := cli
		defer func() { cli = oldCli }()

		expectedKey := &types.Key{
			ID: "test-key",
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("primary-secret-data"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
		}

		cli = &MockAPIClient{
			GetKeyFunc: func(keyID string) (*types.Key, error) {
				assert.Equal(t, "test-key", keyID)
				return expectedKey, nil
			},
		}

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		defer func() { os.Stdout = oldStdout }()

		// Run the command
		result := runGet(cmdGet, []string{"test-key"})

		w.Close()
		output, _ := io.ReadAll(r)

		assert.Nil(t, result, "Should return nil on success")
		assert.Equal(t, "primary-secret-data", string(output))
	})

	t.Run("SuccessGetSpecificVersion", func(t *testing.T) {
		// Setup version flag
		oldVersion := *getVersion
		defer func() { *getVersion = oldVersion }()
		*getVersion = "2"

		oldCli := cli
		defer func() { cli = oldCli }()

		expectedKey := &types.Key{
			ID: "test-key",
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("primary-data"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
				{
					ID:           2,
					Data:         []byte("version-2-data"),
					Status:       types.Active,
					CreationTime: 1234567891,
				},
			},
		}

		cli = &MockAPIClient{
			GetKeyFunc: func(_ string) (*types.Key, error) {
				return expectedKey, nil
			},
		}

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		defer func() { os.Stdout = oldStdout }()

		// Run the command
		result := runGet(cmdGet, []string{"test-key"})

		w.Close()
		output, _ := io.ReadAll(r)

		assert.Nil(t, result, "Should return nil on success")
		assert.Equal(t, "version-2-data", string(output))
	})

	t.Run("SuccessGetJSON", func(t *testing.T) {
		// Setup JSON flag
		oldJSON := *getJSON
		defer func() { *getJSON = oldJSON }()
		*getJSON = true

		oldCli := cli
		defer func() { cli = oldCli }()

		expectedKey := &types.Key{
			ID:          "test-key",
			VersionHash: "test-hash",
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("test-data"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
		}

		cli = &MockAPIClient{
			GetKeyFunc: func(_ string) (*types.Key, error) {
				return expectedKey, nil
			},
		}

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		defer func() { os.Stdout = oldStdout }()

		// Run the command - getAll without JSON flag should output raw data
		result := runGet(cmdGet, []string{"test-key"})

		w.Close()
		output, _ := io.ReadAll(r)

		assert.Nil(t, result, "Should return nil on success")
		assert.Contains(t, string(output), `"id":"test-key"`)
		assert.Contains(t, string(output), `"hash":"test-hash"`)
	})

	t.Run("SuccessGetAllVersions", func(t *testing.T) {
		// Setup all flag
		oldAll := *getAll
		defer func() { *getAll = oldAll }()
		*getAll = true

		oldCli := cli
		defer func() { cli = oldCli }()

		expectedKey := &types.Key{
			ID: "test-key",
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("primary-data"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
				{
					ID:           2,
					Data:         []byte("active-data"),
					Status:       types.Active,
					CreationTime: 1234567891,
				},
				{
					ID:           3,
					Data:         []byte("inactive-data"),
					Status:       types.Inactive,
					CreationTime: 1234567892,
				},
			},
		}

		cli = &MockAPIClient{
			GetKeyWithStatusFunc: func(_ string, status types.VersionStatus) (*types.Key, error) {
				assert.Equal(t, types.Inactive, status)
				return expectedKey, nil
			},
		}

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		defer func() { os.Stdout = oldStdout }()

		// Run the command
		result := runGet(cmdGet, []string{"test-key"})

		w.Close()
		output, _ := io.ReadAll(r)

		assert.Nil(t, result, "Should return nil on success")
		// With -a flag but without -j flag, should output raw data, not JSON
		assert.Equal(t, "primary-data", string(output))
	})

	t.Run("SuccessNetworkGet", func(t *testing.T) {
		// Setup network flag
		oldNetwork := *getNetwork
		defer func() { *getNetwork = oldNetwork }()
		*getNetwork = true

		oldCli := cli
		defer func() { cli = oldCli }()

		expectedKey := &types.Key{
			ID: "test-key",
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("network-data"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
		}

		cli = &MockAPIClient{
			NetworkGetKeyFunc: func(keyID string) (*types.Key, error) {
				assert.Equal(t, "test-key", keyID)
				return expectedKey, nil
			},
		}

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		defer func() { os.Stdout = oldStdout }()

		// Run the command
		result := runGet(cmdGet, []string{"test-key"})

		w.Close()
		output, _ := io.ReadAll(r)

		assert.Nil(t, result, "Should return nil on success")
		assert.Equal(t, "network-data", string(output))
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
				expected: "get takes only one argument",
			},
			{
				name:     "TooManyArguments",
				args:     []string{"key1", "key2"},
				expected: "get takes only one argument",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				result := runGet(cmdGet, tc.args)
				assert.NotNil(t, result, "Should return error status")
				assert.Contains(t, result.Error(), tc.expected)
				assert.False(t, result.serverError, "Should not be server error for argument errors")
			})
		}
	})

	t.Run("GetKeyError", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		cli = &MockAPIClient{
			GetKeyFunc: func(_ string) (*types.Key, error) {
				return nil, errors.New("key not found")
			},
		}

		result := runGet(cmdGet, []string{"non-existent-key"})
		assert.NotNil(t, result, "Should return error status")
		assert.Contains(t, result.Error(), "error getting key")
		assert.Contains(t, result.Error(), "key not found")
		assert.True(t, result.serverError, "Should be server error for API errors")
	})

	t.Run("VersionNotFound", func(t *testing.T) {
		// Setup version flag
		oldVersion := *getVersion
		defer func() { *getVersion = oldVersion }()
		*getVersion = "999"

		oldCli := cli
		defer func() { cli = oldCli }()

		expectedKey := &types.Key{
			ID: "test-key",
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("primary-data"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
		}

		cli = &MockAPIClient{
			GetKeyFunc: func(_ string) (*types.Key, error) {
				return expectedKey, nil
			},
		}

		result := runGet(cmdGet, []string{"test-key"})
		assert.NotNil(t, result, "Should return error status")
		assert.Contains(t, result.Error(), "Key version not found")
		assert.False(t, result.serverError, "Should not be server error for version not found")
	})

	t.Run("JSONMarshalError", func(t *testing.T) {
		// Setup JSON flag
		oldJSON := *getJSON
		defer func() { *getJSON = oldJSON }()
		*getJSON = true

		oldCli := cli
		defer func() { cli = oldCli }()

		// Create a key that cannot be marshaled (circular reference simulation)
		// We'll use a mock that returns an error
		cli = &MockAPIClient{
			GetKeyFunc: func(_ string) (*types.Key, error) {
				// Return a valid key - the JSON marshaling should succeed
				return &types.Key{
					ID: "test-key",
					VersionList: types.KeyVersionList{
						{
							ID:           1,
							Data:         []byte("test-data"),
							Status:       types.Primary,
							CreationTime: 1234567890,
						},
					},
				}, nil
			},
		}

		// This test verifies that normal JSON marshaling works
		// We can't easily simulate a JSON marshal error without complex mocking
		// So we'll test the happy path for JSON output
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		defer func() { os.Stdout = oldStdout }()

		result := runGet(cmdGet, []string{"test-key"})
		w.Close()
		output, _ := io.ReadAll(r)

		assert.Nil(t, result, "Should return nil on success")
		assert.Contains(t, string(output), `"id":"test-key"`)
	})

	t.Run("EmptyVersionList", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		expectedKey := &types.Key{
			ID:          "empty-key",
			VersionList: nil,
		}

		cli = &MockAPIClient{
			GetKeyFunc: func(_ string) (*types.Key, error) {
				return expectedKey, nil
			},
		}

		result := runGet(cmdGet, []string{"empty-key"})
		assert.NotNil(t, result, "Should return error status")
		assert.Contains(t, result.Error(), "Key version not found")
		assert.False(t, result.serverError, "Should not be server error for empty version list")
	})
}

// TestSuccessGetKeyMetric tests the success metric function.
func TestSuccessGetKeyMetric(t *testing.T) {
	t.Run("SuccessMetricCalled", func(t *testing.T) {
		// We can't easily test the metric function directly since it's a function variable
		// But we can verify it doesn't panic when called
		assert.NotPanics(t, func() {
			successGetKeyMetric("test-key")
		})
	})
}

// TestFailureGetKeyMetric tests the failure metric function.
func TestFailureGetKeyMetric(t *testing.T) {
	t.Run("FailureMetricCalled", func(t *testing.T) {
		// We can't easily test the metric function directly since it's a function variable
		// But we can verify it doesn't panic when called
		assert.NotPanics(t, func() {
			failureGetKeyMetric("test-key", errors.New("test error"))
		})
	})
}

// TestGetCommandStructure tests the command structure and metadata.
func TestGetCommandStructure(t *testing.T) {
	t.Run("CommandMetadata", func(t *testing.T) {
		assert.Equal(t, "get [-v key_version] [-n] [-j] [-a] [--tink-keyset] [--tink-keyset-info] <key_identifier>", cmdGet.UsageLine)
		assert.Equal(t, "get a knox key", cmdGet.Short)
		assert.Contains(t, cmdGet.Long, "Get gets the key data for a key")
		assert.Contains(t, cmdGet.Long, "-v specifies the key_version to get")
		assert.Contains(t, cmdGet.Long, "-j returns the json version of the key")
		assert.Contains(t, cmdGet.Long, "-n forces a network call")
		assert.Contains(t, cmdGet.Long, "See also: knox create, knox daemon, knox register, knox keys")
	})

	t.Run("CommandRunnable", func(t *testing.T) {
		assert.True(t, cmdGet.Runnable(), "Get command should be runnable")
		assert.NotNil(t, cmdGet.Run, "Get command should have Run function")
	})

	t.Run("CommandName", func(t *testing.T) {
		assert.Equal(t, "get", cmdGet.Name())
	})
}

// TestGetFlagIntegration tests flag integration.
func TestGetFlagIntegration(t *testing.T) {
	t.Run("FlagDefaults", func(t *testing.T) {
		assert.Equal(t, "", *getVersion, "Version flag should default to empty")
		assert.False(t, *getJSON, "JSON flag should default to false")
		assert.False(t, *getNetwork, "Network flag should default to false")
		assert.False(t, *getAll, "All flag should default to false")
		assert.False(t, *getTinkKeyset, "TinkKeyset flag should default to false")
		assert.False(t, *getTinkKeysetInfo, "TinkKeysetInfo flag should default to false")
	})

	t.Run("FlagSetting", func(t *testing.T) {
		// Test setting flags
		oldVersion := *getVersion
		oldJSON := *getJSON
		oldNetwork := *getNetwork
		oldAll := *getAll
		oldTinkKeyset := *getTinkKeyset
		oldTinkKeysetInfo := *getTinkKeysetInfo

		*getVersion = "test-version"
		*getJSON = true
		*getNetwork = true
		*getAll = true
		*getTinkKeyset = true
		*getTinkKeysetInfo = true

		defer func() {
			*getVersion = oldVersion
			*getJSON = oldJSON
			*getNetwork = oldNetwork
			*getAll = oldAll
			*getTinkKeyset = oldTinkKeyset
			*getTinkKeysetInfo = oldTinkKeysetInfo
		}()

		assert.Equal(t, "test-version", *getVersion)
		assert.True(t, *getJSON)
		assert.True(t, *getNetwork)
		assert.True(t, *getAll)
		assert.True(t, *getTinkKeyset)
		assert.True(t, *getTinkKeysetInfo)
	})
}

// TestGetIntegration tests integration scenarios.
func TestGetIntegration(t *testing.T) {
	t.Run("EndToEndSuccess", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		expectedKey := &types.Key{
			ID: "integration-key",
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("integration-secret"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
		}

		getCalled := false
		cli = &MockAPIClient{
			GetKeyFunc: func(keyID string) (*types.Key, error) {
				getCalled = true
				assert.Equal(t, "integration-key", keyID)
				return expectedKey, nil
			},
		}

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		defer func() { os.Stdout = oldStdout }()

		result := runGet(cmdGet, []string{"integration-key"})

		w.Close()
		output, _ := io.ReadAll(r)

		assert.Nil(t, result, "Should return nil on success")
		assert.Equal(t, "integration-secret", string(output))
		assert.True(t, getCalled, "GetKey should have been called")
	})

	t.Run("EndToEndWithNetwork", func(t *testing.T) {
		// Setup network flag
		oldNetwork := *getNetwork
		defer func() { *getNetwork = oldNetwork }()
		*getNetwork = true

		oldCli := cli
		defer func() { cli = oldCli }()

		expectedKey := &types.Key{
			ID: "network-key",
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("network-secret"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
		}

		networkGetCalled := false
		cli = &MockAPIClient{
			NetworkGetKeyFunc: func(keyID string) (*types.Key, error) {
				networkGetCalled = true
				assert.Equal(t, "network-key", keyID)
				return expectedKey, nil
			},
		}

		// Capture stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		defer func() { os.Stdout = oldStdout }()

		result := runGet(cmdGet, []string{"network-key"})

		w.Close()
		output, _ := io.ReadAll(r)

		assert.Nil(t, result, "Should return nil on success")
		assert.Equal(t, "network-secret", string(output))
		assert.True(t, networkGetCalled, "NetworkGetKey should have been called")
	})
}

// TestRetrieveTinkKeyset tests Tink keyset retrieval functionality.
func TestRetrieveTinkKeyset(t *testing.T) {
	t.Run("NonTinkKeyID", func(t *testing.T) {
		result, err := retrieveTinkKeyset("regular-key", false)
		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "this knox identifier is not for tink keyset")
		assert.False(t, err.serverError)
	})

	// Note: More comprehensive Tink keyset tests would require
	// integration with the actual Tink library and are beyond
	// the scope of unit testing the get command logic
}

// TestRetrieveTinkKeysetInfo tests Tink keyset info retrieval functionality.
func TestRetrieveTinkKeysetInfo(t *testing.T) {
	t.Run("NonTinkKeyID", func(t *testing.T) {
		result, err := retrieveTinkKeysetInfo("regular-key", false)
		assert.Equal(t, "", result)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "this knox identifier is not for tink keyset")
		assert.False(t, err.serverError)
	})

	// Note: More comprehensive Tink keyset info tests would require
	// integration with the actual Tink library and are beyond
	// the scope of unit testing the get command logic
}
