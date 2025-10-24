package client

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRunGetKeys(t *testing.T) {
	t.Run("SuccessWithNoArguments", func(t *testing.T) {
		// Setup
		oldCli := cli
		defer func() { cli = oldCli }()

		expectedKeys := []string{"key1", "key2", "key3"}

		cli = &MockAPIClient{
			GetKeysFunc: func(m map[string]string) ([]string, error) {
				assert.Equal(t, map[string]string{}, m)
				return expectedKeys, nil
			},
		}

		// Capture log output
		var logOutput bytes.Buffer
		log.SetOutput(&logOutput)
		defer log.SetOutput(os.Stderr)

		// Execute
		err := runGetKeys(nil, []string{})

		// Verify
		assert.Nil(t, err)
		assert.Contains(t, logOutput.String(), "key1")
		assert.Contains(t, logOutput.String(), "key2")
		assert.Contains(t, logOutput.String(), "key3")
	})

	t.Run("SuccessWithVersionIDs", func(t *testing.T) {
		// Setup
		oldCli := cli
		defer func() { cli = oldCli }()

		versionIDs := []string{"v1", "v2", "v3"}
		expectedKeys := []string{"key1", "key2"}

		cli = &MockAPIClient{
			GetKeysFunc: func(m map[string]string) ([]string, error) {
				assert.Equal(t, map[string]string{
					"v1": "NONE",
					"v2": "NONE",
					"v3": "NONE",
				}, m)
				return expectedKeys, nil
			},
		}

		// Capture log output
		var logOutput bytes.Buffer
		log.SetOutput(&logOutput)
		defer log.SetOutput(os.Stderr)

		// Execute
		err := runGetKeys(nil, versionIDs)

		// Verify
		assert.Nil(t, err)
		assert.Contains(t, logOutput.String(), "key1")
		assert.Contains(t, logOutput.String(), "key2")
	})

	t.Run("GetKeysAPIError", func(t *testing.T) {
		// Setup
		oldCli := cli
		defer func() { cli = oldCli }()

		expectedError := errors.New("API error: authentication failed")

		cli = &MockAPIClient{
			GetKeysFunc: func(_ map[string]string) ([]string, error) {
				return nil, expectedError
			},
		}

		// Execute
		err := runGetKeys(nil, []string{})

		// Verify
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error getting keys: API error: authentication failed")
		assert.True(t, err.serverError)
	})

	t.Run("EmptyResult", func(t *testing.T) {
		// Setup
		oldCli := cli
		defer func() { cli = oldCli }()

		cli = &MockAPIClient{
			GetKeysFunc: func(_ map[string]string) ([]string, error) {
				return []string{}, nil
			},
		}

		// Capture log output
		var logOutput bytes.Buffer
		log.SetOutput(&logOutput)
		defer log.SetOutput(os.Stderr)

		// Execute
		err := runGetKeys(nil, []string{})

		// Verify
		assert.Nil(t, err)
		assert.Empty(t, logOutput.String())
	})

	t.Run("SingleKeyResult", func(t *testing.T) {
		// Setup
		oldCli := cli
		defer func() { cli = oldCli }()

		singleKey := []string{"single-key"}

		cli = &MockAPIClient{
			GetKeysFunc: func(_ map[string]string) ([]string, error) {
				return singleKey, nil
			},
		}

		// Capture log output
		var logOutput bytes.Buffer
		log.SetOutput(&logOutput)
		defer log.SetOutput(os.Stderr)

		// Execute
		err := runGetKeys(nil, []string{})

		// Verify
		assert.Nil(t, err)
		assert.Contains(t, logOutput.String(), "single-key")
	})
}

func TestGetKeysCommandStructure(t *testing.T) {
	t.Run("CommandMetadata", func(t *testing.T) {
		assert.Equal(t, "keys [<version_id> ...]", cmdGetKeys.UsageLine)
		assert.Equal(t, "gets keys and associated version hash", cmdGetKeys.Short)
		assert.Contains(t, cmdGetKeys.Long, "Get Keys takes version ids returns matching key ids if they exist")
		assert.Contains(t, cmdGetKeys.Long, "If no version ids are given, it returns all key ids")
	})

	t.Run("CommandRunnable", func(t *testing.T) {
		assert.True(t, cmdGetKeys.Runnable())
	})

	t.Run("CommandName", func(t *testing.T) {
		assert.Equal(t, "keys", cmdGetKeys.Name())
	})
}

func TestGetKeysCommandIntegration(t *testing.T) {
	t.Run("EndToEndSuccess", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		// Setup mock client with realistic key data
		expectedKeys := []string{
			"production-database-key",
			"staging-api-key",
			"development-secret",
		}

		cli = &MockAPIClient{
			GetKeysFunc: func(_ map[string]string) ([]string, error) {
				return expectedKeys, nil
			},
		}

		// Capture log output
		var logOutput bytes.Buffer
		log.SetOutput(&logOutput)
		defer log.SetOutput(os.Stderr)

		// Execute
		err := runGetKeys(nil, []string{})

		// Verify
		assert.Nil(t, err)
		assert.Contains(t, logOutput.String(), "production-database-key")
		assert.Contains(t, logOutput.String(), "staging-api-key")
		assert.Contains(t, logOutput.String(), "development-secret")
	})

	t.Run("WithSpecificVersionIDs", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		versionIDs := []string{"12345", "67890"}
		expectedKeys := []string{"matching-key"}

		cli = &MockAPIClient{
			GetKeysFunc: func(m map[string]string) ([]string, error) {
				assert.Equal(t, map[string]string{
					"12345": "NONE",
					"67890": "NONE",
				}, m)
				return expectedKeys, nil
			},
		}

		// Capture log output
		var logOutput bytes.Buffer
		log.SetOutput(&logOutput)
		defer log.SetOutput(os.Stderr)

		// Execute
		err := runGetKeys(nil, versionIDs)

		// Verify
		assert.Nil(t, err)
		assert.Contains(t, logOutput.String(), "matching-key")
	})

	t.Run("ConcurrentGetKeysCalls", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		callCount := 0
		cli = &MockAPIClient{
			GetKeysFunc: func(_ map[string]string) ([]string, error) {
				callCount++
				return []string{fmt.Sprintf("key-%d", callCount)}, nil
			},
		}

		// Test multiple sequential calls
		testCases := [][]string{
			{},
			{"v1"},
			{"v1", "v2"},
		}

		for i, args := range testCases {
			err := runGetKeys(nil, args)
			assert.Nil(t, err, "Test case %d failed", i)
		}

		assert.Equal(t, 3, callCount)
	})
}

func TestGetKeysCommandEdgeCases(t *testing.T) {
	t.Run("DuplicateVersionIDs", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		versionIDs := []string{"v1", "v1", "v2"} // Duplicate v1

		cli = &MockAPIClient{
			GetKeysFunc: func(m map[string]string) ([]string, error) {
				// Should still have unique entries in the map
				assert.Equal(t, map[string]string{
					"v1": "NONE",
					"v2": "NONE",
				}, m)
				return []string{"test-key"}, nil
			},
		}

		err := runGetKeys(nil, versionIDs)
		assert.Nil(t, err)
	})

	t.Run("EmptyVersionID", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		versionIDs := []string{""} // Empty version ID

		cli = &MockAPIClient{
			GetKeysFunc: func(m map[string]string) ([]string, error) {
				assert.Equal(t, map[string]string{
					"": "NONE",
				}, m)
				return []string{}, nil
			},
		}

		err := runGetKeys(nil, versionIDs)
		assert.Nil(t, err)
	})

	t.Run("LargeNumberOfVersionIDs", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		// Create many version IDs
		versionIDs := make([]string, 100)
		for i := range 100 {
			versionIDs[i] = fmt.Sprintf("version-%d", i)
		}

		cli = &MockAPIClient{
			GetKeysFunc: func(m map[string]string) ([]string, error) {
				assert.Equal(t, 100, len(m))
				return []string{"large-test-key"}, nil
			},
		}

		err := runGetKeys(nil, versionIDs)
		assert.Nil(t, err)
	})

	t.Run("SpecialCharactersInVersionIDs", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		specialVersionIDs := []string{"version:1.2.3", "version_with_underscore", "version-with-dash"}

		cli = &MockAPIClient{
			GetKeysFunc: func(m map[string]string) ([]string, error) {
				assert.Equal(t, map[string]string{
					"version:1.2.3":           "NONE",
					"version_with_underscore": "NONE",
					"version-with-dash":       "NONE",
				}, m)
				return []string{"special-key"}, nil
			},
		}

		err := runGetKeys(nil, specialVersionIDs)
		assert.Nil(t, err)
	})
}
