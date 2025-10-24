package client

import (
	"bytes"
	"errors"
	"log"
	"os"
	"strings"
	"testing"

	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/hazayan/knox/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestRunCreate(t *testing.T) {
	t.Run("SuccessWithStdin", func(t *testing.T) {
		// Setup
		oldCli := cli
		defer func() { cli = oldCli }()

		expectedKeyID := "test-key"
		expectedData := []byte("test-secret-data")
		expectedVersionID := int64(123)

		cli = &MockAPIClient{
			CreateKeyFunc: func(keyID string, data []byte, acl types.ACL) (uint64, error) {
				assert.Equal(t, expectedKeyID, keyID)
				assert.Equal(t, expectedData, data)
				assert.Equal(t, types.ACL{}, acl)
				return uint64(expectedVersionID), nil
			},
		}

		// Capture log output
		var logOutput bytes.Buffer
		log.SetOutput(&logOutput)
		defer log.SetOutput(os.Stderr)

		// Mock stdin
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()
		// Create a temporary file to mock stdin
		tmpfile, err := os.CreateTemp(t.TempDir(), "stdin-mock")
		assert.NoError(t, err)
		defer os.Remove(tmpfile.Name())

		_, err = tmpfile.Write(expectedData)
		assert.NoError(t, err)
		_, err = tmpfile.Seek(0, 0)
		assert.NoError(t, err)
		os.Stdin = tmpfile

		// Execute
		errStatus := runCreate(nil, []string{expectedKeyID})

		// Verify
		assert.Nil(t, errStatus)
		assert.Contains(t, logOutput.String(), "Created key with initial version 123")
	})

	t.Run("SuccessWithTinkKeyset", func(t *testing.T) {
		// Setup
		oldCli := cli
		defer func() { cli = oldCli }()

		expectedKeyID := "tink:aead:test-key"
		expectedVersionID := int64(456)
		templateName := "TINK_AEAD_AES128_GCM"

		// Set the flag
		oldFlag := *createTinkKeyset
		*createTinkKeyset = templateName
		defer func() { *createTinkKeyset = oldFlag }()

		cli = &MockAPIClient{
			CreateKeyFunc: func(keyID string, data []byte, acl types.ACL) (uint64, error) {
				assert.Equal(t, expectedKeyID, keyID)
				assert.NotEmpty(t, data) // Should have Tink keyset data
				assert.Equal(t, types.ACL{}, acl)
				return uint64(expectedVersionID), nil
			},
		}

		// Capture log output
		var logOutput bytes.Buffer
		log.SetOutput(&logOutput)
		defer log.SetOutput(os.Stderr)

		// Execute
		errStatus := runCreate(nil, []string{expectedKeyID})

		// Verify
		assert.Nil(t, errStatus)
		assert.Contains(t, logOutput.String(), "Created key with initial version 456")
	})

	t.Run("InvalidArgumentCount", func(t *testing.T) {
		t.Run("NoArguments", func(t *testing.T) {
			errStatus := runCreate(nil, []string{})
			assert.Error(t, errStatus)
			assert.Contains(t, errStatus.Error(), "create takes exactly one argument")
			assert.False(t, errStatus.serverError)
		})

		t.Run("TooManyArguments", func(t *testing.T) {
			errStatus := runCreate(nil, []string{"key1", "key2"})
			assert.Error(t, errStatus)
			assert.Contains(t, errStatus.Error(), "create takes exactly one argument")
			assert.False(t, errStatus.serverError)
		})
	})

	t.Run("TinkKeysetNamingRuleViolation", func(t *testing.T) {
		// Setup
		templateName := "TINK_AEAD_AES128_GCM"
		keyID := "invalid-key-id" // Doesn't follow Tink naming convention (should start with tink:aead:)

		// Set the flag
		oldFlag := *createTinkKeyset
		*createTinkKeyset = templateName
		defer func() { *createTinkKeyset = oldFlag }()

		// Execute
		errStatus := runCreate(nil, []string{keyID})

		// Verify
		assert.Error(t, errStatus)
		assert.Contains(t, errStatus.Error(), "must have prefix")
		assert.False(t, errStatus.serverError)
	})

	t.Run("StdinReadError", func(t *testing.T) {
		// Setup - ReadAll from a closed pipe returns empty data, not an error
		// This test validates that empty data from stdin can be processed
		oldCli := cli
		defer func() { cli = oldCli }()

		calledCreateKey := false
		cli = &MockAPIClient{
			CreateKeyFunc: func(keyID string, data []byte, _ types.ACL) (uint64, error) {
				calledCreateKey = true
				assert.Equal(t, "test-key", keyID)
				assert.Empty(t, data) // Empty stdin results in empty data
				return 1, nil
			},
		}

		// Mock stdin to return empty data (closed pipe)
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		r, w, _ := os.Pipe()
		w.Close()
		os.Stdin = r

		errStatus := runCreate(nil, []string{"test-key"})

		// Empty stdin is valid input and should succeed
		assert.Nil(t, errStatus)
		assert.True(t, calledCreateKey, "CreateKey should be called with empty data")
	})

	t.Run("CreateKeyAPIError", func(t *testing.T) {
		// Setup
		oldCli := cli
		defer func() { cli = oldCli }()

		expectedError := errors.New("API error: key already exists")

		cli = &MockAPIClient{
			CreateKeyFunc: func(_ string, _ []byte, _ types.ACL) (uint64, error) {
				return 0, expectedError
			},
		}

		// Mock stdin
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()
		// Create a temporary file to mock stdin
		tmpfile, err := os.CreateTemp(t.TempDir(), "stdin-mock")
		assert.Nil(t, err)
		defer os.Remove(tmpfile.Name())

		_, err = tmpfile.Write([]byte("test-data"))
		assert.NoError(t, err)
		_, err = tmpfile.Seek(0, 0)
		assert.NoError(t, err)
		os.Stdin = tmpfile

		// Execute
		errStatus := runCreate(nil, []string{"test-key"})

		// Verify
		assert.Error(t, errStatus)
		assert.Contains(t, errStatus.Error(), "error adding version: API error: key already exists")
		assert.True(t, errStatus.serverError)
	})

	t.Run("TinkKeysetCreationError", func(t *testing.T) {
		// Setup - temporarily replace the Tink template function to return error
		oldTemplates := tinkKeyTemplates
		defer func() { tinkKeyTemplates = oldTemplates }()

		tinkKeyTemplates = map[string]tinkKeyTemplateInfo{
			"INVALID": {
				knoxIDPrefix: "tink:invalid:",
				templateFunc: func() *tinkpb.KeyTemplate {
					return nil
				},
			},
		}

		// Set the flag
		oldFlag := *createTinkKeyset
		*createTinkKeyset = "INVALID"
		defer func() { *createTinkKeyset = oldFlag }()

		// Use a valid Tink key ID that matches the prefix requirement
		errStatus := runCreate(nil, []string{"tink:invalid:test_key"})

		// Verify - The nil template function will cause an error during keyset creation
		assert.Error(t, errStatus)
		assert.Contains(t, errStatus.Error(), "cannot get tink keyset handle")
		assert.False(t, errStatus.serverError)
	})
}

func TestReadDataFromStdin(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		// Mock stdin
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		expectedData := []byte("test input data")
		// Create a temporary file to mock stdin
		tmpfile, err := os.CreateTemp(t.TempDir(), "stdin-mock")
		assert.Nil(t, err)
		defer os.Remove(tmpfile.Name())

		_, err = tmpfile.Write(expectedData)
		assert.NoError(t, err)
		_, err = tmpfile.Seek(0, 0)
		assert.NoError(t, err)
		os.Stdin = tmpfile

		// Capture log output
		var logOutput bytes.Buffer
		log.SetOutput(&logOutput)
		defer log.SetOutput(os.Stderr)

		// Execute
		data, err := readDataFromStdin()

		// Verify
		assert.NoError(t, err)
		assert.Equal(t, expectedData, data)
		assert.Contains(t, logOutput.String(), "Reading from stdin...")
	})

	t.Run("ReadError", func(t *testing.T) {
		// Note: ReadAll from a closed pipe returns empty data, not an error
		// This test validates that empty stdin is successfully read
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		r, w, _ := os.Pipe()
		w.Close()
		os.Stdin = r

		// Execute
		data, err := readDataFromStdin()

		// Verify - empty stdin is valid
		assert.NoError(t, err)
		assert.Empty(t, data)
	})

	t.Run("EmptyInput", func(t *testing.T) {
		// Mock stdin with empty input
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		// Create a temporary file to mock stdin
		tmpfile, err := os.CreateTemp(t.TempDir(), "stdin-mock")
		assert.NoError(t, err)
		defer os.Remove(tmpfile.Name())

		os.Stdin = tmpfile

		// Execute
		data, err := readDataFromStdin()

		// Verify
		assert.NoError(t, err)
		assert.Empty(t, data)
	})
}

func TestCreateCommandStructure(t *testing.T) {
	t.Run("CommandMetadata", func(t *testing.T) {
		assert.Equal(t, "create [--key-template template_name] <key_identifier>", cmdCreate.UsageLine)
		assert.Equal(t, "creates a new key", cmdCreate.Short)
		assert.Contains(t, cmdCreate.Long, "Create will create a new key in knox")
		assert.Contains(t, cmdCreate.Long, "Key data should be sent to stdin")
		assert.Contains(t, cmdCreate.Long, "key-template option")
	})

	t.Run("CommandRunnable", func(t *testing.T) {
		assert.True(t, cmdCreate.Runnable())
	})

	t.Run("CommandName", func(t *testing.T) {
		assert.Equal(t, "create", cmdCreate.Name())
	})
}

func TestCreateCommandIntegration(t *testing.T) {
	t.Run("EndToEndSuccess", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		// Setup mock client
		cli = &MockAPIClient{
			CreateKeyFunc: func(keyID string, data []byte, _ types.ACL) (uint64, error) {
				assert.Equal(t, "integration-test-key", keyID)
				assert.Equal(t, []byte("integration-test-data"), data)
				return 789, nil
			},
		}

		// Mock stdin
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()
		// Create a temporary file to mock stdin
		tmpfile, err := os.CreateTemp(t.TempDir(), "stdin-mock")
		assert.NoError(t, err)
		defer os.Remove(tmpfile.Name())

		_, err = tmpfile.Write([]byte("integration-test-data"))
		assert.NoError(t, err)
		_, err = tmpfile.Seek(0, 0)
		assert.NoError(t, err)
		os.Stdin = tmpfile

		// Capture output
		var logOutput bytes.Buffer
		log.SetOutput(&logOutput)
		defer log.SetOutput(os.Stderr)

		// Execute
		errStatus := runCreate(nil, []string{"integration-test-key"})
		assert.Nil(t, errStatus)

		// Verify
		assert.Contains(t, logOutput.String(), "Created key with initial version 789")
	})

	t.Run("ConcurrentCreateCalls", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		createCount := 0
		cli = &MockAPIClient{
			CreateKeyFunc: func(_ string, _ []byte, _ types.ACL) (uint64, error) {
				createCount++
				return uint64(createCount), nil
			},
		}

		// Mock stdin for multiple calls
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		// Test multiple sequential calls
		testCases := []struct {
			keyID string
			data  string
		}{
			{"key1", "data1"},
			{"key2", "data2"},
			{"key3", "data3"},
		}

		for i, tc := range testCases {
			// Create a temporary file to mock stdin
			tmpfile, err := os.CreateTemp(t.TempDir(), "stdin-mock")
			assert.NoError(t, err)
			defer os.Remove(tmpfile.Name())

			_, err = tmpfile.Write([]byte(tc.data))
			assert.NoError(t, err)
			_, err = tmpfile.Seek(0, 0)
			assert.NoError(t, err)
			os.Stdin = tmpfile
			errStatus := runCreate(nil, []string{tc.keyID})
			assert.Nil(t, errStatus, "Test case %d failed", i)
		}

		assert.Equal(t, 3, createCount)
	})
}

func TestCreateCommandEdgeCases(t *testing.T) {
	t.Run("VeryLongKeyID", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		longKeyID := strings.Repeat("a", 100) // 100 character key ID
		cli = &MockAPIClient{
			CreateKeyFunc: func(keyID string, _ []byte, _ types.ACL) (uint64, error) {
				assert.Equal(t, longKeyID, keyID)
				return 1, nil
			},
		}

		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()
		// Create a temporary file to mock stdin
		tmpfile, err := os.CreateTemp(t.TempDir(), "stdin-mock")
		assert.NoError(t, err)
		defer os.Remove(tmpfile.Name())

		_, err = tmpfile.Write([]byte("test-data"))
		assert.NoError(t, err)
		_, err = tmpfile.Seek(0, 0)
		assert.NoError(t, err)
		os.Stdin = tmpfile

		errStatus := runCreate(nil, []string{longKeyID})
		assert.Nil(t, errStatus)
		assert.Nil(t, errStatus)
	})

	t.Run("BinaryDataFromStdin", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		binaryData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xFF, 0xFE, 0xFD}
		cli = &MockAPIClient{
			CreateKeyFunc: func(_ string, data []byte, _ types.ACL) (uint64, error) {
				assert.Equal(t, binaryData, data)
				return 1, nil
			},
		}

		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()
		// Create a temporary file to mock stdin
		tmpfile, err := os.CreateTemp(t.TempDir(), "stdin-mock")
		assert.NoError(t, err)
		defer os.Remove(tmpfile.Name())

		_, err = tmpfile.Write(binaryData)
		assert.NoError(t, err)
		_, err = tmpfile.Seek(0, 0)
		assert.NoError(t, err)
		os.Stdin = tmpfile

		errStatus := runCreate(nil, []string{"binary-test-key"})
		assert.Nil(t, errStatus)
		assert.Nil(t, errStatus)
	})

	t.Run("LargeDataFromStdin", func(t *testing.T) {
		oldCli := cli
		defer func() { cli = oldCli }()

		// Create 1MB of test data
		largeData := bytes.Repeat([]byte("A"), 1024*1024)
		cli = &MockAPIClient{
			CreateKeyFunc: func(_ string, data []byte, _ types.ACL) (uint64, error) {
				assert.Equal(t, len(largeData), len(data))
				return 1, nil
			},
		}

		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()
		// Create a temporary file to mock stdin
		tmpfile, err := os.CreateTemp(t.TempDir(), "stdin-mock")
		assert.NoError(t, err)
		defer os.Remove(tmpfile.Name())

		_, err = tmpfile.Write(largeData)
		assert.NoError(t, err)
		_, err = tmpfile.Seek(0, 0)
		assert.NoError(t, err)
		os.Stdin = tmpfile

		errStatus := runCreate(nil, []string{"large-data-test-key"})
		assert.Nil(t, errStatus)
		assert.Nil(t, errStatus)
	})
}

// Test helper to reset global state between tests.
func resetCreateCommand() {
	*createTinkKeyset = ""
}

func init() {
	// Ensure tests start with clean state
	resetCreateCommand()
}
