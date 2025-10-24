// Package main provides testing utilities for the Knox CLI.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/hazayan/knox/pkg/config"
	"github.com/hazayan/knox/pkg/types"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfig represents a test configuration for CLI testing.
type TestConfig struct {
	ConfigDir    string
	ConfigFile   string
	ProfileName  string
	MockClient   *MockAPIClient
	OutputBuffer *bytes.Buffer
	ErrorBuffer  *bytes.Buffer
}

// MockAPIClient is a mock implementation of client.APIClient for testing.
type MockAPIClient struct {
	GetKeyFunc                  func(keyID string) (*types.Key, error)
	NetworkGetKeyFunc           func(keyID string) (*types.Key, error)
	GetKeyWithStatusFunc        func(keyID string, status types.VersionStatus) (*types.Key, error)
	NetworkGetKeyWithStatusFunc func(keyID string, status types.VersionStatus) (*types.Key, error)
	GetKeysFunc                 func(keys map[string]string) ([]string, error)
	CreateKeyFunc               func(keyID string, data []byte, acl types.ACL) (uint64, error)
	GetACLFunc                  func(keyID string) (*types.ACL, error)
	PutACLFunc                  func(keyID string, acl types.ACL) error
	AddAccessFunc               func(keyID string, access types.Access) error
	DeleteAccessFunc            func(keyID string, access types.Access) error
	DeleteKeyFunc               func(keyID string) error
	AddVersionFunc              func(keyID string, data []byte) (uint64, error)
	UpdateVersionFunc           func(keyID string, versionID string, status types.VersionStatus) error
	CacheGetKeyFunc             func(keyID string) (*types.Key, error)
	CacheGetKeyWithStatusFunc   func(keyID string, status types.VersionStatus) (*types.Key, error)
	PutAccessFunc               func(keyID string, access ...types.Access) error
}

// NewTestConfig creates a new test configuration.
func NewTestConfig(t *testing.T) *TestConfig {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, ".knox")
	err := os.MkdirAll(configDir, 0o700)
	require.NoError(t, err)

	configFile := filepath.Join(configDir, "config.yaml")

	// Create a basic test configuration
	cfg := &config.ClientConfig{
		CurrentProfile: "test",
		Profiles: map[string]config.ClientProfile{
			"test": {
				Server: "localhost:9000",
				Cache: config.CacheConfig{
					Enabled:   false,
					Directory: filepath.Join(configDir, "cache"),
					TTL:       "5m",
				},
				TLS: config.ClientTLSConfig{
					CACert:     "",
					ClientCert: "",
					ClientKey:  "",
				},
			},
		},
	}

	// Write config to file
	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	err = os.WriteFile(configFile, data, 0o600)
	require.NoError(t, err)

	return &TestConfig{
		ConfigDir:    configDir,
		ConfigFile:   configFile,
		ProfileName:  "test",
		MockClient:   &MockAPIClient{},
		OutputBuffer: &bytes.Buffer{},
		ErrorBuffer:  &bytes.Buffer{},
	}
}

// SetupTestEnvironment sets up the test environment with the given configuration.
func (tc *TestConfig) SetupTestEnvironment(t *testing.T) {
	// Set environment variables for config
	t.Setenv("KNOX_CONFIG_FILE", tc.ConfigFile)
}

// SetupCache creates the cache directory for testing.
func (tc *TestConfig) SetupCache() {
	// Create cache directory if needed
	cacheDir := filepath.Join(tc.ConfigDir, "cache")
	err := os.MkdirAll(cacheDir, 0o700)
	if err != nil {
		panic(err)
	}
}

// Cleanup cleans up the test configuration.
func (tc *TestConfig) Cleanup() {
	// Cleanup is handled by t.TempDir() automatically
}

// ExecuteCommand executes a CLI command and returns the output and error.
func ExecuteCommand(cmd *cobra.Command, args ...string) (string, string, error) {
	// Capture stdout and stderr
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
	}()

	r, w, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w

	cmd.SetOut(w)
	cmd.SetErr(w)
	cmd.SetArgs(args)

	err := cmd.Execute()
	w.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return "", "", err
	}

	output := buf.String()

	// Split output into stdout and stderr (simplified for testing)
	// In real usage, we'd need to separate them properly
	stdout := output
	stderr := ""
	if err != nil {
		stderr = err.Error()
	}

	return stdout, stderr, err
}

// ExecuteCommandWithConfig executes a CLI command with test configuration.
func (tc *TestConfig) ExecuteCommand(cmd *cobra.Command, args ...string) (string, string, error) {
	return ExecuteCommand(cmd, args...)
}

// CreateTestKey creates a test key for use in tests.
func CreateTestKey(keyID string) *types.Key {
	return &types.Key{
		ID: keyID,
		ACL: types.ACL{
			{
				ID:         "user@example.com",
				Type:       types.User,
				AccessType: types.Read,
			},
		},
		VersionList: types.KeyVersionList{
			{
				ID:           1,
				Data:         []byte("test-secret-data"),
				Status:       types.Primary,
				CreationTime: 1234567890,
			},
		},
		VersionHash: "test-hash",
	}
}

// CreateTestKeyWithVersions creates a test key with multiple versions.
func CreateTestKeyWithVersions(keyID string) *types.Key {
	return &types.Key{
		ID: keyID,
		ACL: types.ACL{
			{
				ID:         "user@example.com",
				Type:       types.User,
				AccessType: types.Read,
			},
		},
		VersionList: types.KeyVersionList{
			{
				ID:           1,
				Data:         []byte("primary-secret"),
				Status:       types.Primary,
				CreationTime: 1234567890,
			},
			{
				ID:           2,
				Data:         []byte("active-secret"),
				Status:       types.Active,
				CreationTime: 1234567891,
			},
			{
				ID:           3,
				Data:         []byte("inactive-secret"),
				Status:       types.Inactive,
				CreationTime: 1234567892,
			},
		},
		VersionHash: "test-hash-with-versions",
	}
}

// CreateTestKeyWithTwoVersions creates a test key with exactly two versions for testing.
func CreateTestKeyWithTwoVersions(keyID string) *types.Key {
	return &types.Key{
		ID: keyID,
		ACL: types.ACL{
			{
				ID:         "user@example.com",
				Type:       types.User,
				AccessType: types.Read,
			},
		},
		VersionList: types.KeyVersionList{
			{
				ID:           1,
				Data:         []byte("primary-secret"),
				Status:       types.Primary,
				CreationTime: 1234567890,
			},
			{
				ID:           2,
				Data:         []byte("active-secret"),
				Status:       types.Active,
				CreationTime: 1234567891,
			},
		},
		VersionHash: "test-hash-with-two-versions",
	}
}

// CreateTestACL creates a test ACL for use in tests.
func CreateTestACL() *types.ACL {
	return &types.ACL{
		{
			ID:         "user@example.com",
			Type:       types.User,
			AccessType: types.Read,
		},
		{
			ID:         "machine.example.com",
			Type:       types.Machine,
			AccessType: types.Write,
		},
		{
			ID:         "spiffe://example.com/service",
			Type:       types.Service,
			AccessType: types.Admin,
		},
	}
}

// MockAPIClient implementation

func (m *MockAPIClient) GetKey(keyID string) (*types.Key, error) {
	if m.GetKeyFunc != nil {
		return m.GetKeyFunc(keyID)
	}
	return nil, errors.New("GetKey not implemented")
}

func (m *MockAPIClient) NetworkGetKey(keyID string) (*types.Key, error) {
	if m.NetworkGetKeyFunc != nil {
		return m.NetworkGetKeyFunc(keyID)
	}
	return nil, errors.New("NetworkGetKey not implemented")
}

func (m *MockAPIClient) GetKeyWithStatus(keyID string, status types.VersionStatus) (*types.Key, error) {
	if m.GetKeyWithStatusFunc != nil {
		return m.GetKeyWithStatusFunc(keyID, status)
	}
	return nil, errors.New("GetKeyWithStatus not implemented")
}

func (m *MockAPIClient) NetworkGetKeyWithStatus(keyID string, status types.VersionStatus) (*types.Key, error) {
	if m.NetworkGetKeyWithStatusFunc != nil {
		return m.NetworkGetKeyWithStatusFunc(keyID, status)
	}
	return nil, errors.New("NetworkGetKeyWithStatus not implemented")
}

func (m *MockAPIClient) GetKeys(keys map[string]string) ([]string, error) {
	if m.GetKeysFunc != nil {
		return m.GetKeysFunc(keys)
	}
	return nil, errors.New("GetKeys not implemented")
}

func (m *MockAPIClient) CreateKey(keyID string, data []byte, acl types.ACL) (uint64, error) {
	if m.CreateKeyFunc != nil {
		return m.CreateKeyFunc(keyID, data, acl)
	}
	return 0, errors.New("CreateKey not implemented")
}

func (m *MockAPIClient) GetACL(keyID string) (*types.ACL, error) {
	if m.GetACLFunc != nil {
		return m.GetACLFunc(keyID)
	}
	return nil, errors.New("GetACL not implemented")
}

func (m *MockAPIClient) PutACL(keyID string, acl types.ACL) error {
	if m.PutACLFunc != nil {
		return m.PutACLFunc(keyID, acl)
	}
	return errors.New("PutACL not implemented")
}

func (m *MockAPIClient) AddAccess(keyID string, access types.Access) error {
	if m.AddAccessFunc != nil {
		return m.AddAccessFunc(keyID, access)
	}
	return errors.New("AddAccess not implemented")
}

func (m *MockAPIClient) DeleteAccess(keyID string, access types.Access) error {
	if m.DeleteAccessFunc != nil {
		return m.DeleteAccessFunc(keyID, access)
	}
	return errors.New("DeleteAccess not implemented")
}

func (m *MockAPIClient) DeleteKey(keyID string) error {
	if m.DeleteKeyFunc != nil {
		return m.DeleteKeyFunc(keyID)
	}
	return errors.New("DeleteKey not implemented")
}

func (m *MockAPIClient) AddVersion(keyID string, data []byte) (uint64, error) {
	if m.AddVersionFunc != nil {
		return m.AddVersionFunc(keyID, data)
	}
	return 0, errors.New("AddVersion not implemented")
}

func (m *MockAPIClient) UpdateVersion(keyID, versionID string, status types.VersionStatus) error {
	if m.UpdateVersionFunc != nil {
		return m.UpdateVersionFunc(keyID, versionID, status)
	}
	return errors.New("UpdateVersion not implemented")
}

func (m *MockAPIClient) CacheGetKey(keyID string) (*types.Key, error) {
	if m.CacheGetKeyFunc != nil {
		return m.CacheGetKeyFunc(keyID)
	}
	return nil, errors.New("CacheGetKey not implemented")
}

func (m *MockAPIClient) CacheGetKeyWithStatus(keyID string, status types.VersionStatus) (*types.Key, error) {
	if m.CacheGetKeyWithStatusFunc != nil {
		return m.CacheGetKeyWithStatusFunc(keyID, status)
	}
	return nil, errors.New("CacheGetKeyWithStatus not implemented")
}

func (m *MockAPIClient) PutAccess(keyID string, access ...types.Access) error {
	if m.PutAccessFunc != nil {
		return m.PutAccessFunc(keyID, access...)
	}
	return errors.New("PutAccess not implemented")
}

// AssertJSONOutput validates that the output is valid JSON.
func AssertJSONOutput(t *testing.T, output string) {
	var jsonData any
	err := json.Unmarshal([]byte(output), &jsonData)
	assert.NoError(t, err, "Output should be valid JSON")
}

// AssertOutputContains validates that the output contains the expected string.
func AssertOutputContains(t *testing.T, output, expected string) {
	assert.Contains(t, output, expected, "Output should contain expected string")
}

// AssertOutputNotContains validates that the output does not contain the unexpected string.
func AssertOutputNotContains(t *testing.T, output, unexpected string) {
	assert.NotContains(t, output, unexpected, "Output should not contain unexpected string")
}

// CreateTempFile creates a temporary file with the given content.
func CreateTempFile(t *testing.T, content string) string {
	tmpFile, err := os.CreateTemp(t.TempDir(), "knox-test-*.txt")
	require.NoError(t, err)
	defer tmpFile.Close()

	_, err = tmpFile.WriteString(content)
	require.NoError(t, err)

	return tmpFile.Name()
}

// SetupMockClient sets up common mock responses for testing.
func (m *MockAPIClient) SetupMockClient() {
	// Default implementations that can be overridden in tests
	m.GetKeyFunc = func(_ string) (*types.Key, error) {
		return CreateTestKey("test"), nil
	}

	m.GetKeysFunc = func(_ map[string]string) ([]string, error) {
		return []string{"test:key1", "test:key2", "test:key3"}, nil
	}

	m.CreateKeyFunc = func(_ string, _ []byte, _ types.ACL) (uint64, error) {
		return 1, nil
	}

	m.GetACLFunc = func(_ string) (*types.ACL, error) {
		return CreateTestACL(), nil
	}

	m.DeleteKeyFunc = func(_ string) error {
		return nil
	}

	m.AddVersionFunc = func(_ string, _ []byte) (uint64, error) {
		return 2, nil
	}

	// Setup cache methods
	m.CacheGetKeyFunc = func(_ string) (*types.Key, error) {
		return CreateTestKey("test"), nil
	}

	m.CacheGetKeyWithStatusFunc = func(_ string, _ types.VersionStatus) (*types.Key, error) {
		return CreateTestKey("test"), nil
	}
}

// APIClient interface defines the methods needed for testing.
type APIClient interface {
	GetKey(keyID string) (*types.Key, error)
	NetworkGetKey(keyID string) (*types.Key, error)
	GetKeyWithStatus(keyID string, status types.VersionStatus) (*types.Key, error)
	NetworkGetKeyWithStatus(keyID string, status types.VersionStatus) (*types.Key, error)
	GetKeys(keys map[string]string) ([]string, error)
	CreateKey(keyID string, data []byte, acl types.ACL) (uint64, error)
	GetACL(keyID string) (*types.ACL, error)
	PutACL(keyID string, acl types.ACL) error
	AddAccess(keyID string, access types.Access) error
	DeleteAccess(keyID string, access types.Access) error
	DeleteKey(keyID string) error
	AddVersion(keyID string, data []byte) (uint64, error)
	UpdateVersion(keyID string, versionID uint64, status types.VersionStatus) error
}
