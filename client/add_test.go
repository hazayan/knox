package client

import (
	"errors"
	"strings"
	"testing"

	"github.com/hazayan/knox/pkg/types"
)

// TestRunAdd_InvalidArguments tests runAdd with invalid number of arguments.
func TestRunAdd_InvalidArguments(t *testing.T) {
	// Test with no arguments
	err := runAdd(nil, []string{})
	if err == nil {
		t.Error("expected error for no arguments, got nil")
	} else if !strings.Contains(err.Error(), "add takes only one argument") {
		t.Errorf("expected error about one argument, got: %v", err)
	}

	// Test with too many arguments
	err = runAdd(nil, []string{"key1", "key2"})
	if err == nil {
		t.Error("expected error for too many arguments, got nil")
	} else if !strings.Contains(err.Error(), "add takes only one argument") {
		t.Errorf("expected error about one argument, got: %v", err)
	}
}

// TestRunAdd_AddVersionError tests runAdd when AddVersion fails.
func TestRunAdd_AddVersionError(t *testing.T) {
	// Save original values
	originalAddTinkKeyset := *addTinkKeyset
	originalCli := cli
	defer func() {
		*addTinkKeyset = originalAddTinkKeyset
		cli = originalCli
	}()

	// Clear template flag
	*addTinkKeyset = ""

	// Mock the CLI
	mockCLI := &MockAPIClient{}
	cli = mockCLI

	// Mock AddVersion to return error
	mockCLI.AddVersionFunc = func(_ string, _ []byte) (uint64, error) {
		return 0, errors.New("add version error")
	}

	err := runAdd(nil, []string{"test-key"})
	if err == nil {
		t.Error("expected error from AddVersion, got nil")
	}
	if err != nil && !err.serverError {
		t.Error("expected fatal error, got non-fatal")
	}
	if !strings.Contains(err.Error(), "error adding version") {
		t.Errorf("expected error about adding version, got: %v", err)
	}
}

// TestGetDataWithTemplate_NamingRuleError tests getDataWithTemplate with naming rule violation.
func TestGetDataWithTemplate_NamingRuleError(t *testing.T) {
	// Test with invalid template name that violates naming rules
	_, err := getDataWithTemplate("invalid-template!", "test-key")
	if err == nil {
		t.Error("expected error for invalid template name, got nil")
	}
}

// TestGetDataWithTemplate_GetKeyError tests getDataWithTemplate when NetworkGetKeyWithStatus fails.
func TestGetDataWithTemplate_GetKeyError(t *testing.T) {
	// Save original values
	originalCli := cli
	defer func() {
		cli = originalCli
	}()

	// Mock the CLI
	mockCLI := &MockAPIClient{}
	cli = mockCLI

	// Mock NetworkGetKeyWithStatus to return error
	mockCLI.NetworkGetKeyWithStatusFunc = func(_ string, _ types.VersionStatus) (*types.Key, error) {
		return nil, errors.New("get key error")
	}

	_, err := getDataWithTemplate("TINK_AEAD_AES128_GCM", "tink:aead:test-key")
	if err == nil {
		t.Error("expected error from NetworkGetKeyWithStatus, got nil")
	}
	if !strings.Contains(err.Error(), "error getting key") {
		t.Errorf("expected error about getting key, got: %v", err)
	}
}

// MockAPIClient is a mock implementation of APIClient for testing.
type MockAPIClient struct {
	GetKeyFunc                  func(keyID string) (*types.Key, error)
	CreateKeyFunc               func(keyID string, data []byte, acl types.ACL) (uint64, error)
	GetKeysFunc                 func(keys map[string]string) ([]string, error)
	DeleteKeyFunc               func(keyID string) error
	GetACLFunc                  func(keyID string) (*types.ACL, error)
	PutAccessFunc               func(keyID string, acl ...types.Access) error
	AddVersionFunc              func(keyID string, data []byte) (uint64, error)
	UpdateVersionFunc           func(keyID, versionID string, status types.VersionStatus) error
	CacheGetKeyFunc             func(keyID string) (*types.Key, error)
	NetworkGetKeyFunc           func(keyID string) (*types.Key, error)
	CacheGetKeyWithStatusFunc   func(keyID string, status types.VersionStatus) (*types.Key, error)
	NetworkGetKeyWithStatusFunc func(keyID string, status types.VersionStatus) (*types.Key, error)
	GetKeyWithStatusFunc        func(keyID string, status types.VersionStatus) (*types.Key, error)
}

func (m *MockAPIClient) GetKey(keyID string) (*types.Key, error) {
	if m.GetKeyFunc != nil {
		return m.GetKeyFunc(keyID)
	}
	return nil, errors.New("GetKey not implemented")
}

func (m *MockAPIClient) CreateKey(keyID string, data []byte, acl types.ACL) (uint64, error) {
	if m.CreateKeyFunc != nil {
		return m.CreateKeyFunc(keyID, data, acl)
	}
	return 0, errors.New("CreateKey not implemented")
}

func (m *MockAPIClient) GetKeys(keys map[string]string) ([]string, error) {
	if m.GetKeysFunc != nil {
		return m.GetKeysFunc(keys)
	}
	return nil, errors.New("GetKeys not implemented")
}

func (m *MockAPIClient) DeleteKey(keyID string) error {
	if m.DeleteKeyFunc != nil {
		return m.DeleteKeyFunc(keyID)
	}
	return errors.New("DeleteKey not implemented")
}

func (m *MockAPIClient) GetACL(keyID string) (*types.ACL, error) {
	if m.GetACLFunc != nil {
		return m.GetACLFunc(keyID)
	}
	return nil, errors.New("GetACL not implemented")
}

func (m *MockAPIClient) PutAccess(keyID string, acl ...types.Access) error {
	if m.PutAccessFunc != nil {
		return m.PutAccessFunc(keyID, acl...)
	}
	return errors.New("PutAccess not implemented")
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

func (m *MockAPIClient) NetworkGetKey(keyID string) (*types.Key, error) {
	if m.NetworkGetKeyFunc != nil {
		return m.NetworkGetKeyFunc(keyID)
	}
	return nil, errors.New("NetworkGetKey not implemented")
}

func (m *MockAPIClient) CacheGetKeyWithStatus(keyID string, status types.VersionStatus) (*types.Key, error) {
	if m.CacheGetKeyWithStatusFunc != nil {
		return m.CacheGetKeyWithStatusFunc(keyID, status)
	}
	return nil, errors.New("CacheGetKeyWithStatus not implemented")
}

func (m *MockAPIClient) NetworkGetKeyWithStatus(keyID string, status types.VersionStatus) (*types.Key, error) {
	if m.NetworkGetKeyWithStatusFunc != nil {
		return m.NetworkGetKeyWithStatusFunc(keyID, status)
	}
	return nil, errors.New("NetworkGetKeyWithStatus not implemented")
}

func (m *MockAPIClient) GetKeyWithStatus(keyID string, status types.VersionStatus) (*types.Key, error) {
	if m.GetKeyWithStatusFunc != nil {
		return m.GetKeyWithStatusFunc(keyID, status)
	}
	return nil, errors.New("GetKeyWithStatus not implemented")
}
