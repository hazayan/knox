package crypto

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// KMSProvider is an interface for Key Management Service providers.
type KMSProvider interface {
	// Decrypt decrypts a data encryption key using the KMS.
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)

	// Encrypt encrypts a data encryption key using the KMS.
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)

	// GenerateDataKey generates a new data encryption key.
	GenerateDataKey(ctx context.Context, keySpec string) (plaintext []byte, ciphertext []byte, err error)

	// Name returns the provider name.
	Name() string
}

// LoadMasterKeyFromKMS loads the master key using a KMS provider.
// The encrypted key is stored in an environment variable or file,
// and decrypted on-demand using the KMS.
// Note: Primarily used for testing with MockKMSProvider.
func LoadMasterKeyFromKMS(provider KMSProvider) ([]byte, error) {
	// Check if encrypted key is in environment
	encryptedKeyB64 := os.Getenv("KNOX_MASTER_KEY_ENCRYPTED")
	if encryptedKeyB64 == "" {
		// Try loading from file
		keyFile := os.Getenv("KNOX_MASTER_KEY_ENCRYPTED_FILE")
		if keyFile == "" {
			return nil, errors.New("no encrypted master key found: set KNOX_MASTER_KEY_ENCRYPTED or KNOX_MASTER_KEY_ENCRYPTED_FILE")
		}

		// Validate file path for security
		if !filepath.IsAbs(keyFile) {
			return nil, errors.New("KMS key file path must be absolute")
		}
		if strings.Contains(keyFile, "..") {
			return nil, errors.New("KMS key file path cannot contain parent directory references")
		}

		// #nosec G304 -- keyFile path is strictly validated above (absolute, no traversal)
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read encrypted key file: %w", err)
		}
		encryptedKeyB64 = string(data)
	}

	// Decode base64
	encryptedKey, err := base64.StdEncoding.DecodeString(encryptedKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %w", err)
	}

	// Decrypt using KMS
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	plaintext, err := provider.Decrypt(ctx, encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("KMS decryption failed: %w", err)
	}

	if len(plaintext) != 32 {
		return nil, fmt.Errorf("decrypted key has wrong length: %d bytes (expected 32)", len(plaintext))
	}

	return plaintext, nil
}

// EncryptMasterKeyWithKMS encrypts a master key for storage.
// Note: Primarily used for testing with MockKMSProvider.
func EncryptMasterKeyWithKMS(provider KMSProvider, masterKey []byte) (string, error) {
	if len(masterKey) != 32 {
		return "", errors.New("master key must be 32 bytes")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ciphertext, err := provider.Encrypt(ctx, masterKey)
	if err != nil {
		return "", fmt.Errorf("KMS encryption failed: %w", err)
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// MockKMSProvider is a mock KMS provider for testing.
// DO NOT USE IN PRODUCTION - keys are not actually protected!
// This is suitable for development and testing environments only.
// For production use, rely on secure key storage via environment
// variables or properly secured key files.
type MockKMSProvider struct {
	name string
}

// NewMockKMSProvider creates a mock KMS provider (for testing only).
func NewMockKMSProvider() *MockKMSProvider {
	return &MockKMSProvider{name: "mock"}
}

// Name returns the provider name.
func (m *MockKMSProvider) Name() string {
	return m.name
}

// Decrypt decrypts ciphertext using mock provider (no actual decryption).
func (m *MockKMSProvider) Decrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	// Mock: just return as-is (NO ACTUAL DECRYPTION)
	return ciphertext, nil
}

// Encrypt encrypts plaintext using mock provider (no actual encryption).
func (m *MockKMSProvider) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	// Mock: just return as-is (NO ACTUAL ENCRYPTION)
	return plaintext, nil
}

// GenerateDataKey generates a data key using mock provider.
func (m *MockKMSProvider) GenerateDataKey(_ context.Context, _ string) ([]byte, []byte, error) {
	key := make([]byte, 32)
	// In mock, plaintext and ciphertext are the same
	return key, key, nil
}

var _ KMSProvider = (*MockKMSProvider)(nil)
