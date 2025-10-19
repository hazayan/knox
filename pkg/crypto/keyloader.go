package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// LoadMasterKey loads the master encryption key from various sources.
// Priority order:
// 1. KNOX_MASTER_KEY environment variable (base64 or hex encoded)
// 2. KNOX_MASTER_KEY_FILE environment variable (path to key file)
// 3. Default key file location.
func LoadMasterKey() ([]byte, error) {
	// Try environment variable first
	if keyStr := os.Getenv("KNOX_MASTER_KEY"); keyStr != "" {
		return decodeMasterKey(keyStr)
	}

	// Try key file from environment
	if keyFile := os.Getenv("KNOX_MASTER_KEY_FILE"); keyFile != "" {
		return loadMasterKeyFromFile(keyFile)
	}

	// Try default key file location
	defaultKeyFile := "/etc/knox/master.key"
	if _, err := os.Stat(defaultKeyFile); err == nil {
		return loadMasterKeyFromFile(defaultKeyFile)
	}

	return nil, errors.New("no master key found: set KNOX_MASTER_KEY or KNOX_MASTER_KEY_FILE environment variable")
}

// decodeMasterKey decodes a master key from string (supports base64 or hex).
func decodeMasterKey(keyStr string) ([]byte, error) {
	keyStr = strings.TrimSpace(keyStr)

	// Try base64 decoding first
	if key, err := base64.StdEncoding.DecodeString(keyStr); err == nil {
		if len(key) == 32 {
			return key, nil
		}
		return nil, fmt.Errorf("decoded key has wrong length: %d bytes (expected 32)", len(key))
	}

	// Try hex decoding
	if key, err := hex.DecodeString(keyStr); err == nil {
		if len(key) == 32 {
			return key, nil
		}
		return nil, fmt.Errorf("decoded key has wrong length: %d bytes (expected 32)", len(key))
	}

	return nil, errors.New("failed to decode master key: must be base64 or hex encoded 32-byte key")
}

// loadMasterKeyFromFile loads the master key from a file.
func loadMasterKeyFromFile(path string) ([]byte, error) {
	// Check file permissions (should be 0600 or stricter)
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat key file: %w", err)
	}

	mode := info.Mode()
	if mode&0o077 != 0 {
		return nil, fmt.Errorf("key file has insecure permissions %o (should be 0600)", mode)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	return decodeMasterKey(string(data))
}

// GenerateMasterKeyString generates a new master key and returns it as a base64 string.
func GenerateMasterKeyString() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("failed to generate master key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// SaveMasterKeyToFile saves a master key to a file with secure permissions.
func SaveMasterKeyToFile(key []byte, path string) error {
	if len(key) != 32 {
		return errors.New("key must be 32 bytes")
	}

	// Encode as base64
	encoded := base64.StdEncoding.EncodeToString(key)

	// Write with secure permissions (owner read/write only)
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}
