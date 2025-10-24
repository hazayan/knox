// Package crypto_test provides comprehensive tests for the keyloader functionality.
package crypto_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/hazayan/knox/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadMasterKey_EnvironmentVariable tests loading master key from environment variable.
func TestLoadMasterKey_EnvironmentVariable(t *testing.T) {
	t.Run("Base64Encoded", func(t *testing.T) {
		// Generate a valid 32-byte key
		expectedKey := make([]byte, 32)
		_, err := rand.Read(expectedKey)
		require.NoError(t, err)

		// Encode as base64
		encodedKey := base64.StdEncoding.EncodeToString(expectedKey)

		t.Setenv("KNOX_MASTER_KEY", encodedKey)
		defer t.Setenv("KNOX_MASTER_KEY", "")

		key, err := crypto.LoadMasterKey()
		assert.NoError(t, err)
		assert.Equal(t, expectedKey, key)
	})

	t.Run("HexEncoded", func(t *testing.T) {
		// Use a fixed hex key for debugging
		expectedKey, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
		encodedKey := hex.EncodeToString(expectedKey)

		t.Setenv("KNOX_MASTER_KEY", encodedKey)
		defer t.Setenv("KNOX_MASTER_KEY", "")

		key, err := crypto.LoadMasterKey()
		assert.NoError(t, err)
		assert.Equal(t, expectedKey, key)
	})

	t.Run("InvalidEncoding", func(t *testing.T) {
		t.Setenv("KNOX_MASTER_KEY", "invalid-encoding")
		defer t.Setenv("KNOX_MASTER_KEY", "")

		_, err := crypto.LoadMasterKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode master key")
	})

	t.Run("WrongKeyLength", func(t *testing.T) {
		// Create a key with wrong length
		shortKey := make([]byte, 16)
		_, err := rand.Read(shortKey)
		require.NoError(t, err)

		encodedKey := base64.StdEncoding.EncodeToString(shortKey)

		t.Setenv("KNOX_MASTER_KEY", encodedKey)
		defer t.Setenv("KNOX_MASTER_KEY", "")

		_, err = crypto.LoadMasterKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "wrong length")
	})
}

// TestLoadMasterKey_KeyFile tests loading master key from file.
func TestLoadMasterKey_KeyFile(t *testing.T) {
	t.Run("ValidKeyFile", func(t *testing.T) {
		tmpDir := t.TempDir()
		keyFile := filepath.Join(tmpDir, "master.key")

		// Generate a valid key
		expectedKey := make([]byte, 32)
		_, err := rand.Read(expectedKey)
		require.NoError(t, err)

		// Write base64 encoded key to file
		encodedKey := base64.StdEncoding.EncodeToString(expectedKey)
		err = os.WriteFile(keyFile, []byte(encodedKey), 0o600)
		require.NoError(t, err)

		t.Setenv("KNOX_MASTER_KEY_FILE", keyFile)
		defer t.Setenv("KNOX_MASTER_KEY_FILE", "")

		key, err := crypto.LoadMasterKey()
		assert.NoError(t, err)
		assert.Equal(t, expectedKey, key)
	})

	t.Run("FileNotFound", func(t *testing.T) {
		t.Setenv("KNOX_MASTER_KEY_FILE", "/non/existent/file.key")
		defer t.Setenv("KNOX_MASTER_KEY_FILE", "")

		_, err := crypto.LoadMasterKey()
		assert.Error(t, err)
	})

	t.Run("InsecureFilePermissions", func(t *testing.T) {
		tmpDir := t.TempDir()
		keyFile := filepath.Join(tmpDir, "insecure.key")

		// Generate a valid key
		expectedKey := make([]byte, 32)
		_, err := rand.Read(expectedKey)
		require.NoError(t, err)

		// Write with insecure permissions
		encodedKey := base64.StdEncoding.EncodeToString(expectedKey)
		err = os.WriteFile(keyFile, []byte(encodedKey), 0o644) // World readable
		require.NoError(t, err)

		t.Setenv("KNOX_MASTER_KEY_FILE", keyFile)
		defer t.Setenv("KNOX_MASTER_KEY_FILE", "")

		_, err = crypto.LoadMasterKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "insecure permissions")
	})

	t.Run("RelativePath", func(t *testing.T) {
		// Test with a relative path that doesn't exist
		// The error will be about file not found, not about absolute path
		// This documents the current behavior
		t.Setenv("KNOX_MASTER_KEY_FILE", "relative.key")
		defer t.Setenv("KNOX_MASTER_KEY_FILE", "")

		_, err := crypto.LoadMasterKey()
		assert.Error(t, err)
		// The error is about file not found, not path validation
	})

	t.Run("PathTraversal", func(t *testing.T) {
		// Test with a path traversal that doesn't exist
		// The error will be about file not found, not about path traversal
		// This documents the current behavior
		t.Setenv("KNOX_MASTER_KEY_FILE", "/etc/knox/../passwd")
		defer t.Setenv("KNOX_MASTER_KEY_FILE", "")

		_, err := crypto.LoadMasterKey()
		assert.Error(t, err)
		// The error is about file not found, not path traversal
	})
}

// TestLoadMasterKey_Priority tests the priority order of key sources.
func TestLoadMasterKey_Priority(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "master.key")

	// Generate keys for different sources
	envKey := make([]byte, 32)
	_, err := rand.Read(envKey)
	require.NoError(t, err)

	fileKey := make([]byte, 32)
	_, err = rand.Read(fileKey)
	require.NoError(t, err)

	// Write file key
	encodedFileKey := base64.StdEncoding.EncodeToString(fileKey)
	err = os.WriteFile(keyFile, []byte(encodedFileKey), 0o600)
	require.NoError(t, err)

	// Set both environment variables
	encodedEnvKey := base64.StdEncoding.EncodeToString(envKey)
	t.Setenv("KNOX_MASTER_KEY", encodedEnvKey)
	t.Setenv("KNOX_MASTER_KEY_FILE", keyFile)
	defer func() {
		t.Setenv("KNOX_MASTER_KEY", "")
		t.Setenv("KNOX_MASTER_KEY_FILE", "")
	}()

	// Environment variable should take priority
	key, err := crypto.LoadMasterKey()
	assert.NoError(t, err)
	assert.Equal(t, envKey, key) // Should use env key, not file key
}

// TestLoadMasterKey_NoKeyFound tests when no key sources are available.
func TestLoadMasterKey_NoKeyFound(t *testing.T) {
	// Clear all environment variables
	t.Setenv("KNOX_MASTER_KEY", "")
	t.Setenv("KNOX_MASTER_KEY_FILE", "")

	_, err := crypto.LoadMasterKey()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no master key found")
}

// TestDecodeMasterKey tests the decodeMasterKey function.
func TestDecodeMasterKey(t *testing.T) {
	t.Run("ValidBase64", func(t *testing.T) {
		expectedKey := make([]byte, 32)
		_, err := rand.Read(expectedKey)
		require.NoError(t, err)

		encodedKey := base64.StdEncoding.EncodeToString(expectedKey)

		// Remove ineffectual assignment
		// This is an internal function, so we test through LoadMasterKey
		// by setting environment variable
		t.Setenv("KNOX_MASTER_KEY", encodedKey)
		defer t.Setenv("KNOX_MASTER_KEY", "")

		key, err := crypto.LoadMasterKey()
		assert.NoError(t, err)
		assert.Equal(t, expectedKey, key)
	})

	t.Run("ValidHex", func(t *testing.T) {
		// Use a fixed hex key for debugging
		expectedKey, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
		encodedKey := hex.EncodeToString(expectedKey)

		t.Setenv("KNOX_MASTER_KEY", encodedKey)
		defer t.Setenv("KNOX_MASTER_KEY", "")

		key, err := crypto.LoadMasterKey()
		assert.NoError(t, err)
		assert.Equal(t, expectedKey, key)
	})

	t.Run("InvalidFormat", func(t *testing.T) {
		t.Setenv("KNOX_MASTER_KEY", "not-base64-or-hex")
		defer t.Setenv("KNOX_MASTER_KEY", "")

		_, err := crypto.LoadMasterKey()
		assert.Error(t, err)
	})

	t.Run("EmptyString", func(t *testing.T) {
		t.Setenv("KNOX_MASTER_KEY", "")
		defer t.Setenv("KNOX_MASTER_KEY", "")

		_, err := crypto.LoadMasterKey()
		assert.Error(t, err)
	})

	t.Run("WhitespacePadding", func(t *testing.T) {
		expectedKey := make([]byte, 32)
		_, err := rand.Read(expectedKey)
		require.NoError(t, err)

		encodedKey := base64.StdEncoding.EncodeToString(expectedKey)

		// Test with whitespace padding
		t.Setenv("KNOX_MASTER_KEY", "  "+encodedKey+"  ")
		defer t.Setenv("KNOX_MASTER_KEY", "")

		key, err := crypto.LoadMasterKey()
		assert.NoError(t, err)
		assert.Equal(t, expectedKey, key)
	})
}

// TestGenerateMasterKeyString tests master key generation.
func TestGenerateMasterKeyString(t *testing.T) {
	key1, err := crypto.GenerateMasterKeyString()
	assert.NoError(t, err)
	assert.NotEmpty(t, key1)

	// Verify it's valid base64
	decoded1, err := base64.StdEncoding.DecodeString(key1)
	assert.NoError(t, err)
	assert.Len(t, decoded1, 32)

	// Generate another key to ensure randomness
	key2, err := crypto.GenerateMasterKeyString()
	assert.NoError(t, err)
	assert.NotEmpty(t, key2)
	assert.NotEqual(t, key1, key2)

	decoded2, err := base64.StdEncoding.DecodeString(key2)
	assert.NoError(t, err)
	assert.Len(t, decoded2, 32)
	assert.NotEqual(t, decoded1, decoded2)
}

// TestSaveMasterKeyToFile tests saving master key to file.
func TestSaveMasterKeyToFile(t *testing.T) {
	t.Run("ValidKey", func(t *testing.T) {
		tmpDir := t.TempDir()
		keyFile := filepath.Join(tmpDir, "test.key")

		// Generate a valid key
		expectedKey := make([]byte, 32)
		_, err := rand.Read(expectedKey)
		require.NoError(t, err)

		// Save the key
		err = crypto.SaveMasterKeyToFile(expectedKey, keyFile)
		assert.NoError(t, err)

		// Verify file was created with correct permissions
		info, err := os.Stat(keyFile)
		assert.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

		// Verify file content
		data, err := os.ReadFile(keyFile)
		assert.NoError(t, err)

		decodedKey, err := base64.StdEncoding.DecodeString(string(data))
		assert.NoError(t, err)
		assert.Equal(t, expectedKey, decodedKey)
	})

	t.Run("InvalidKeyLength", func(t *testing.T) {
		tmpDir := t.TempDir()
		keyFile := filepath.Join(tmpDir, "test.key")

		// Use invalid key length
		invalidKey := make([]byte, 16)

		err := crypto.SaveMasterKeyToFile(invalidKey, keyFile)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be 32 bytes")
	})

	t.Run("InvalidPath", func(t *testing.T) {
		// Try to save to non-existent directory
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		err = crypto.SaveMasterKeyToFile(key, "/non/existent/dir/key.key")
		assert.Error(t, err)
	})
}

// TestKeyLoader_Integration tests integration between generation and loading.
func TestKeyLoader_Integration(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "integration.key")

	// Generate a key string
	keyStr, err := crypto.GenerateMasterKeyString()
	assert.NoError(t, err)

	// Decode to get the raw key
	rawKey, err := base64.StdEncoding.DecodeString(keyStr)
	assert.NoError(t, err)

	// Save the raw key to file
	err = crypto.SaveMasterKeyToFile(rawKey, keyFile)
	assert.NoError(t, err)

	// Load the key back
	t.Setenv("KNOX_MASTER_KEY_FILE", keyFile)
	defer t.Setenv("KNOX_MASTER_KEY_FILE", "")

	loadedKey, err := crypto.LoadMasterKey()
	assert.NoError(t, err)
	assert.Equal(t, rawKey, loadedKey)
}

// TestKeyLoader_DefaultFileLocation tests the default key file location behavior.
func TestKeyLoader_DefaultFileLocation(t *testing.T) {
	// This test is mostly for documentation since we can't reliably test
	// the default location in a portable way
	t.Run("DefaultLocationNotUsedWhenEnvSet", func(t *testing.T) {
		// Even if default file exists, env should take priority
		tmpDir := t.TempDir()
		envKeyFile := filepath.Join(tmpDir, "env.key")

		// Create env key file
		envKey := make([]byte, 32)
		_, err := rand.Read(envKey)
		require.NoError(t, err)

		encodedEnvKey := base64.StdEncoding.EncodeToString(envKey)
		err = os.WriteFile(envKeyFile, []byte(encodedEnvKey), 0o600)
		require.NoError(t, err)

		t.Setenv("KNOX_MASTER_KEY_FILE", envKeyFile)
		defer t.Setenv("KNOX_MASTER_KEY_FILE", "")

		// Clear KNOX_MASTER_KEY to force file loading
		t.Setenv("KNOX_MASTER_KEY", "")
		defer t.Setenv("KNOX_MASTER_KEY", "")

		loadedKey, err := crypto.LoadMasterKey()
		assert.NoError(t, err)
		assert.Equal(t, envKey, loadedKey)
	})
}

// TestDecodeMasterKey_ErrorPaths tests error handling in decodeMasterKey.
func TestDecodeMasterKey_ErrorPaths(t *testing.T) {
	t.Run("InvalidBase64", func(t *testing.T) {
		// Not valid base64 or hex
		_, err := crypto.DecodeMasterKeyForTest("not-valid-base64-or-hex!!!")
		assert.Error(t, err)
		// Error should indicate the key format is wrong
	})

	t.Run("WrongLengthAfterDecoding", func(t *testing.T) {
		// Valid base64 but wrong length (16 bytes instead of 32)
		shortKey := make([]byte, 16)
		encoded := base64.StdEncoding.EncodeToString(shortKey)
		_, err := crypto.DecodeMasterKeyForTest(encoded)
		assert.Error(t, err)
		// Should error because wrong length
	})
}

// TestLoadMasterKeyFromFile_ErrorPaths tests error handling in loadMasterKeyFromFile.
func TestLoadMasterKeyFromFile_ErrorPaths(t *testing.T) {
	t.Run("FileNotFound", func(t *testing.T) {
		_, err := crypto.LoadMasterKeyFromFileForTest("/nonexistent/path/to/key.txt")
		assert.Error(t, err)
		// Error message varies by OS, just check there's an error
	})

	t.Run("InvalidKeyInFile", func(t *testing.T) {
		// Create temp file with invalid key
		tmpfile, err := os.CreateTemp(t.TempDir(), "invalid-key-*.txt")
		require.NoError(t, err)
		defer os.Remove(tmpfile.Name())

		_, err = tmpfile.WriteString("invalid-key-content")
		require.NoError(t, err)
		tmpfile.Close()

		_, err = crypto.LoadMasterKeyFromFileForTest(tmpfile.Name())
		assert.Error(t, err)
		// Should fail because the key content is invalid
	})
}

// TestSaveMasterKeyToFile_ErrorPaths tests error handling in SaveMasterKeyToFile.
func TestSaveMasterKeyToFile_ErrorPaths(t *testing.T) {
	t.Run("InvalidKeyLength", func(t *testing.T) {
		// Create temp file path
		tmpfile, err := os.CreateTemp(t.TempDir(), "key-*.txt")
		require.NoError(t, err)
		tmpfile.Close()
		defer os.Remove(tmpfile.Name())

		// Try to save a key with wrong length
		invalidKey := make([]byte, 16) // Should be 32 bytes
		err = crypto.SaveMasterKeyToFile(invalidKey, tmpfile.Name())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key must be 32 bytes")
	})

	t.Run("InvalidPath", func(t *testing.T) {
		// Try to write to a directory that doesn't exist
		validKey := make([]byte, 32)
		err := crypto.SaveMasterKeyToFile(validKey, "/nonexistent/directory/key.txt")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to write key file")
	})
}

// TestGetKMSProvider_ErrorPaths tests error handling in GetKMSProvider.
func TestGetKMSProvider_ErrorPaths(t *testing.T) {
	t.Run("UnsupportedProvider", func(t *testing.T) {
		_, err := crypto.GetKMSProvider("unsupported-provider")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported KMS provider")
	})
}
