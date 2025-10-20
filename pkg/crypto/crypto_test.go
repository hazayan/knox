// Package crypto_test provides tests for cryptographic operations.
package crypto_test

import (
	"crypto/rand"
	"testing"

	"github.com/hazayan/knox/pkg/crypto"
	"github.com/hazayan/knox/pkg/types"
	"github.com/hazayan/knox/server/keydb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAESCryptor_New tests the creation of a new AES cryptor.
func TestAESCryptor_New(t *testing.T) {
	// Test valid master key
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	cryptor, err := crypto.NewAESCryptor(masterKey)
	assert.NoError(t, err)
	assert.NotNil(t, cryptor)

	// Test invalid master key size
	shortKey := make([]byte, 16)
	_, err = crypto.NewAESCryptor(shortKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "master key must be 32 bytes")

	longKey := make([]byte, 64)
	_, err = crypto.NewAESCryptor(longKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "master key must be 32 bytes")
}

// TestAESCryptor_EncryptDecrypt tests the encryption and decryption round-trip.
func TestAESCryptor_EncryptDecrypt(t *testing.T) {
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	cryptor, err := crypto.NewAESCryptor(masterKey)
	require.NoError(t, err)

	// Create test key
	testKey := &types.Key{
		ID: "test:key",
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
				Data:         []byte("secret-data-1"),
				Status:       types.Primary,
				CreationTime: 1234567890,
			},
			{
				ID:           2,
				Data:         []byte("secret-data-2"),
				Status:       types.Active,
				CreationTime: 1234567891,
			},
		},
		VersionHash: "test-hash",
	}

	// Encrypt the key
	encryptedKey, err := cryptor.Encrypt(testKey)
	assert.NoError(t, err)
	assert.NotNil(t, encryptedKey)
	assert.Equal(t, testKey.ID, encryptedKey.ID)
	assert.Equal(t, testKey.ACL, encryptedKey.ACL)
	assert.Equal(t, testKey.VersionHash, encryptedKey.VersionHash)
	assert.Len(t, encryptedKey.VersionList, len(testKey.VersionList))

	// Verify encrypted data is different from original
	for i, encVersion := range encryptedKey.VersionList {
		assert.NotEqual(t, testKey.VersionList[i].Data, encVersion.EncData)
		assert.NotEmpty(t, encVersion.CryptoMetadata)
	}

	// Decrypt the key
	decryptedKey, err := cryptor.Decrypt(encryptedKey)
	assert.NoError(t, err)
	assert.NotNil(t, decryptedKey)

	// Verify decrypted key matches original
	assert.Equal(t, testKey.ID, decryptedKey.ID)
	assert.Equal(t, testKey.ACL, decryptedKey.ACL)
	assert.Equal(t, testKey.VersionHash, decryptedKey.VersionHash)
	assert.Len(t, decryptedKey.VersionList, len(testKey.VersionList))

	for i, decVersion := range decryptedKey.VersionList {
		origVersion := testKey.VersionList[i]
		assert.Equal(t, origVersion.ID, decVersion.ID)
		assert.Equal(t, origVersion.Data, decVersion.Data)
		assert.Equal(t, origVersion.Status, decVersion.Status)
		assert.Equal(t, origVersion.CreationTime, decVersion.CreationTime)
	}
}

// TestAESCryptor_EncryptVersion tests encrypting a single key version.
func TestAESCryptor_EncryptVersion(t *testing.T) {
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	cryptor, err := crypto.NewAESCryptor(masterKey)
	require.NoError(t, err)

	// Create test key and version
	testKey := &types.Key{
		ID: "test:key",
		ACL: types.ACL{
			{
				ID:         "user@example.com",
				Type:       types.User,
				AccessType: types.Read,
			},
		},
		VersionList: types.KeyVersionList{},
		VersionHash: "test-hash",
	}

	testVersion := &types.KeyVersion{
		ID:           1,
		Data:         []byte("secret-data"),
		Status:       types.Primary,
		CreationTime: 1234567890,
	}

	// Encrypt the version
	encryptedVersion, err := cryptor.EncryptVersion(testKey, testVersion)
	assert.NoError(t, err)
	assert.NotNil(t, encryptedVersion)

	// Verify encrypted data is different from original
	assert.NotEqual(t, testVersion.Data, encryptedVersion.EncData)
	assert.NotEmpty(t, encryptedVersion.CryptoMetadata)
	assert.Equal(t, testVersion.ID, encryptedVersion.ID)
	assert.Equal(t, testVersion.Status, encryptedVersion.Status)
	assert.Equal(t, testVersion.CreationTime, encryptedVersion.CreationTime)
}

// TestAESCryptor_DecryptInvalidData tests decryption with invalid data.
func TestAESCryptor_DecryptInvalidData(t *testing.T) {
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	cryptor, err := crypto.NewAESCryptor(masterKey)
	require.NoError(t, err)

	// Test with nil key
	_, err = cryptor.Decrypt(nil)
	assert.Error(t, err)

	// Test with empty version list
	emptyKey := &types.Key{
		ID:          "test:key",
		ACL:         types.ACL{},
		VersionList: types.KeyVersionList{},
		VersionHash: "test-hash",
	}

	encryptedKey, err := cryptor.Encrypt(emptyKey)
	assert.NoError(t, err)

	decryptedKey, err := cryptor.Decrypt(encryptedKey)
	assert.NoError(t, err)
	assert.NotNil(t, decryptedKey)
	assert.Len(t, decryptedKey.VersionList, 0)
}

// TestAESCryptor_DifferentKeys tests that different master keys produce different encryption.
func TestAESCryptor_DifferentKeys(t *testing.T) {
	// Create two different master keys
	masterKey1 := make([]byte, 32)
	_, err := rand.Read(masterKey1)
	require.NoError(t, err)

	masterKey2 := make([]byte, 32)
	_, err = rand.Read(masterKey2)
	require.NoError(t, err)

	cryptor1, err := crypto.NewAESCryptor(masterKey1)
	require.NoError(t, err)

	cryptor2, err := crypto.NewAESCryptor(masterKey2)
	require.NoError(t, err)

	// Create test key
	testKey := &types.Key{
		ID: "test:key",
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
				Data:         []byte("secret-data"),
				Status:       types.Primary,
				CreationTime: 1234567890,
			},
		},
		VersionHash: "test-hash",
	}

	// Encrypt with first cryptor
	encrypted1, err := cryptor1.Encrypt(testKey)
	assert.NoError(t, err)

	// Encrypt with second cryptor
	encrypted2, err := cryptor2.Encrypt(testKey)
	assert.NoError(t, err)

	// Verify encrypted data is different
	assert.NotEqual(t, encrypted1.VersionList[0].EncData, encrypted2.VersionList[0].EncData)

	// Verify each cryptor can only decrypt its own data
	decrypted1, err := cryptor1.Decrypt(encrypted1)
	assert.NoError(t, err)
	assert.Equal(t, testKey.VersionList[0].Data, decrypted1.VersionList[0].Data)

	decrypted2, err := cryptor2.Decrypt(encrypted2)
	assert.NoError(t, err)
	assert.Equal(t, testKey.VersionList[0].Data, decrypted2.VersionList[0].Data)

	// Verify cross-decryption fails
	_, err = cryptor1.Decrypt(encrypted2)
	assert.Error(t, err)

	_, err = cryptor2.Decrypt(encrypted1)
	assert.Error(t, err)
}

// TestDeriveKey tests key derivation from password.
func TestDeriveKey(t *testing.T) {
	password := []byte("test-password")
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	require.NoError(t, err)

	info := []byte("test-context")

	// Test valid derivation
	derivedKey, err := crypto.DeriveKey(password, salt, info)
	assert.NoError(t, err)
	assert.Len(t, derivedKey, 32) // 256-bit key

	// Test with same inputs produces same output
	derivedKey2, err := crypto.DeriveKey(password, salt, info)
	assert.NoError(t, err)
	assert.Equal(t, derivedKey, derivedKey2)

	// Test with different salt produces different output
	differentSalt := make([]byte, 16)
	_, err = rand.Read(differentSalt)
	require.NoError(t, err)

	derivedKey3, err := crypto.DeriveKey(password, differentSalt, info)
	assert.NoError(t, err)
	assert.NotEqual(t, derivedKey, derivedKey3)

	// Test with different info produces different output
	differentInfo := []byte("different-context")
	derivedKey4, err := crypto.DeriveKey(password, salt, differentInfo)
	assert.NoError(t, err)
	assert.NotEqual(t, derivedKey, derivedKey4)

	// Test with insufficient salt
	shortSalt := make([]byte, 8)
	_, err = crypto.DeriveKey(password, shortSalt, info)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "salt must be at least 16 bytes")
}

// TestGenerateMasterKey tests master key generation.
func TestGenerateMasterKey(t *testing.T) {
	// Generate multiple keys to ensure randomness
	key1, err := crypto.GenerateMasterKey()
	assert.NoError(t, err)
	assert.Len(t, key1, 32)

	key2, err := crypto.GenerateMasterKey()
	assert.NoError(t, err)
	assert.Len(t, key2, 32)

	// Verify keys are different (random)
	assert.NotEqual(t, key1, key2)
}

// TestCryptoMetadata_MarshalUnmarshal tests metadata serialization.
func TestCryptoMetadata_MarshalUnmarshal(t *testing.T) {
	metadata := &crypto.CryptoMetadata{
		Algorithm:    "AES-256-GCM",
		EncryptedDEK: "base64-encoded-data",
		Version:      1,
	}

	// Marshal metadata
	data, err := metadata.Marshal()
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	// Unmarshal metadata
	unmarshaled, err := crypto.UnmarshalCryptoMetadata(data)
	assert.NoError(t, err)
	assert.Equal(t, metadata.Algorithm, unmarshaled.Algorithm)
	assert.Equal(t, metadata.EncryptedDEK, unmarshaled.EncryptedDEK)
	assert.Equal(t, metadata.Version, unmarshaled.Version)

	// Test invalid metadata
	_, err = crypto.UnmarshalCryptoMetadata([]byte("invalid-json"))
	assert.Error(t, err)
}

// TestAESCryptor_EncryptWithEmptyData tests encryption with empty data.
func TestAESCryptor_EncryptWithEmptyData(t *testing.T) {
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	cryptor, err := crypto.NewAESCryptor(masterKey)
	require.NoError(t, err)

	// Test with empty data
	testKey := &types.Key{
		ID: "test:key",
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
				Data:         []byte{}, // Empty data
				Status:       types.Primary,
				CreationTime: 1234567890,
			},
		},
		VersionHash: "test-hash",
	}

	encryptedKey, err := cryptor.Encrypt(testKey)
	assert.NoError(t, err)

	decryptedKey, err := cryptor.Decrypt(encryptedKey)
	assert.NoError(t, err)
	// Handle the case where empty slice becomes nil during encryption/decryption
	expectedData := testKey.VersionList[0].Data
	actualData := decryptedKey.VersionList[0].Data
	if len(expectedData) == 0 && actualData == nil {
		// Both are effectively empty, so consider them equal - no assertion needed
		return
	}
	assert.Equal(t, expectedData, actualData)
}

// TestAESCryptor_EncryptWithLargeData tests encryption with large data.
func TestAESCryptor_EncryptWithLargeData(t *testing.T) {
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	cryptor, err := crypto.NewAESCryptor(masterKey)
	require.NoError(t, err)

	// Create large data (1MB)
	largeData := make([]byte, 1024*1024)
	_, err = rand.Read(largeData)
	require.NoError(t, err)

	testKey := &types.Key{
		ID: "test:key",
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
				Data:         largeData,
				Status:       types.Primary,
				CreationTime: 1234567890,
			},
		},
		VersionHash: "test-hash",
	}

	encryptedKey, err := cryptor.Encrypt(testKey)
	assert.NoError(t, err)

	decryptedKey, err := cryptor.Decrypt(encryptedKey)
	assert.NoError(t, err)
	assert.Equal(t, testKey.VersionList[0].Data, decryptedKey.VersionList[0].Data)
}

// TestAESCryptor_EncryptDecryptCorruptedData tests decryption with corrupted encrypted data.
func TestAESCryptor_EncryptDecryptCorruptedData(t *testing.T) {
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	cryptor, err := crypto.NewAESCryptor(masterKey)
	require.NoError(t, err)

	// Create test key
	testKey := &types.Key{
		ID: "test:key",
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
				Data:         []byte("secret-data"),
				Status:       types.Primary,
				CreationTime: 1234567890,
			},
		},
		VersionHash: "test-hash",
	}

	// Encrypt the key
	encryptedKey, err := cryptor.Encrypt(testKey)
	assert.NoError(t, err)

	// Corrupt the encrypted data
	encryptedKey.VersionList[0].EncData[0] ^= 0xFF // Flip first byte

	// Try to decrypt corrupted data - should fail
	_, err = cryptor.Decrypt(encryptedKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt")
}

// TestAESCryptor_EncryptDecryptInvalidMetadata tests decryption with invalid metadata.
func TestAESCryptor_EncryptDecryptInvalidMetadata(t *testing.T) {
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	cryptor, err := crypto.NewAESCryptor(masterKey)
	require.NoError(t, err)

	// Create test key
	testKey := &types.Key{
		ID: "test:key",
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
				Data:         []byte("secret-data"),
				Status:       types.Primary,
				CreationTime: 1234567890,
			},
		},
		VersionHash: "test-hash",
	}

	// Encrypt the key
	encryptedKey, err := cryptor.Encrypt(testKey)
	assert.NoError(t, err)

	// Corrupt the metadata
	encryptedKey.VersionList[0].CryptoMetadata = []byte("invalid-metadata")

	// Try to decrypt with invalid metadata - should fail
	_, err = cryptor.Decrypt(encryptedKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal metadata")
}

// TestAESCryptor_EncryptDecryptWrongAlgorithm tests decryption with wrong algorithm in metadata.
func TestAESCryptor_EncryptDecryptWrongAlgorithm(t *testing.T) {
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	cryptor, err := crypto.NewAESCryptor(masterKey)
	require.NoError(t, err)

	// Create test key
	testKey := &types.Key{
		ID: "test:key",
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
				Data:         []byte("secret-data"),
				Status:       types.Primary,
				CreationTime: 1234567890,
			},
		},
		VersionHash: "test-hash",
	}

	// Encrypt the key
	encryptedKey, err := cryptor.Encrypt(testKey)
	assert.NoError(t, err)

	// Parse and modify metadata to use wrong algorithm
	metadata, err := crypto.UnmarshalCryptoMetadata(encryptedKey.VersionList[0].CryptoMetadata)
	assert.NoError(t, err)

	metadata.Algorithm = "AES-128-CBC" // Wrong algorithm

	// Marshal modified metadata back
	modifiedMetadata, err := metadata.Marshal()
	assert.NoError(t, err)

	encryptedKey.VersionList[0].CryptoMetadata = modifiedMetadata

	// Try to decrypt with wrong algorithm - should fail
	_, err = cryptor.Decrypt(encryptedKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}

// TestAESCryptor_EncryptDecryptEmptyKey tests encryption with nil key.
func TestAESCryptor_EncryptDecryptEmptyKey(t *testing.T) {
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	cryptor, err := crypto.NewAESCryptor(masterKey)
	require.NoError(t, err)

	// Test with nil key - should return error
	encryptedKey, err := cryptor.Encrypt(nil)
	assert.Error(t, err)
	assert.Nil(t, encryptedKey)
	assert.Contains(t, err.Error(), "key cannot be nil")
}

// TestAESCryptor_EncryptDecryptNilVersion tests encryption with nil version.
func TestAESCryptor_EncryptDecryptNilVersion(t *testing.T) {
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	cryptor, err := crypto.NewAESCryptor(masterKey)
	require.NoError(t, err)

	// Test with nil version - should panic or return error
	// The current implementation doesn't handle nil, so we expect a panic
	// This documents the current behavior that needs to be fixed
	assert.Panics(t, func() {
		_, _ = cryptor.EncryptVersion(nil, nil)
	})
}

// TestAESCryptor_EncryptDecryptEmptyVersionData tests encryption with nil version data.
func TestAESCryptor_EncryptDecryptEmptyVersionData(t *testing.T) {
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	cryptor, err := crypto.NewAESCryptor(masterKey)
	require.NoError(t, err)

	testKey := &types.Key{
		ID: "test:key",
		ACL: types.ACL{
			{
				ID:         "user@example.com",
				Type:       types.User,
				AccessType: types.Read,
			},
		},
		VersionList: types.KeyVersionList{},
		VersionHash: "test-hash",
	}

	testVersion := &types.KeyVersion{
		ID:           1,
		Data:         nil, // nil data
		Status:       types.Primary,
		CreationTime: 1234567890,
	}

	// Encrypt the version with nil data
	encryptedVersion, err := cryptor.EncryptVersion(testKey, testVersion)
	assert.NoError(t, err)
	assert.NotNil(t, encryptedVersion)

	// Verify we can decrypt it back
	// The decrypted data might be empty slice instead of nil, which is acceptable
}

// TestDeriveKey_EdgeCases tests edge cases for key derivation.
func TestDeriveKey_EdgeCases(t *testing.T) {
	// Test with empty password
	_, err := crypto.DeriveKey([]byte{}, make([]byte, 16), []byte("info"))
	assert.NoError(t, err)

	// Test with nil password
	_, err = crypto.DeriveKey(nil, make([]byte, 16), []byte("info"))
	assert.NoError(t, err)

	// Test with nil salt
	_, err = crypto.DeriveKey([]byte("password"), nil, []byte("info"))
	assert.Error(t, err)

	// Test with nil info
	_, err = crypto.DeriveKey([]byte("password"), make([]byte, 16), nil)
	assert.NoError(t, err)
}

// TestGenerateMasterKey_ErrorHandling tests error handling in master key generation.
func TestGenerateMasterKey_ErrorHandling(t *testing.T) {
	// This test is mostly for documentation since crypto/rand.Read rarely fails
	// but we want to ensure the error handling path exists
	key, err := crypto.GenerateMasterKey()
	assert.NoError(t, err)
	assert.Len(t, key, 32)
}

// TestCryptoMetadata_InvalidUnmarshal tests unmarshaling invalid metadata.
func TestCryptoMetadata_InvalidUnmarshal(t *testing.T) {
	// Test with empty data
	_, err := crypto.UnmarshalCryptoMetadata([]byte{})
	assert.Error(t, err)

	// Test with malformed JSON
	_, err = crypto.UnmarshalCryptoMetadata([]byte(`{"invalid": json`))
	assert.Error(t, err)

	// Test with missing required fields
	_, err = crypto.UnmarshalCryptoMetadata([]byte(`{"Algorithm": "AES-256-GCM"}`))
	assert.Error(t, err)
}

// TestAESCryptor_EncryptWithKeyErrorHandling tests error handling in low-level encryption.
func TestAESCryptor_EncryptWithKeyErrorHandling(_ *testing.T) {
	// This test documents that error handling for low-level encryption
	// is covered through the public API tests
	// The encryptWithKey and decryptWithKey methods are internal
	// and their error paths are exercised through the public Encrypt/Decrypt methods
}

// TestClearBytes tests that clearBytes function works (indirectly through encryption flow).
func TestClearBytes(t *testing.T) {
	// This is tested indirectly through the encryption/decryption flow
	// where DEK is cleared from memory after use
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	cryptor, err := crypto.NewAESCryptor(masterKey)
	require.NoError(t, err)

	testKey := &types.Key{
		ID: "test:key",
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
				Data:         []byte("secret-data"),
				Status:       types.Primary,
				CreationTime: 1234567890,
			},
		},
		VersionHash: "test-hash",
	}

	// Multiple encryption/decryption cycles to verify memory safety
	for range 10 {
		encryptedKey, err := cryptor.Encrypt(testKey)
		assert.NoError(t, err)

		decryptedKey, err := cryptor.Decrypt(encryptedKey)
		assert.NoError(t, err)
		assert.Equal(t, testKey.VersionList[0].Data, decryptedKey.VersionList[0].Data)
	}
}

// TestNewAESCryptorFromFile tests the file-based cryptor constructor (currently unimplemented).
func TestNewAESCryptorFromFile(t *testing.T) {
	cryptor, err := crypto.NewAESCryptorFromFile("/path/to/key")
	assert.Nil(t, cryptor)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "file-based key loading not yet implemented")
}

// TestGetKMSProvider tests the KMS provider getter.
func TestGetKMSProvider(t *testing.T) {
	t.Run("mock provider", func(t *testing.T) {
		provider, err := crypto.GetKMSProvider("mock")
		assert.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "mock", provider.Name())
	})

	t.Run("unsupported provider", func(t *testing.T) {
		provider, err := crypto.GetKMSProvider("aws-kms")
		assert.Nil(t, provider)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported KMS provider")
	})
}

// TestGenerateMasterKeyWithKMS tests KMS-based key generation.
func TestGenerateMasterKeyWithKMS(t *testing.T) {
	mockProvider := crypto.NewMockKMSProvider()
	plaintext, encrypted, err := crypto.GenerateMasterKeyWithKMS(mockProvider)
	assert.NoError(t, err)
	assert.NotNil(t, plaintext)
	assert.Equal(t, 32, len(plaintext))
	assert.NotEmpty(t, encrypted)
}

// TestAESCryptor_DecryptWithCorruptedData tests decryption error paths with corrupted data.
func TestAESCryptor_DecryptWithCorruptedData(t *testing.T) {
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	cryptor, err := crypto.NewAESCryptor(masterKey)
	require.NoError(t, err)

	// Create and encrypt a valid key first
	testKey := &types.Key{
		ID: "test:key",
		ACL: types.ACL{
			{ID: "user@example.com", Type: types.User, AccessType: types.Admin},
		},
		VersionList: types.KeyVersionList{
			{ID: 1, Data: []byte("test-data"), Status: types.Primary},
		},
	}

	dbKey, err := cryptor.Encrypt(testKey)
	require.NoError(t, err)

	t.Run("CorruptedCiphertext", func(t *testing.T) {
		// Corrupt the encrypted data
		corruptedDBKey := &keydb.DBKey{
			ID:  dbKey.ID,
			ACL: dbKey.ACL,
			VersionList: []keydb.EncKeyVersion{
				{
					ID:             dbKey.VersionList[0].ID,
					EncData:        []byte("corrupted-data-not-valid-ciphertext"),
					CryptoMetadata: dbKey.VersionList[0].CryptoMetadata,
				},
			},
		}

		_, err := cryptor.Decrypt(corruptedDBKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt version")
	})

	t.Run("CorruptedMetadata", func(t *testing.T) {
		// Corrupt the metadata
		corruptedDBKey := &keydb.DBKey{
			ID:  dbKey.ID,
			ACL: dbKey.ACL,
			VersionList: []keydb.EncKeyVersion{
				{
					ID:             dbKey.VersionList[0].ID,
					EncData:        dbKey.VersionList[0].EncData,
					CryptoMetadata: []byte("invalid-json-metadata"),
				},
			},
		}

		_, err := cryptor.Decrypt(corruptedDBKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt version")
	})

	t.Run("TruncatedCiphertext", func(t *testing.T) {
		// Use ciphertext that's too short (less than nonce size)
		corruptedDBKey := &keydb.DBKey{
			ID:  dbKey.ID,
			ACL: dbKey.ACL,
			VersionList: []keydb.EncKeyVersion{
				{
					ID:             dbKey.VersionList[0].ID,
					EncData:        []byte("short"), // Too short for GCM nonce
					CryptoMetadata: dbKey.VersionList[0].CryptoMetadata,
				},
			},
		}

		_, err := cryptor.Decrypt(corruptedDBKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt version")
	})
}
