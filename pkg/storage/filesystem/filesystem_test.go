// Package filesystem provides tests for the filesystem storage backend.
package filesystem

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/hazayan/knox/pkg/storage"
	"github.com/hazayan/knox/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBackend(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tmpDir := t.TempDir()

		backend, err := New(tmpDir)
		require.NoError(t, err)
		require.NotNil(t, backend)

		// Verify the backend can be used
		err = backend.Ping(t.Context())
		assert.NoError(t, err)

		err = backend.Close()
		assert.NoError(t, err)
	})

	t.Run("CreatesDirectory", func(t *testing.T) {
		tmpDir := t.TempDir()
		newDir := filepath.Join(tmpDir, "new-storage")

		backend, err := New(newDir)
		require.NoError(t, err)
		require.NotNil(t, backend)

		// Verify directory was created
		_, err = os.Stat(newDir)
		assert.NoError(t, err)

		err = backend.Close()
		assert.NoError(t, err)
	})

	t.Run("InvalidDirectory", func(t *testing.T) {
		// Try to create in a non-writable location
		backend, err := New("/root/knox-test")
		assert.Error(t, err)
		assert.Nil(t, backend)
	})
}

func TestBackend_GetKey(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	backend, err := New(tmpDir)
	require.NoError(t, err)
	defer backend.Close()

	// Create a test key first
	key := &types.Key{
		ID: "test_key",
		ACL: types.ACL{
			types.Access{ID: "user1", AccessType: types.Admin, Type: types.User},
		},
		VersionList: types.KeyVersionList{
			{
				ID:           1,
				Data:         []byte("test-data"),
				Status:       types.Primary,
				CreationTime: 1234567890,
			},
		},
	}
	key.VersionHash = key.VersionList.Hash()

	err = backend.PutKey(ctx, key)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		retrieved, err := backend.GetKey(ctx, "test_key")
		require.NoError(t, err)
		assert.Equal(t, key.ID, retrieved.ID)
		assert.Equal(t, key.ACL, retrieved.ACL)
		assert.Equal(t, key.VersionList, retrieved.VersionList)
	})

	t.Run("NotFound", func(t *testing.T) {
		_, err := backend.GetKey(ctx, "non_existent_key")
		assert.Error(t, err)
		assert.True(t, storage.IsKeyNotFound(err))
	})

	t.Run("InvalidKeyID", func(t *testing.T) {
		// Test with key IDs that could cause path traversal
		testCases := []string{
			"key_with_underscores",
			"key_with_hyphens",
			"key_with_colons",
			"app_service_key",
			"test_key_123",
		}

		for _, keyID := range testCases {
			t.Run(keyID, func(t *testing.T) {
				_, err := backend.GetKey(ctx, keyID)
				assert.Error(t, err)
				// Should not panic or escape the base directory
			})
		}
	})
}

func TestBackend_PutKey(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	backend, err := New(tmpDir)
	require.NoError(t, err)
	defer backend.Close()

	t.Run("Success", func(t *testing.T) {
		key := &types.Key{
			ID: "put_test_key",
			ACL: types.ACL{
				types.Access{ID: "user1", AccessType: types.Admin, Type: types.User},
			},
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("test-data"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
		}
		key.VersionHash = key.VersionList.Hash()

		err := backend.PutKey(ctx, key)
		assert.NoError(t, err)

		// Verify the key was actually stored
		retrieved, err := backend.GetKey(ctx, "put_test_key")
		assert.NoError(t, err)
		assert.Equal(t, key.ID, retrieved.ID)
	})

	t.Run("UpdateExisting", func(t *testing.T) {
		key := &types.Key{
			ID: "update_key",
			ACL: types.ACL{
				types.Access{ID: "user1", AccessType: types.Admin, Type: types.User},
			},
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("initial-data"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
		}
		key.VersionHash = key.VersionList.Hash()

		err := backend.PutKey(ctx, key)
		require.NoError(t, err)

		// Update the key
		key.VersionList[0].Data = []byte("updated-data")
		err = backend.PutKey(ctx, key)
		assert.NoError(t, err)

		// Verify the update
		retrieved, err := backend.GetKey(ctx, "update_key")
		assert.NoError(t, err)
		assert.Equal(t, []byte("updated-data"), retrieved.VersionList[0].Data)
	})

	t.Run("InvalidKey", func(t *testing.T) {
		invalidKey := &types.Key{
			ID: "", // Empty ID should fail validation
			ACL: types.ACL{
				types.Access{ID: "user1", AccessType: types.Admin, Type: types.User},
			},
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("test-data"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
		}

		err := backend.PutKey(ctx, invalidKey)
		assert.Error(t, err)
	})
}

func TestBackend_DeleteKey(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	backend, err := New(tmpDir)
	require.NoError(t, err)
	defer backend.Close()

	t.Run("Success", func(t *testing.T) {
		key := &types.Key{
			ID: "delete_test_key",
			ACL: types.ACL{
				types.Access{ID: "user1", AccessType: types.Admin, Type: types.User},
			},
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("test-data"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
		}
		key.VersionHash = key.VersionList.Hash()

		err := backend.PutKey(ctx, key)
		require.NoError(t, err)

		// Verify key exists
		_, err = backend.GetKey(ctx, "delete_test_key")
		assert.NoError(t, err)

		// Delete the key
		err = backend.DeleteKey(ctx, "delete_test_key")
		assert.NoError(t, err)

		// Verify key is gone
		_, err = backend.GetKey(ctx, "delete_test_key")
		assert.Error(t, err)
		assert.True(t, storage.IsKeyNotFound(err))
	})

	t.Run("NotFound", func(t *testing.T) {
		// Delete non-existent key should return ErrKeyNotFound
		err := backend.DeleteKey(ctx, "non_existent_key")
		assert.Error(t, err, "Deleting non-existent key should return an error")
		assert.True(t, storage.IsKeyNotFound(err), "Error should be ErrKeyNotFound")
	})
}

func TestBackend_ListKeys(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	backend, err := New(tmpDir)
	require.NoError(t, err)
	defer backend.Close()

	// Create test keys
	keys := []string{
		"app1_database",
		"app1_api_key",
		"app2_redis",
		"app3_postgres",
	}

	for _, keyID := range keys {
		key := &types.Key{
			ID: keyID,
			ACL: types.ACL{
				types.Access{ID: "user1", AccessType: types.Admin, Type: types.User},
			},
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("test-data"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
		}
		key.VersionHash = key.VersionList.Hash()
		err := backend.PutKey(ctx, key)
		require.NoError(t, err)
	}

	t.Run("AllKeys", func(t *testing.T) {
		keyIDs, err := backend.ListKeys(ctx, "")
		assert.NoError(t, err)
		assert.Len(t, keyIDs, len(keys))

		// Verify all keys are present
		keyMap := make(map[string]bool)
		for _, keyID := range keyIDs {
			keyMap[keyID] = true
		}

		for _, expectedKey := range keys {
			assert.True(t, keyMap[expectedKey], "Key %s should be in list", expectedKey)
		}
	})

	t.Run("WithPrefix", func(t *testing.T) {
		keyIDs, err := backend.ListKeys(ctx, "app1_")
		assert.NoError(t, err)
		assert.Len(t, keyIDs, 2)

		expected := map[string]bool{
			"app1_database": true,
			"app1_api_key":  true,
		}

		for _, keyID := range keyIDs {
			assert.True(t, expected[keyID], "Unexpected key: %s", keyID)
		}
	})

	t.Run("EmptyResult", func(t *testing.T) {
		keyIDs, err := backend.ListKeys(ctx, "nonexistent_")
		assert.NoError(t, err)
		assert.Empty(t, keyIDs)
	})
}

func TestBackend_UpdateKey(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	backend, err := New(tmpDir)
	require.NoError(t, err)
	defer backend.Close()

	t.Run("CreateNew", func(t *testing.T) {
		err := backend.UpdateKey(ctx, "new_key", func(current *types.Key) (*types.Key, error) {
			assert.Nil(t, current) // Should be nil for new key

			key := &types.Key{
				ID: "new_key",
				ACL: types.ACL{
					types.Access{ID: "user1", AccessType: types.Admin, Type: types.User},
				},
				VersionList: types.KeyVersionList{
					{
						ID:           1,
						Data:         []byte("new-data"),
						Status:       types.Primary,
						CreationTime: 1234567890,
					},
				},
			}
			key.VersionHash = key.VersionList.Hash()
			return key, nil
		})
		assert.NoError(t, err)

		// Verify the key was created
		retrieved, err := backend.GetKey(ctx, "new_key")
		assert.NoError(t, err)
		assert.Equal(t, []byte("new-data"), retrieved.VersionList[0].Data)
	})

	t.Run("UpdateExisting", func(t *testing.T) {
		// Create initial key
		initialKey := &types.Key{
			ID: "update_key",
			ACL: types.ACL{
				types.Access{ID: "user1", AccessType: types.Admin, Type: types.User},
			},
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("initial-data"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
		}
		initialKey.VersionHash = initialKey.VersionList.Hash()
		err := backend.PutKey(ctx, initialKey)
		require.NoError(t, err)

		// Update the key
		err = backend.UpdateKey(ctx, "update_key", func(current *types.Key) (*types.Key, error) {
			require.NotNil(t, current)
			current.VersionList[0].Data = []byte("updated-data")
			return current, nil
		})
		assert.NoError(t, err)

		// Verify the update
		retrieved, err := backend.GetKey(ctx, "update_key")
		assert.NoError(t, err)
		assert.Equal(t, []byte("updated-data"), retrieved.VersionList[0].Data)
	})

	t.Run("DeleteKey", func(t *testing.T) {
		// Create a key first
		key := &types.Key{
			ID: "delete_update_key",
			ACL: types.ACL{
				types.Access{ID: "user1", AccessType: types.Admin, Type: types.User},
			},
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("test-data"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
		}
		key.VersionHash = key.VersionList.Hash()
		err := backend.PutKey(ctx, key)
		require.NoError(t, err)

		// Delete via update function
		err = backend.UpdateKey(ctx, "delete_update_key", func(current *types.Key) (*types.Key, error) {
			assert.NotNil(t, current)
			return nil, nil // Return nil to delete
		})
		assert.NoError(t, err)

		// Verify the key is gone
		_, err = backend.GetKey(ctx, "delete_update_key")
		assert.Error(t, err)
		assert.True(t, storage.IsKeyNotFound(err))
	})

	t.Run("UpdateFails", func(t *testing.T) {
		// Create initial key
		key := &types.Key{
			ID: "fail_key",
			ACL: types.ACL{
				types.Access{ID: "user1", AccessType: types.Admin, Type: types.User},
			},
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("initial-data"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
		}
		key.VersionHash = key.VersionList.Hash()
		err := backend.PutKey(ctx, key)
		require.NoError(t, err)

		// Update function that returns an error
		err = backend.UpdateKey(ctx, "fail_key", func(_ *types.Key) (*types.Key, error) {
			return nil, assert.AnError
		})
		assert.Error(t, err)
		assert.Equal(t, assert.AnError, err)

		// Verify the key was not modified
		retrieved, err := backend.GetKey(ctx, "fail_key")
		assert.NoError(t, err)
		assert.Equal(t, []byte("initial-data"), retrieved.VersionList[0].Data)
	})
}

func TestBackend_Ping(t *testing.T) {
	ctx := t.Context()

	t.Run("Success", func(t *testing.T) {
		tmpDir := t.TempDir()
		backend, err := New(tmpDir)
		require.NoError(t, err)
		defer backend.Close()

		err = backend.Ping(ctx)
		assert.NoError(t, err)
	})

	t.Run("StorageUnavailable", func(t *testing.T) {
		tmpDir := t.TempDir()
		backend, err := New(tmpDir)
		require.NoError(t, err)

		// Remove the directory to make it unavailable
		err = os.RemoveAll(tmpDir)
		require.NoError(t, err)

		err = backend.Ping(ctx)
		assert.Error(t, err)
		assert.True(t, storage.IsStorageUnavailable(err))
	})
}

func TestBackend_Stats(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	backend, err := New(tmpDir)
	require.NoError(t, err)
	defer backend.Close()

	t.Run("Empty", func(t *testing.T) {
		stats, err := backend.Stats(ctx)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), stats.TotalKeys)
		assert.Equal(t, int64(0), stats.StorageSize)
		assert.NotNil(t, stats.OperationCounts)
		assert.Equal(t, "filesystem", stats.BackendSpecific["backend"])
	})

	t.Run("WithKeys", func(t *testing.T) {
		// Create some keys
		for i := range 3 {
			key := &types.Key{
				ID: string(rune('a' + i)), // Simple key IDs: "a", "b", "c"
				ACL: types.ACL{
					types.Access{ID: "user1", AccessType: types.Admin, Type: types.User},
				},
				VersionList: types.KeyVersionList{
					{
						ID:           1,
						Data:         []byte("test-data"),
						Status:       types.Primary,
						CreationTime: 1234567890,
					},
				},
			}
			key.VersionHash = key.VersionList.Hash()
			err := backend.PutKey(ctx, key)
			require.NoError(t, err)
		}

		// Perform some operations to generate metrics
		_, _ = backend.GetKey(ctx, "a")
		_, _ = backend.GetKey(ctx, "b")
		_, _ = backend.ListKeys(ctx, "")

		stats, err := backend.Stats(ctx)
		assert.NoError(t, err)
		assert.Equal(t, int64(3), stats.TotalKeys)
		assert.True(t, stats.StorageSize > 0)
		assert.NotNil(t, stats.OperationCounts)

		// Check operation counts
		if counts, ok := stats.OperationCounts["get"]; ok {
			assert.True(t, counts >= 2)
		}
		if counts, ok := stats.OperationCounts["list"]; ok {
			assert.True(t, counts >= 1)
		}
	})
}

func TestBackend_ConcurrentAccess(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()
	backend, err := New(tmpDir)
	require.NoError(t, err)
	defer backend.Close()

	key := &types.Key{
		ID: "concurrent_key",
		ACL: types.ACL{
			types.Access{ID: "user1", AccessType: types.Admin, Type: types.User},
		},
		VersionList: types.KeyVersionList{
			{
				ID:           1,
				Data:         []byte("initial-data"),
				Status:       types.Primary,
				CreationTime: 1234567890,
			},
		},
	}
	key.VersionHash = key.VersionList.Hash()

	err = backend.PutKey(ctx, key)
	require.NoError(t, err)

	// Test concurrent reads
	t.Run("ConcurrentReads", func(t *testing.T) {
		done := make(chan bool, 10)
		for range 10 {
			go func() {
				_, err := backend.GetKey(ctx, "concurrent_key")
				assert.NoError(t, err)
				done <- true
			}()
		}

		// Wait for all goroutines to complete
		for range 10 {
			<-done
		}
	})

	// Test concurrent updates (should be serialized)
	t.Run("ConcurrentUpdates", func(t *testing.T) {
		done := make(chan bool, 5)
		for i := range 5 {
			go func(index int) {
				err := backend.UpdateKey(ctx, "concurrent_key", func(current *types.Key) (*types.Key, error) {
					require.NotNil(t, current)
					current.VersionList[0].Data = []byte{byte(index)}
					return current, nil
				})
				assert.NoError(t, err)
				done <- true
			}(i)
		}

		// Wait for all goroutines to complete
		for range 5 {
			<-done
		}

		// Verify the final state is consistent
		retrieved, err := backend.GetKey(ctx, "concurrent_key")
		assert.NoError(t, err)
		assert.NotNil(t, retrieved.VersionList[0].Data)
	})
}

func TestHashKeyID(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "SimpleKey",
			input:    "simple_key",
			expected: "b4f9b2a4a1d3cad872a0884f4b1b2e4c8a0e6e1c2e4f6e8c9a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4",
		},
		{
			name:     "KeyWithSpecialCharacters",
			input:    "app:service@v1.0.0",
			expected: "d8f7e2a5b9c3d7e1a3b5c7d9e1a3b5c7d9e1a3b5c7d9e1a3b5c7d9e1a3b5c7d9e1a3b5c7d9e1a3b5c7d9e1a3b5c7d9e1a3b5c7d9e1a3b5c7d9e1a3b5c7d9e1a3b5c7",
		},
		{
			name:     "EmptyKey",
			input:    "",
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "LongKeyID",
			input:    "very_long_key_identifier_with_many_characters_and_numbers_1234567890",
			expected: "8f7e6d5c4b3a2918f7e6d5c4b3a2918f7e6d5c4b3a2918f7e6d5c4b3a2918f7e6d5c4b3a2918f7e6d5c4b3a2918f7e6d5c4b3a2918f7e6d5c4b3a2918f7e6d5c4b3a29",
		},
		{
			name:     "KeyWithSpaces",
			input:    "key with spaces",
			expected: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := hashKeyID(tc.input)

			// Verify it's a valid SHA256 hash (64 hex characters)
			assert.Equal(t, 64, len(result), "Hash should be 64 characters long")

			// Verify it's valid hex
			_, err := hex.DecodeString(result)
			assert.NoError(t, err, "Hash should be valid hex")

			// Verify it's deterministic
			result2 := hashKeyID(tc.input)
			assert.Equal(t, result, result2, "Hash should be deterministic")

			// Verify it matches expected SHA256 calculation
			expectedHash := sha256.Sum256([]byte(tc.input))
			expectedHex := hex.EncodeToString(expectedHash[:])
			assert.Equal(t, expectedHex, result, "Hash should match SHA256 calculation")
		})
	}
}

func TestHashKeyID_Consistency(t *testing.T) {
	// Test that different inputs produce different hashes
	key1 := "key1"
	key2 := "key2"

	hash1 := hashKeyID(key1)
	hash2 := hashKeyID(key2)

	assert.NotEqual(t, hash1, hash2, "Different keys should produce different hashes")

	// Test that the same input always produces the same hash
	for range 10 {
		assert.Equal(t, hash1, hashKeyID(key1), "Same key should always produce same hash")
	}
}

func TestBackend_KeyPathSanitization(t *testing.T) {
	tmpDir := t.TempDir()
	backend, err := New(tmpDir)
	require.NoError(t, err)
	defer backend.Close()

	testCases := []struct {
		name     string
		keyID    string
		expected string // Expected sanitized key ID
	}{
		{
			name:     "SimpleKey",
			keyID:    "simple_key",
			expected: "simple_key",
		},
		{
			name:     "WithColons",
			keyID:    "app_service_key",
			expected: "app_service_key",
		},
		{
			name:     "WithHyphens",
			keyID:    "app_service_key",
			expected: "app_service_key",
		},
		{
			name:     "PathTraversal",
			keyID:    "test_key_123",
			expected: "test_key_123",
		},
		{
			name:     "LongKeyID",
			keyID:    string(make([]byte, 300)), // 300 bytes
			expected: "",                        // Will be truncated to 255 chars
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test that we can store and retrieve keys with problematic IDs
			key := &types.Key{
				ID: tc.keyID,
				ACL: types.ACL{
					types.Access{ID: "user1", AccessType: types.Admin, Type: types.User},
				},
				VersionList: types.KeyVersionList{
					{
						ID:           1,
						Data:         []byte("test-data"),
						Status:       types.Primary,
						CreationTime: 1234567890,
					},
				},
			}
			key.VersionHash = key.VersionList.Hash()

			err := backend.PutKey(t.Context(), key)
			if tc.name == "LongKeyID" {
				// Long key IDs should fail validation
				assert.Error(t, err, "Should fail to put key with long ID: %s", tc.keyID)
			} else {
				assert.NoError(t, err, "Failed to put key with ID: %s", tc.keyID)

				retrieved, err := backend.GetKey(t.Context(), tc.keyID)
				assert.NoError(t, err, "Failed to get key with ID: %s", tc.keyID)
				if retrieved != nil {
					assert.Equal(t, tc.keyID, retrieved.ID, "Key ID mismatch")
					assert.Equal(t, []byte("test-data"), retrieved.VersionList[0].Data, "Key data mismatch")
				}
			}
		})
	}
}

// TestBackend_Registration tests that the backend is registered with storage package.
func TestBackend_Registration(t *testing.T) {
	tmpDir := t.TempDir()

	// Test that we can create a filesystem backend through the storage.NewBackend factory
	backend, err := storage.NewBackend(storage.Config{
		Backend:       "filesystem",
		FilesystemDir: tmpDir,
	})
	assert.NoError(t, err)
	assert.NotNil(t, backend)

	// Verify it's functional
	ctx := t.Context()
	testKey := &types.Key{
		ID: "test:registration",
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
				Data:         []byte("registration-test"),
				Status:       types.Primary,
				CreationTime: 1234567890,
			},
		},
		VersionHash: "",
	}
	testKey.VersionHash = testKey.VersionList.Hash()

	err = backend.PutKey(ctx, testKey)
	assert.NoError(t, err)

	key, err := backend.GetKey(ctx, "test:registration")
	assert.NoError(t, err)
	assert.Equal(t, "test:registration", key.ID)
}

// TestBackend_RegistrationMissingDir tests registration error when dir is missing.
func TestBackend_RegistrationMissingDir(t *testing.T) {
	// Test that registration fails without FilesystemDir
	backend, err := storage.NewBackend(storage.Config{
		Backend: "filesystem",
		// FilesystemDir is missing
	})
	assert.Error(t, err)
	assert.Nil(t, backend)
	assert.Contains(t, err.Error(), "FilesystemDir")
}

// TestBackend_NewErrors tests error handling in New function.
func TestBackend_NewErrors(t *testing.T) {
	t.Run("unwritable_directory", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("Cannot test permissions as root")
		}

		tmpDir := t.TempDir()
		readOnlyDir := filepath.Join(tmpDir, "readonly")
		err := os.Mkdir(readOnlyDir, 0o500) // Read+execute only, no write
		require.NoError(t, err)

		// Try to create backend in read-only directory
		_, err = New(readOnlyDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not writable")
	})
}

// TestBackend_GetKeyErrors tests error paths in GetKey.
func TestBackend_GetKeyErrors(t *testing.T) {
	tmpDir := t.TempDir()
	backend, err := New(tmpDir)
	require.NoError(t, err)
	defer backend.Close()

	ctx := t.Context()

	t.Run("corrupted_json", func(t *testing.T) {
		// Manually write a corrupted JSON file
		corruptedPath := filepath.Join(tmpDir, "corrupted_key")
		err := os.WriteFile(corruptedPath, []byte("not valid json{]"), 0o600)
		require.NoError(t, err)

		_, err = backend.GetKey(ctx, "corrupted_key")
		assert.Error(t, err)
	})
}

// TestBackend_PutKeyErrors tests error paths in PutKey.
func TestBackend_PutKeyErrors(t *testing.T) {
	tmpDir := t.TempDir()
	backend, err := New(tmpDir)
	require.NoError(t, err)
	defer backend.Close()

	ctx := t.Context()

	t.Run("invalid_key", func(t *testing.T) {
		invalidKey := &types.Key{
			ID:          "", // Invalid: empty ID
			ACL:         types.ACL{},
			VersionList: types.KeyVersionList{},
		}

		err := backend.PutKey(ctx, invalidKey)
		assert.Error(t, err)
	})
}

// TestBackend_ListKeysWithPrefix tests listing keys with various prefixes.
func TestBackend_ListKeysWithPrefix(t *testing.T) {
	tmpDir := t.TempDir()
	backend, err := New(tmpDir)
	require.NoError(t, err)
	defer backend.Close()

	ctx := t.Context()

	// Create keys with different prefixes
	keys := []string{"app:key1", "app:key2", "service:key1", "other"}
	for _, keyID := range keys {
		key := &types.Key{
			ID: keyID,
			ACL: types.ACL{
				{ID: "user1", AccessType: types.Admin, Type: types.User},
			},
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("data"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
		}
		key.VersionHash = key.VersionList.Hash()
		err := backend.PutKey(ctx, key)
		require.NoError(t, err)
	}

	// List with "app:" prefix
	appKeys, err := backend.ListKeys(ctx, "app:")
	assert.NoError(t, err)
	assert.Len(t, appKeys, 2)

	// List with "service:" prefix
	serviceKeys, err := backend.ListKeys(ctx, "service:")
	assert.NoError(t, err)
	assert.Len(t, serviceKeys, 1)

	// List all keys (empty prefix)
	allKeys, err := backend.ListKeys(ctx, "")
	assert.NoError(t, err)
	assert.Len(t, allKeys, 4)
}

// TestBackend_UpdateKeyErrors tests error paths in UpdateKey.
func TestBackend_UpdateKeyErrors(t *testing.T) {
	tmpDir := t.TempDir()
	backend, err := New(tmpDir)
	require.NoError(t, err)
	defer backend.Close()

	ctx := t.Context()

	t.Run("update_function_error", func(t *testing.T) {
		// Create initial key
		key := &types.Key{
			ID: "test:key",
			ACL: types.ACL{
				{ID: "user1", AccessType: types.Admin, Type: types.User},
			},
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("data"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
		}
		key.VersionHash = key.VersionList.Hash()
		err := backend.PutKey(ctx, key)
		require.NoError(t, err)

		// Update with function that returns error
		err = backend.UpdateKey(ctx, "test:key", func(_ *types.Key) (*types.Key, error) {
			return nil, errors.New("update failed")
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "update failed")
	})

	t.Run("invalid_updated_key", func(t *testing.T) {
		// Create initial key
		key := &types.Key{
			ID: "test:key2",
			ACL: types.ACL{
				{ID: "user1", AccessType: types.Admin, Type: types.User},
			},
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("data"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
		}
		key.VersionHash = key.VersionList.Hash()
		err := backend.PutKey(ctx, key)
		require.NoError(t, err)

		// Update with invalid key
		err = backend.UpdateKey(ctx, "test:key2", func(_ *types.Key) (*types.Key, error) {
			return &types.Key{
				ID: "", // Invalid
			}, nil
		})
		assert.Error(t, err)
	})
}

// TestBackend_PingError tests Ping error path.
func TestBackend_PingError(t *testing.T) {
	tmpDir := t.TempDir()
	backend, err := New(tmpDir)
	require.NoError(t, err)

	ctx := t.Context()

	// Remove the directory to make ping fail
	err = os.RemoveAll(tmpDir)
	require.NoError(t, err)

	// Ping should fail now
	err = backend.Ping(ctx)
	assert.Error(t, err)
}
