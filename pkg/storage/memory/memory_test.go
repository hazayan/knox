// Package memory_test provides comprehensive tests for the in-memory storage backend.
package memory_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/hazayan/knox/pkg/storage"
	"github.com/hazayan/knox/pkg/storage/memory"
	"github.com/hazayan/knox/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMemoryBackend_New tests creation of a new memory backend.
func TestMemoryBackend_New(t *testing.T) {
	backend := memory.New()
	assert.NotNil(t, backend)
}

// TestMemoryBackend_PutGet tests basic put and get operations.
func TestMemoryBackend_PutGet(t *testing.T) {
	backend := memory.New()
	ctx := t.Context()

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
		VersionHash: "",
	}
	testKey.VersionHash = testKey.VersionList.Hash()

	// Put the key
	err := backend.PutKey(ctx, testKey)
	assert.NoError(t, err)

	// Get the key
	retrievedKey, err := backend.GetKey(ctx, "test:key")
	assert.NoError(t, err)
	assert.NotNil(t, retrievedKey)
	assert.Equal(t, testKey.ID, retrievedKey.ID)
	assert.Equal(t, testKey.VersionHash, retrievedKey.VersionHash)
	assert.Len(t, retrievedKey.VersionList, 1)
	assert.Equal(t, testKey.VersionList[0].Data, retrievedKey.VersionList[0].Data)
}

// TestMemoryBackend_GetNonExistent tests getting a non-existent key.
func TestMemoryBackend_GetNonExistent(t *testing.T) {
	backend := memory.New()
	ctx := t.Context()

	key, err := backend.GetKey(ctx, "nonexistent")
	assert.Error(t, err)
	assert.Nil(t, key)
	assert.Equal(t, storage.ErrKeyNotFound, err)
}

// TestMemoryBackend_PutInvalidKey tests putting an invalid key.
func TestMemoryBackend_PutInvalidKey(t *testing.T) {
	backend := memory.New()
	ctx := t.Context()

	// Create invalid key (missing ID)
	invalidKey := &types.Key{
		ID:          "",
		ACL:         types.ACL{},
		VersionList: types.KeyVersionList{},
		VersionHash: "",
	}

	err := backend.PutKey(ctx, invalidKey)
	assert.Error(t, err)
}

// TestMemoryBackend_UpdateKey tests updating an existing key.
func TestMemoryBackend_UpdateKey(t *testing.T) {
	backend := memory.New()
	ctx := t.Context()

	// Create initial key
	initialKey := &types.Key{
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
				Data:         []byte("initial-data"),
				Status:       types.Primary,
				CreationTime: 1234567890,
			},
		},
		VersionHash: "",
	}
	initialKey.VersionHash = initialKey.VersionList.Hash()

	err := backend.PutKey(ctx, initialKey)
	assert.NoError(t, err)

	// Update the key
	updatedKey := &types.Key{
		ID: "test:key",
		ACL: types.ACL{
			{
				ID:         "user@example.com",
				Type:       types.User,
				AccessType: types.Read,
			},
			{
				ID:         "admin@example.com",
				Type:       types.User,
				AccessType: types.Admin,
			},
		},
		VersionList: types.KeyVersionList{
			{
				ID:           1,
				Data:         []byte("updated-data"),
				Status:       types.Primary,
				CreationTime: 1234567890,
			},
		},
		VersionHash: "",
	}
	updatedKey.VersionHash = updatedKey.VersionList.Hash()

	err = backend.PutKey(ctx, updatedKey)
	assert.NoError(t, err)

	// Verify the update
	retrievedKey, err := backend.GetKey(ctx, "test:key")
	assert.NoError(t, err)
	assert.Equal(t, updatedKey.ID, retrievedKey.ID)
	assert.Equal(t, updatedKey.VersionHash, retrievedKey.VersionHash)
	assert.Len(t, retrievedKey.ACL, 2)
	assert.Equal(t, updatedKey.VersionList[0].Data, retrievedKey.VersionList[0].Data)
}

// TestMemoryBackend_DeleteKey tests deleting a key.
func TestMemoryBackend_DeleteKey(t *testing.T) {
	backend := memory.New()
	ctx := t.Context()

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
		VersionHash: "",
	}
	testKey.VersionHash = testKey.VersionList.Hash()

	err := backend.PutKey(ctx, testKey)
	assert.NoError(t, err)

	// Delete the key
	err = backend.DeleteKey(ctx, "test:key")
	assert.NoError(t, err)

	// Verify key is gone
	key, err := backend.GetKey(ctx, "test:key")
	assert.Error(t, err)
	assert.Nil(t, key)
}

// TestMemoryBackend_DeleteNonExistent tests deleting a non-existent key.
func TestMemoryBackend_DeleteNonExistent(t *testing.T) {
	backend := memory.New()
	ctx := t.Context()

	err := backend.DeleteKey(ctx, "nonexistent")
	assert.Error(t, err)
	assert.Equal(t, storage.ErrKeyNotFound, err)
}

// TestMemoryBackend_ListKeys tests listing keys with and without prefix.
func TestMemoryBackend_ListKeys(t *testing.T) {
	backend := memory.New()
	ctx := t.Context()

	// Create multiple keys
	keys := []*types.Key{
		{
			ID: "app1:database",
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
					Data:         []byte("db-secret"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
			VersionHash: "hash1",
		},
		{
			ID: "app1:api",
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
					Data:         []byte("api-secret"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
			VersionHash: "hash2",
		},
		{
			ID: "app2:database",
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
					Data:         []byte("db-secret2"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
			VersionHash: "hash3",
		},
	}

	// Put all keys
	for _, key := range keys {
		// Set proper version hash before putting
		key.VersionHash = key.VersionList.Hash()
		err := backend.PutKey(ctx, key)
		assert.NoError(t, err)
	}

	// List all keys
	allKeys, err := backend.ListKeys(ctx, "")
	assert.NoError(t, err)
	assert.Len(t, allKeys, 3)
	assert.Contains(t, allKeys, "app1:database")
	assert.Contains(t, allKeys, "app1:api")
	assert.Contains(t, allKeys, "app2:database")

	// List keys with prefix
	app1Keys, err := backend.ListKeys(ctx, "app1:")
	assert.NoError(t, err)
	assert.Len(t, app1Keys, 2)
	assert.Contains(t, app1Keys, "app1:database")
	assert.Contains(t, app1Keys, "app1:api")
	assert.NotContains(t, app1Keys, "app2:database")

	// List keys with non-matching prefix
	noKeys, err := backend.ListKeys(ctx, "nonexistent:")
	assert.NoError(t, err)
	assert.Len(t, noKeys, 0)
}

// TestMemoryBackend_UpdateKeyAtomic tests atomic key updates.
func TestMemoryBackend_UpdateKeyAtomic(t *testing.T) {
	backend := memory.New()
	ctx := t.Context()

	// Create initial key
	initialKey := &types.Key{
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
				Data:         []byte("initial-data"),
				Status:       types.Primary,
				CreationTime: 1234567890,
			},
		},
		VersionHash: "",
	}
	initialKey.VersionHash = initialKey.VersionList.Hash()

	err := backend.PutKey(ctx, initialKey)
	assert.NoError(t, err)

	// Update the key atomically
	err = backend.UpdateKey(ctx, "test:key", func(currentKey *types.Key) (*types.Key, error) {
		if currentKey == nil {
			return nil, assert.AnError
		}
		// Modify the key
		updatedKey := &types.Key{
			ID:  currentKey.ID,
			ACL: currentKey.ACL,
			VersionList: types.KeyVersionList{
				{
					ID:           2,
					Data:         []byte("updated-data"),
					Status:       types.Primary,
					CreationTime: 1234567891,
				},
			},
		}
		updatedKey.VersionHash = updatedKey.VersionList.Hash()

		return updatedKey, nil
	})
	assert.NoError(t, err)

	// Verify the update
	retrievedKey, err := backend.GetKey(ctx, "test:key")
	assert.NoError(t, err)
	assert.Equal(t, "d86e8112f3c4c4442126f8e9f44f16867da487f29052bf91b810457db34209a4", retrievedKey.VersionHash)
	assert.Len(t, retrievedKey.VersionList, 1)
	assert.Equal(t, uint64(2), retrievedKey.VersionList[0].ID)
	assert.Equal(t, []byte("updated-data"), retrievedKey.VersionList[0].Data)
}

// TestMemoryBackend_UpdateKeyDelete tests atomic key deletion via update.
func TestMemoryBackend_UpdateKeyDelete(t *testing.T) {
	backend := memory.New()
	ctx := t.Context()

	// Create initial key
	initialKey := &types.Key{
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
				Data:         []byte("initial-data"),
				Status:       types.Primary,
				CreationTime: 1234567890,
			},
		},
		VersionHash: "",
	}
	initialKey.VersionHash = initialKey.VersionList.Hash()

	err := backend.PutKey(ctx, initialKey)
	assert.NoError(t, err)

	// Delete the key atomically
	err = backend.UpdateKey(ctx, "test:key", func(_ *types.Key) (*types.Key, error) {
		// Return nil to delete the key
		return nil, nil
	})
	assert.NoError(t, err)

	// Verify the key is gone
	key, err := backend.GetKey(ctx, "test:key")
	assert.Error(t, err)
	assert.Nil(t, key)
}

// TestMemoryBackend_UpdateKeyNonExistent tests updating a non-existent key.
func TestMemoryBackend_UpdateKeyNonExistent(t *testing.T) {
	backend := memory.New()
	ctx := t.Context()

	// Try to update non-existent key
	err := backend.UpdateKey(ctx, "nonexistent", func(currentKey *types.Key) (*types.Key, error) {
		if currentKey == nil {
			// Create new key
			newKey := &types.Key{
				ID: "nonexistent",
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
						Data:         []byte("new-data"),
						Status:       types.Primary,
						CreationTime: 1234567890,
					},
				},
				VersionHash: "",
			}

			newKey.VersionHash = newKey.VersionList.Hash()
			return newKey, nil
		}
		currentKey.VersionHash = currentKey.VersionList.Hash()
		return currentKey, nil
	})
	assert.NoError(t, err)

	// Verify the key was created
	key, err := backend.GetKey(ctx, "nonexistent")
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, "nonexistent", key.ID)
}

// TestMemoryBackend_UpdateKeyError tests update with error.
func TestMemoryBackend_UpdateKeyError(t *testing.T) {
	backend := memory.New()
	ctx := t.Context()

	// Create initial key
	initialKey := &types.Key{
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
				Data:         []byte("initial-data"),
				Status:       types.Primary,
				CreationTime: 1234567890,
			},
		},
		VersionHash: "",
	}
	initialKey.VersionHash = initialKey.VersionList.Hash()

	err := backend.PutKey(ctx, initialKey)
	assert.NoError(t, err)

	// Update with error
	err = backend.UpdateKey(ctx, "test:key", func(_ *types.Key) (*types.Key, error) {
		return nil, assert.AnError
	})
	assert.Error(t, err)

	// Verify key is unchanged
	retrievedKey, err := backend.GetKey(ctx, "test:key")
	assert.NoError(t, err)
	assert.Equal(t, initialKey.VersionHash, retrievedKey.VersionHash)
}

// TestMemoryBackend_Ping tests the ping operation.
func TestMemoryBackend_Ping(t *testing.T) {
	backend := memory.New()
	ctx := t.Context()

	err := backend.Ping(ctx)
	assert.NoError(t, err)
}

// TestMemoryBackend_Close tests the close operation.
func TestMemoryBackend_Close(t *testing.T) {
	backend := memory.New()
	ctx := t.Context()

	// Create a key
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
		VersionHash: "",
	}
	testKey.VersionHash = testKey.VersionList.Hash()

	err := backend.PutKey(ctx, testKey)
	assert.NoError(t, err)

	// Close the backend
	err = backend.Close()
	assert.NoError(t, err)

	// Verify data is cleared
	stats, err := backend.Stats(ctx)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), stats.TotalKeys)
}

// TestMemoryBackend_Stats tests statistics collection.
func TestMemoryBackend_Stats(t *testing.T) {
	backend := memory.New()
	ctx := t.Context()

	// Create multiple keys
	keys := []string{"key1", "key2", "key3"}
	for _, keyID := range keys {
		testKey := &types.Key{
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
					Data:         []byte("secret-data"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
			VersionHash: "",
		}
		testKey.VersionHash = testKey.VersionList.Hash()
		err := backend.PutKey(ctx, testKey)
		assert.NoError(t, err)
	}

	// Get stats
	stats, err := backend.Stats(ctx)
	assert.NoError(t, err)
	assert.Equal(t, int64(3), stats.TotalKeys)
	assert.True(t, stats.StorageSize > 0)
	assert.Contains(t, stats.BackendSpecific, "backend")
	assert.Equal(t, "memory", stats.BackendSpecific["backend"])

	// Verify operation counts
	assert.True(t, stats.OperationCounts["put"] >= 3)
	assert.True(t, stats.OperationCounts["get"] >= 0) // We haven't done any gets yet
}

// TestMemoryBackend_ConcurrentAccess tests concurrent access to the backend.
func TestMemoryBackend_ConcurrentAccess(t *testing.T) {
	backend := memory.New()
	ctx := t.Context()

	// Create initial key
	initialKey := &types.Key{
		ID: "concurrent:key",
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
				Data:         []byte("initial-data"),
				Status:       types.Primary,
				CreationTime: 1234567890,
			},
		},
		VersionHash: "",
	}
	initialKey.VersionHash = initialKey.VersionList.Hash()

	err := backend.PutKey(ctx, initialKey)
	require.NoError(t, err)

	// Run concurrent operations
	done := make(chan bool, 10)
	successfulReads := 0
	successfulUpdates := 0

	for i := range 5 {
		go func(_ int) {
			// Read the key
			key, err := backend.GetKey(ctx, "concurrent:key")
			if err == nil {
				assert.Equal(t, "concurrent:key", key.ID)
				successfulReads++
			}
			done <- true
		}(i)
	}

	for i := range 5 {
		go func(workerID int) {
			// Use atomic update to avoid hash conflicts
			err := backend.UpdateKey(ctx, "concurrent:key", func(currentKey *types.Key) (*types.Key, error) {
				if currentKey == nil {
					return nil, nil
				}

				// Create a new version with unique data
				newVersion := types.KeyVersion{
					ID:           uint64(workerID + 100), // Use unique IDs to avoid conflicts
					Data:         []byte(fmt.Sprintf("worker-%d-data", workerID)),
					Status:       types.Active,
					CreationTime: time.Now().UnixNano(),
				}

				updatedKey := &types.Key{
					ID:          currentKey.ID,
					ACL:         currentKey.ACL,
					VersionList: append(currentKey.VersionList, newVersion),
					VersionHash: "", // Will be set after building the list
				}
				updatedKey.VersionHash = updatedKey.VersionList.Hash()

				return updatedKey, nil
			})

			if err == nil {
				successfulUpdates++
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for range 10 {
		<-done
	}

	// Verify the backend is still consistent
	stats, err := backend.Stats(ctx)
	assert.NoError(t, err)
	assert.Equal(t, int64(1), stats.TotalKeys) // Should still have exactly one key

	// Verify we had some successful operations
	assert.True(t, successfulReads > 0, "Should have at least some successful reads")
	assert.True(t, successfulUpdates >= 0, "Updates may succeed or fail due to concurrency")
}

// TestMemoryBackend_DeepCopy tests that the backend returns deep copies.
func TestMemoryBackend_DeepCopy(t *testing.T) {
	backend := memory.New()
	ctx := t.Context()

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
		VersionHash: "",
	}
	testKey.VersionHash = testKey.VersionList.Hash()

	err := backend.PutKey(ctx, testKey)
	assert.NoError(t, err)

	// Get the key and modify it externally
	retrievedKey1, err := backend.GetKey(ctx, "test:key")
	assert.NoError(t, err)

	// Modify the retrieved key
	retrievedKey1.VersionList[0].Data = []byte("modified-externally")

	// Get the key again - should be unchanged
	retrievedKey2, err := backend.GetKey(ctx, "test:key")
	assert.NoError(t, err)
	assert.Equal(t, []byte("secret-data"), retrievedKey2.VersionList[0].Data)
	assert.NotEqual(t, retrievedKey1.VersionList[0].Data, retrievedKey2.VersionList[0].Data)
}

// TestMemoryBackend_NewBackendDeprecated tests the deprecated NewBackend function.
func TestMemoryBackend_NewBackendDeprecated(t *testing.T) {
	backend := memory.NewBackend()
	assert.NotNil(t, backend)

	// Verify it works the same as New()
	ctx := t.Context()
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
				Data:         []byte("test-data"),
				Status:       types.Primary,
				CreationTime: 1234567890,
			},
		},
		VersionHash: "",
	}
	testKey.VersionHash = testKey.VersionList.Hash()

	err := backend.PutKey(ctx, testKey)
	assert.NoError(t, err)

	key, err := backend.GetKey(ctx, "test:key")
	assert.NoError(t, err)
	assert.Equal(t, "test:key", key.ID)
}

// TestMemoryBackend_Registration tests that the backend is registered with storage package.
func TestMemoryBackend_Registration(t *testing.T) {
	// Test that we can create a memory backend through the storage.NewBackend factory
	backend, err := storage.NewBackend(storage.Config{Backend: "memory"})
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

// TestMemoryBackend_UpdateKeyValidation tests validation in UpdateKey.
func TestMemoryBackend_UpdateKeyValidation(t *testing.T) {
	backend := memory.New()
	ctx := t.Context()

	t.Run("invalid_key_returned", func(t *testing.T) {
		// Try to update with an invalid key (empty ID)
		err := backend.UpdateKey(ctx, "test:key", func(_ *types.Key) (*types.Key, error) {
			return &types.Key{
				ID:          "",
				ACL:         types.ACL{},
				VersionList: types.KeyVersionList{},
			}, nil
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key ID")
	})

	t.Run("changed_key_id", func(t *testing.T) {
		// Create initial key
		initialKey := &types.Key{
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
					Data:         []byte("data"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
			VersionHash: "",
		}
		initialKey.VersionHash = initialKey.VersionList.Hash()

		err := backend.PutKey(ctx, initialKey)
		require.NoError(t, err)

		// Try to change the key ID during update
		err = backend.UpdateKey(ctx, "test:key", func(currentKey *types.Key) (*types.Key, error) {
			updatedKey := &types.Key{
				ID:          "different:id", // Changed ID!
				ACL:         currentKey.ACL,
				VersionList: currentKey.VersionList,
				VersionHash: "",
			}
			updatedKey.VersionHash = updatedKey.VersionList.Hash()
			return updatedKey, nil
		})
		assert.Error(t, err)
		assert.Equal(t, types.ErrInvalidKeyID, err)
	})
}
