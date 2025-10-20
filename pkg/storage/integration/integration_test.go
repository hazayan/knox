// Package integration provides integration tests for the storage abstraction layer.
package integration

import (
	"context"
	"testing"
	"time"

	"github.com/hazayan/knox/pkg/storage"
	_ "github.com/hazayan/knox/pkg/storage/filesystem" // Register filesystem backend
	_ "github.com/hazayan/knox/pkg/storage/memory"     // Register memory backend
	_ "github.com/hazayan/knox/pkg/storage/postgres"   // Register postgres backend
	"github.com/hazayan/knox/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStorageBackendIntegration tests the storage backend interface with all implementations.
func TestStorageBackendIntegration(t *testing.T) {
	backends := []struct {
		name   string
		config storage.Config
	}{
		{
			name: "MemoryBackend",
			config: storage.Config{
				Backend: "memory",
			},
		},
		{
			name: "FilesystemBackend",
			config: storage.Config{
				Backend:       "filesystem",
				FilesystemDir: t.TempDir(),
			},
		},
	}

	for _, backend := range backends {
		t.Run(backend.name, func(t *testing.T) {
			// Create backend
			storage, err := storage.NewBackend(backend.config)
			require.NoError(t, err)
			require.NotNil(t, storage)

			defer func() {
				err := storage.Close()
				assert.NoError(t, err)
			}()

			// Test basic operations
			testBasicKeyOperations(t, storage)
			testKeyNotFoundScenarios(t, storage)
			testConcurrentAccess(t, storage)
			testListKeysWithPrefix(t, storage)
			testUpdateKeyAtomicity(t, storage)
			testPingOperation(t, storage)
		})
	}
}

// testBasicKeyOperations tests basic CRUD operations.
func testBasicKeyOperations(t *testing.T, backend storage.Backend) {
	ctx := t.Context()
	keyID := "test:basic:operations"

	// Create a valid key
	key := &types.Key{
		ID: keyID,
		ACL: types.ACL{
			{
				Type:       types.User,
				ID:         "test-user",
				AccessType: types.Admin,
			},
		},
		VersionList: types.KeyVersionList{
			{
				ID:           1,
				Data:         []byte("primary-secret"),
				Status:       types.Primary,
				CreationTime: time.Now().Unix(),
			},
		},
	}
	key.VersionHash = key.VersionList.Hash()

	// Test PutKey
	err := backend.PutKey(ctx, key)
	assert.NoError(t, err)

	// Test GetKey
	retrievedKey, err := backend.GetKey(ctx, keyID)
	assert.NoError(t, err)
	assert.Equal(t, key.ID, retrievedKey.ID)
	assert.Equal(t, key.VersionHash, retrievedKey.VersionHash)
	assert.Len(t, retrievedKey.ACL, 1)
	assert.Len(t, retrievedKey.VersionList, 1)

	// Test ListKeys
	keys, err := backend.ListKeys(ctx, "test:")
	assert.NoError(t, err)
	assert.Contains(t, keys, keyID)

	// Test DeleteKey
	err = backend.DeleteKey(ctx, keyID)
	assert.NoError(t, err)

	// Verify key is gone
	_, err = backend.GetKey(ctx, keyID)
	assert.Error(t, err)
	assert.True(t, storage.IsKeyNotFound(err))
}

// testKeyNotFoundScenarios tests error handling for non-existent keys.
func testKeyNotFoundScenarios(t *testing.T, backend storage.Backend) {
	ctx := t.Context()
	nonExistentKey := "test:non:existent:key"

	// Test GetKey with non-existent key
	_, err := backend.GetKey(ctx, nonExistentKey)
	assert.Error(t, err)
	assert.True(t, storage.IsKeyNotFound(err))

	// Test DeleteKey with non-existent key
	err = backend.DeleteKey(ctx, nonExistentKey)
	assert.Error(t, err)
	assert.True(t, storage.IsKeyNotFound(err))

	// Test UpdateKey with non-existent key
	err = backend.UpdateKey(ctx, nonExistentKey, func(key *types.Key) (*types.Key, error) {
		if key == nil {
			return nil, storage.ErrKeyNotFound
		}
		return key, nil
	})
	assert.Error(t, err)
}

// testConcurrentAccess tests concurrent access patterns.
func testConcurrentAccess(t *testing.T, backend storage.Backend) {
	ctx := t.Context()
	baseKeyID := "test:concurrent:"

	// Create multiple keys concurrently
	const numKeys = 10
	errors := make(chan error, numKeys)

	for i := range numKeys {
		go func(index int) {
			keyID := baseKeyID + string(rune('a'+index))
			key := &types.Key{
				ID: keyID,
				ACL: types.ACL{
					{
						Type:       types.User,
						ID:         "test-user",
						AccessType: types.Admin,
					},
				},
				VersionList: types.KeyVersionList{
					{
						ID:           1,
						Data:         []byte("concurrent-data"),
						Status:       types.Primary,
						CreationTime: time.Now().Unix(),
					},
				},
			}
			key.VersionHash = key.VersionList.Hash()

			err := backend.PutKey(ctx, key)
			errors <- err
		}(i)
	}

	// Wait for all operations to complete
	for range numKeys {
		err := <-errors
		assert.NoError(t, err)
	}

	// Verify all keys were created
	keys, err := backend.ListKeys(ctx, baseKeyID)
	assert.NoError(t, err)
	assert.Len(t, keys, numKeys)

	// Clean up
	for i := range numKeys {
		keyID := baseKeyID + string(rune('a'+i))
		err := backend.DeleteKey(ctx, keyID)
		assert.NoError(t, err)
	}
}

// testListKeysWithPrefix tests prefix-based key listing.
func testListKeysWithPrefix(t *testing.T, backend storage.Backend) {
	ctx := t.Context()

	// Create keys with different prefixes
	testKeys := []string{
		"app:database:password",
		"app:api:key",
		"app:config:secret",
		"system:token:auth",
		"system:cert:tls",
	}

	for _, keyID := range testKeys {
		key := &types.Key{
			ID: keyID,
			ACL: types.ACL{
				{
					Type:       types.User,
					ID:         "test-user",
					AccessType: types.Admin,
				},
			},
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("test-data"),
					Status:       types.Primary,
					CreationTime: time.Now().Unix(),
				},
			},
		}
		key.VersionHash = key.VersionList.Hash()

		err := backend.PutKey(ctx, key)
		assert.NoError(t, err)
	}

	// Test listing with different prefixes
	tests := []struct {
		prefix        string
		expected      int
		shouldContain []string
	}{
		{
			prefix:        "app:",
			expected:      3,
			shouldContain: []string{"app:database:password", "app:api:key", "app:config:secret"},
		},
		{
			prefix:        "system:",
			expected:      2,
			shouldContain: []string{"system:token:auth", "system:cert:tls"},
		},
		{
			prefix:        "nonexistent:",
			expected:      0,
			shouldContain: []string{},
		},
		{
			prefix:        "",
			expected:      5,
			shouldContain: testKeys,
		},
	}

	for _, tt := range tests {
		keys, err := backend.ListKeys(ctx, tt.prefix)
		assert.NoError(t, err)
		assert.Len(t, keys, tt.expected)

		for _, expectedKey := range tt.shouldContain {
			assert.Contains(t, keys, expectedKey)
		}
	}

	// Clean up
	for _, keyID := range testKeys {
		err := backend.DeleteKey(ctx, keyID)
		assert.NoError(t, err)
	}
}

// testUpdateKeyAtomicity tests atomic key updates.
func testUpdateKeyAtomicity(t *testing.T, backend storage.Backend) {
	ctx := t.Context()
	keyID := "test:atomic:update"

	// Create initial key
	initialKey := &types.Key{
		ID: keyID,
		ACL: types.ACL{
			{
				Type:       types.User,
				ID:         "test-user",
				AccessType: types.Admin,
			},
		},
		VersionList: types.KeyVersionList{
			{
				ID:           1,
				Data:         []byte("initial-data"),
				Status:       types.Primary,
				CreationTime: time.Now().Unix(),
			},
		},
	}
	initialKey.VersionHash = initialKey.VersionList.Hash()

	err := backend.PutKey(ctx, initialKey)
	assert.NoError(t, err)

	// Test successful atomic update
	updateCount := 0
	err = backend.UpdateKey(ctx, keyID, func(key *types.Key) (*types.Key, error) {
		updateCount++
		if key == nil {
			return nil, storage.ErrKeyNotFound
		}

		// Add a new version
		newVersion := types.KeyVersion{
			ID:           uint64(len(key.VersionList) + 1),
			Data:         []byte("updated-data"),
			Status:       types.Active,
			CreationTime: time.Now().Unix(),
		}
		key.VersionList = append(key.VersionList, newVersion)
		key.VersionHash = key.VersionList.Hash()

		return key, nil
	})
	assert.NoError(t, err)
	assert.Equal(t, 1, updateCount)

	// Verify update was applied
	updatedKey, err := backend.GetKey(ctx, keyID)
	assert.NoError(t, err)
	assert.Len(t, updatedKey.VersionList, 2)
	assert.Equal(t, "updated-data", string(updatedKey.VersionList[1].Data))

	// Test update with error (should not modify key)
	updateCount = 0
	err = backend.UpdateKey(ctx, keyID, func(_ *types.Key) (*types.Key, error) {
		updateCount++
		return nil, assert.AnError // Simulate an error during update
	})
	assert.Error(t, err)
	assert.Equal(t, 1, updateCount)

	// Verify key was not modified
	unchangedKey, err := backend.GetKey(ctx, keyID)
	assert.NoError(t, err)
	assert.Equal(t, updatedKey.VersionHash, unchangedKey.VersionHash)

	// Clean up
	err = backend.DeleteKey(ctx, keyID)
	assert.NoError(t, err)
}

// testPingOperation tests the Ping operation.
func testPingOperation(t *testing.T, backend storage.Backend) {
	ctx := t.Context()

	err := backend.Ping(ctx)
	assert.NoError(t, err)
}

// TestStorageErrorScenarios tests various error scenarios.
func TestStorageErrorScenarios(t *testing.T) {
	backend, err := storage.NewBackend(storage.Config{Backend: "memory"})
	require.NoError(t, err)
	defer backend.Close()

	ctx := t.Context()

	t.Run("PutInvalidKey", func(t *testing.T) {
		// Test with empty key ID
		emptyKey := &types.Key{ID: ""}
		err := backend.PutKey(ctx, emptyKey)
		assert.Error(t, err)

		// Test with invalid key (no versions)
		invalidKey := &types.Key{
			ID: "test:invalid",
			ACL: types.ACL{
				{
					Type:       types.User,
					ID:         "test-user",
					AccessType: types.Admin,
				},
			},
			VersionList: types.KeyVersionList{},
		}
		err = backend.PutKey(ctx, invalidKey)
		assert.Error(t, err)
	})

	t.Run("DuplicateKeyCreation", func(t *testing.T) {
		keyID := "test:duplicate"

		// Create first key
		key1 := createTestKey(keyID, "first-data")
		err := backend.PutKey(ctx, key1)
		assert.NoError(t, err)

		// Try to create duplicate key
		key2 := createTestKey(keyID, "second-data")
		err = backend.PutKey(ctx, key2)
		assert.NoError(t, err) // PutKey should overwrite existing keys

		// Clean up
		err = backend.DeleteKey(ctx, keyID)
		assert.NoError(t, err)
	})

	t.Run("ContextCancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel() // Immediately cancel the context

		_, err := backend.GetKey(ctx, "test:cancelled")
		assert.Error(t, err)
	})
}

// TestTransactionalBackend tests transactional backend functionality.
func TestTransactionalBackend(t *testing.T) {
	backend, err := storage.NewBackend(storage.Config{Backend: "memory"})
	require.NoError(t, err)
	defer backend.Close()

	// Check if backend supports transactions
	txBackend, ok := backend.(storage.TransactionalBackend)
	if !ok {
		t.Skip("Backend does not support transactions")
		return
	}

	ctx := t.Context()
	keyID := "test:transactional"

	// Test transaction lifecycle
	tx, err := txBackend.BeginTx(ctx)
	require.NoError(t, err)
	require.NotNil(t, tx)

	// Create key within transaction
	key := createTestKey(keyID, "transaction-data")
	err = tx.PutKey(ctx, key)
	assert.NoError(t, err)

	// Key should not be visible outside transaction yet
	_, err = backend.GetKey(ctx, keyID)
	assert.Error(t, err)
	assert.True(t, storage.IsKeyNotFound(err))

	// Commit transaction
	err = tx.Commit()
	assert.NoError(t, err)

	// Key should now be visible
	retrievedKey, err := backend.GetKey(ctx, keyID)
	assert.NoError(t, err)
	assert.Equal(t, keyID, retrievedKey.ID)

	// Test rollback
	tx, err = txBackend.BeginTx(ctx)
	require.NoError(t, err)

	newKeyID := "test:rollback"
	rollbackKey := createTestKey(newKeyID, "rollback-data")
	err = tx.PutKey(ctx, rollbackKey)
	assert.NoError(t, err)

	// Rollback transaction
	err = tx.Rollback()
	assert.NoError(t, err)

	// Key should not exist after rollback
	_, err = backend.GetKey(ctx, newKeyID)
	assert.Error(t, err)
	assert.True(t, storage.IsKeyNotFound(err))

	// Clean up
	err = backend.DeleteKey(ctx, keyID)
	assert.NoError(t, err)
}

// TestStorageBackendStats tests statistics collection.
func TestStorageBackendStats(t *testing.T) {
	backend, err := storage.NewBackend(storage.Config{Backend: "memory"})
	require.NoError(t, err)
	defer backend.Close()

	// Check if backend supports stats
	statsBackend, ok := backend.(storage.StatsProvider)
	if !ok {
		t.Skip("Backend does not support statistics")
		return
	}

	ctx := t.Context()

	// Get initial stats
	initialStats, err := statsBackend.Stats(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, initialStats)

	// Create some keys and check stats change
	const numKeys = 5
	for i := range numKeys {
		key := createTestKey("test:stats:"+string(rune('a'+i)), "stats-data")
		err := backend.PutKey(ctx, key)
		assert.NoError(t, err)
	}

	// Get updated stats
	updatedStats, err := statsBackend.Stats(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, updatedStats)

	// Stats should reflect the changes
	assert.GreaterOrEqual(t, updatedStats.TotalKeys, initialStats.TotalKeys)

	// Clean up
	for i := range numKeys {
		err := backend.DeleteKey(ctx, "test:stats:"+string(rune('a'+i)))
		assert.NoError(t, err)
	}
}

// Helper function to create test keys.
func createTestKey(id, data string) *types.Key {
	key := &types.Key{
		ID: id,
		ACL: types.ACL{
			{
				Type:       types.User,
				ID:         "test-user",
				AccessType: types.Admin,
			},
		},
		VersionList: types.KeyVersionList{
			{
				ID:           1,
				Data:         []byte(data),
				Status:       types.Primary,
				CreationTime: time.Now().Unix(),
			},
		},
	}
	key.VersionHash = key.VersionList.Hash()
	return key
}
