package orm

import (
	"fmt"
	"testing"
	"time"

	"github.com/hazayan/knox/pkg/storage"
	"github.com/hazayan/knox/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupTestBackend creates an in-memory SQLite backend for testing.
func setupTestBackend(t *testing.T) *Backend {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err, "failed to open in-memory database")

	backend, err := New(db)
	require.NoError(t, err, "failed to create backend")

	return backend
}

// createTestKey is a helper to create a valid test key.
func createTestKey(id string, data []byte) *types.Key {
	key := &types.Key{
		ID: id,
		ACL: types.ACL{
			{Type: types.User, ID: "testuser", AccessType: types.Admin},
		},
		VersionList: types.KeyVersionList{
			{
				Data:         data,
				CreationTime: time.Now().UnixNano(),
			},
		},
	}
	key.VersionHash = key.VersionList.Hash()
	return key
}

func TestBackend_PutAndGetKey(t *testing.T) {
	backend := setupTestBackend(t)
	defer backend.Close()

	ctx := t.Context()

	// Create a test key
	key := createTestKey("test:key1", []byte("secret-data"))

	// Put the key
	err := backend.PutKey(ctx, key)
	require.NoError(t, err)

	// Get the key back
	retrieved, err := backend.GetKey(ctx, "test:key1")
	require.NoError(t, err)
	assert.Equal(t, key.ID, retrieved.ID)
	assert.Equal(t, len(key.ACL), len(retrieved.ACL))
	assert.Equal(t, len(key.VersionList), len(retrieved.VersionList))
}

func TestBackend_GetKeyNotFound(t *testing.T) {
	backend := setupTestBackend(t)
	defer backend.Close()

	ctx := t.Context()

	_, err := backend.GetKey(ctx, "nonexistent")
	assert.ErrorIs(t, err, storage.ErrKeyNotFound)
}

func TestBackend_DeleteKey(t *testing.T) {
	backend := setupTestBackend(t)
	defer backend.Close()

	ctx := t.Context()

	// Create and store a key
	key := createTestKey("test:key2", []byte("data"))
	require.NoError(t, backend.PutKey(ctx, key))

	// Delete the key
	err := backend.DeleteKey(ctx, "test:key2")
	require.NoError(t, err)

	// Verify it's gone
	_, err = backend.GetKey(ctx, "test:key2")
	assert.ErrorIs(t, err, storage.ErrKeyNotFound)
}

func TestBackend_ListKeys(t *testing.T) {
	backend := setupTestBackend(t)
	defer backend.Close()

	ctx := t.Context()

	// Create multiple keys
	keys := []string{"app1:secret1", "app1:secret2", "app2:secret1"}
	for _, keyID := range keys {
		key := createTestKey(keyID, []byte("data"))
		require.NoError(t, backend.PutKey(ctx, key))
	}

	// List all keys
	allKeys, err := backend.ListKeys(ctx, "")
	require.NoError(t, err)
	assert.Len(t, allKeys, 3)

	// List keys with prefix
	app1Keys, err := backend.ListKeys(ctx, "app1:")
	require.NoError(t, err)
	assert.Len(t, app1Keys, 2)
	assert.Contains(t, app1Keys, "app1:secret1")
	assert.Contains(t, app1Keys, "app1:secret2")
}

func TestBackend_UpdateKey(t *testing.T) {
	backend := setupTestBackend(t)
	defer backend.Close()

	ctx := t.Context()

	// Create initial key
	key := createTestKey("test:update", []byte("v1"))
	require.NoError(t, backend.PutKey(ctx, key))

	// Update the key
	err := backend.UpdateKey(ctx, "test:update", func(k *types.Key) (*types.Key, error) {
		nextID := uint64(len(k.VersionList) + 1)
		k.VersionList = append(k.VersionList, types.KeyVersion{
			ID:           nextID,
			Data:         []byte("v2"),
			CreationTime: time.Now().UnixNano(),
			Status:       types.Active,
		})
		k.VersionHash = k.VersionList.Hash()
		return k, nil
	})
	require.NoError(t, err)

	// Verify the update
	updated, err := backend.GetKey(ctx, "test:update")
	require.NoError(t, err)
	assert.Len(t, updated.VersionList, 2)
}

func TestBackend_Transaction(t *testing.T) {
	backend := setupTestBackend(t)
	defer backend.Close()

	ctx := t.Context()

	// Start transaction
	tx, err := backend.BeginTx(ctx)
	require.NoError(t, err)

	// Create key in transaction
	key := createTestKey("test:tx", []byte("tx-data"))
	require.NoError(t, tx.PutKey(ctx, key))

	// Commit transaction
	require.NoError(t, tx.Commit())

	// Verify key exists after commit
	retrieved, err := backend.GetKey(ctx, "test:tx")
	require.NoError(t, err)
	assert.Equal(t, "test:tx", retrieved.ID)
}

func TestBackend_TransactionRollback(t *testing.T) {
	backend := setupTestBackend(t)
	defer backend.Close()

	ctx := t.Context()

	// Start transaction
	tx, err := backend.BeginTx(ctx)
	require.NoError(t, err)

	// Create key in transaction
	key := createTestKey("test:rollback", []byte("rollback-data"))
	require.NoError(t, tx.PutKey(ctx, key))

	// Rollback transaction
	require.NoError(t, tx.Rollback())

	// Verify key doesn't exist after rollback
	_, err = backend.GetKey(ctx, "test:rollback")
	assert.ErrorIs(t, err, storage.ErrKeyNotFound)
}

func TestBackend_Stats(t *testing.T) {
	backend := setupTestBackend(t)
	defer backend.Close()

	ctx := t.Context()

	// Add some keys
	for i := range 5 {
		key := createTestKey(fmt.Sprintf("stats:key%d", i), []byte("data"))
		require.NoError(t, backend.PutKey(ctx, key))
	}

	// Get stats
	stats, err := backend.Stats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(5), stats.TotalKeys)
	assert.Equal(t, "orm", stats.BackendSpecific["backend"])
	assert.Equal(t, "sqlite", stats.BackendSpecific["dialect"])
}

func TestBackend_Ping(t *testing.T) {
	backend := setupTestBackend(t)
	defer backend.Close()

	ctx := t.Context()

	err := backend.Ping(ctx)
	assert.NoError(t, err)
}
