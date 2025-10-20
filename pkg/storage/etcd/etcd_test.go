// Package etcd provides tests for the etcd storage backend.
package etcd

import (
	"context"
	"testing"
	"time"

	"github.com/hazayan/knox/pkg/storage"
	"github.com/hazayan/knox/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBackend_GetKey tests key retrieval functionality.
func TestBackend_GetKey(t *testing.T) {
	ctx := t.Context()
	backend := setupTestBackend(t)
	defer backend.Close()

	// Test getting non-existent key
	_, err := backend.GetKey(ctx, "nonexistent")
	assert.ErrorIs(t, err, storage.ErrKeyNotFound)

	// Test getting existing key
	key := &types.Key{
		ID: "test-key",
		ACL: types.ACL{
			{Type: types.User, ID: "test-user", AccessType: types.Read},
		},
		VersionList: types.KeyVersionList{
			{ID: 1, Data: []byte("test-data"), Status: types.Primary, CreationTime: time.Now().Unix()},
		},
		VersionHash: "test-hash",
	}

	err = backend.PutKey(ctx, key)
	require.NoError(t, err)

	retrieved, err := backend.GetKey(ctx, "test-key")
	require.NoError(t, err)
	assert.Equal(t, key.ID, retrieved.ID)
	assert.Equal(t, key.VersionHash, retrieved.VersionHash)
}

// TestBackend_PutKey tests key storage functionality.
func TestBackend_PutKey(t *testing.T) {
	ctx := t.Context()
	backend := setupTestBackend(t)
	defer backend.Close()

	// Test storing valid key
	key := &types.Key{
		ID: "test-key",
		ACL: types.ACL{
			{Type: types.User, ID: "test-user", AccessType: types.Read},
		},
		VersionList: types.KeyVersionList{
			{ID: 1, Data: []byte("test-data"), Status: types.Primary, CreationTime: time.Now().Unix()},
		},
		VersionHash: "test-hash",
	}

	err := backend.PutKey(ctx, key)
	assert.NoError(t, err)

	// Test storing duplicate key
	err = backend.PutKey(ctx, key)
	assert.ErrorIs(t, err, storage.ErrKeyExists)

	// Test storing invalid key
	invalidKey := &types.Key{
		ID:          "invalid-key",
		VersionHash: "test-hash",
		// Missing required fields
	}
	err = backend.PutKey(ctx, invalidKey)
	assert.Error(t, err)
}

// TestBackend_DeleteKey tests key deletion functionality.
func TestBackend_DeleteKey(t *testing.T) {
	ctx := t.Context()
	backend := setupTestBackend(t)
	defer backend.Close()

	// Test deleting non-existent key
	err := backend.DeleteKey(ctx, "nonexistent")
	assert.ErrorIs(t, err, storage.ErrKeyNotFound)

	// Test deleting existing key
	key := &types.Key{
		ID: "test-key",
		ACL: types.ACL{
			{Type: types.User, ID: "test-user", AccessType: types.Read},
		},
		VersionList: types.KeyVersionList{
			{ID: 1, Data: []byte("test-data"), Status: types.Primary, CreationTime: time.Now().Unix()},
		},
		VersionHash: "test-hash",
	}

	err = backend.PutKey(ctx, key)
	require.NoError(t, err)

	err = backend.DeleteKey(ctx, "test-key")
	assert.NoError(t, err)

	// Verify key is gone
	_, err = backend.GetKey(ctx, "test-key")
	assert.ErrorIs(t, err, storage.ErrKeyNotFound)
}

// TestBackend_ListKeys tests key listing functionality.
func TestBackend_ListKeys(t *testing.T) {
	ctx := t.Context()
	backend := setupTestBackend(t)
	defer backend.Close()

	// Test listing with no keys
	keys, err := backend.ListKeys(ctx, "")
	assert.NoError(t, err)
	assert.Empty(t, keys)

	// Add multiple keys
	keysToCreate := []string{"key1", "key2", "test-key", "other-key"}
	for _, keyID := range keysToCreate {
		key := &types.Key{
			ID: keyID,
			ACL: types.ACL{
				{Type: types.User, ID: "test-user", AccessType: types.Read},
			},
			VersionList: types.KeyVersionList{
				{ID: 1, Data: []byte("test-data"), Status: types.Primary, CreationTime: time.Now().Unix()},
			},
			VersionHash: "test-hash",
		}
		err := backend.PutKey(ctx, key)
		require.NoError(t, err)
	}

	// Test listing all keys
	allKeys, err := backend.ListKeys(ctx, "")
	assert.NoError(t, err)
	assert.ElementsMatch(t, keysToCreate, allKeys)

	// Test listing with prefix
	prefixedKeys, err := backend.ListKeys(ctx, "key")
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"key1", "key2"}, prefixedKeys)
}

// TestBackend_UpdateKey tests atomic key updates.
func TestBackend_UpdateKey(t *testing.T) {
	ctx := t.Context()
	backend := setupTestBackend(t)
	defer backend.Close()

	// Test updating non-existent key (should create it)
	err := backend.UpdateKey(ctx, "new-key", func(current *types.Key) (*types.Key, error) {
		if current == nil {
			return &types.Key{
				ID: "new-key",
				ACL: types.ACL{
					{Type: types.User, ID: "test-user", AccessType: types.Read},
				},
				VersionList: types.KeyVersionList{
					{ID: 1, Data: []byte("test-data"), Status: types.Primary, CreationTime: time.Now().Unix()},
				},
				VersionHash: "test-hash",
			}, nil
		}
		return current, nil
	})
	assert.NoError(t, err)

	// Verify key was created
	key, err := backend.GetKey(ctx, "new-key")
	assert.NoError(t, err)
	assert.Equal(t, "new-key", key.ID)

	// Test updating existing key
	err = backend.UpdateKey(ctx, "new-key", func(current *types.Key) (*types.Key, error) {
		if current != nil {
			current.VersionHash = "updated-hash"
		}
		return current, nil
	})
	assert.NoError(t, err)

	// Verify key was updated
	updatedKey, err := backend.GetKey(ctx, "new-key")
	assert.NoError(t, err)
	assert.Equal(t, "updated-hash", updatedKey.VersionHash)

	// Test update function returning error
	err = backend.UpdateKey(ctx, "new-key", func(_ *types.Key) (*types.Key, error) {
		return nil, assert.AnError
	})
	assert.ErrorIs(t, err, assert.AnError)

	// Test update function returning nil (delete)
	err = backend.UpdateKey(ctx, "new-key", func(_ *types.Key) (*types.Key, error) {
		return nil, nil
	})
	assert.NoError(t, err)

	// Verify key was deleted
	_, err = backend.GetKey(ctx, "new-key")
	assert.ErrorIs(t, err, storage.ErrKeyNotFound)
}

// TestBackend_Ping tests connectivity checking.
func TestBackend_Ping(t *testing.T) {
	ctx := t.Context()
	backend := setupTestBackend(t)
	defer backend.Close()

	err := backend.Ping(ctx)
	assert.NoError(t, err)
}

// TestBackend_ReadOnly tests read-only mode.
func TestBackend_ReadOnly(t *testing.T) {
	ctx := t.Context()

	// Create read-only backend
	backend, err := New([]string{"http://localhost:2379"}, "/test", true)
	if err != nil {
		t.Skip("etcd not available, skipping read-only test")
	}
	defer backend.Close()

	key := &types.Key{
		ID: "test-key",
		ACL: types.ACL{
			{Type: types.User, ID: "test-user", AccessType: types.Read},
		},
		VersionList: types.KeyVersionList{
			{ID: 1, Data: []byte("test-data"), Status: types.Primary, CreationTime: time.Now().Unix()},
		},
		VersionHash: "test-hash",
	}

	// Test that write operations fail in read-only mode
	err = backend.PutKey(ctx, key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read-only")

	err = backend.DeleteKey(ctx, "test-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read-only")

	err = backend.UpdateKey(ctx, "test-key", func(current *types.Key) (*types.Key, error) {
		return current, nil
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read-only")
}

// TestBackend_ConcurrentUpdates tests concurrent modification handling.
func TestBackend_ConcurrentUpdates(t *testing.T) {
	ctx := t.Context()
	backend := setupTestBackend(t)
	defer backend.Close()

	// Create initial key
	key := &types.Key{
		ID: "concurrent-key",
		ACL: types.ACL{
			{Type: types.User, ID: "test-user", AccessType: types.Read},
		},
		VersionList: types.KeyVersionList{
			{ID: 1, Data: []byte("initial-data"), Status: types.Primary, CreationTime: time.Now().Unix()},
		},
		VersionHash: "initial-hash",
	}

	err := backend.PutKey(ctx, key)
	require.NoError(t, err)

	// Simulate concurrent updates
	done := make(chan error, 2)

	// First update
	go func() {
		err := backend.UpdateKey(ctx, "concurrent-key", func(current *types.Key) (*types.Key, error) {
			if current != nil {
				current.VersionHash = "first-update"
				time.Sleep(100 * time.Millisecond) // Simulate work
			}
			return current, nil
		})
		done <- err
	}()

	// Second update (should detect conflict)
	go func() {
		time.Sleep(50 * time.Millisecond) // Start slightly later
		err := backend.UpdateKey(ctx, "concurrent-key", func(current *types.Key) (*types.Key, error) {
			if current != nil {
				current.VersionHash = "second-update"
			}
			return current, nil
		})
		done <- err
	}()

	// Collect results
	err1 := <-done
	err2 := <-done

	// One should succeed, one should fail with concurrent modification
	assert.True(t, (err1 == nil && err2 != nil) || (err1 != nil && err2 == nil),
		"expected exactly one update to succeed, got err1=%v, err2=%v", err1, err2)
}

// TestBackend_Stats tests metrics collection.
func TestBackend_Stats(t *testing.T) {
	ctx := t.Context()
	backend := setupTestBackend(t)
	defer backend.Close()

	stats, err := backend.Stats(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, stats)
	assert.GreaterOrEqual(t, stats.TotalKeys, int64(0))
	assert.NotNil(t, stats.OperationCounts)
	assert.NotNil(t, stats.BackendSpecific)
}

// TestBackend_Transaction tests transaction support.
func TestBackend_Transaction(t *testing.T) {
	ctx := t.Context()
	backend := setupTestBackend(t)
	defer backend.Close()

	tx, err := backend.BeginTx(ctx)
	require.NoError(t, err)

	// Add keys in transaction
	key1 := &types.Key{
		ID: "tx-key1",
		ACL: types.ACL{
			{Type: types.User, ID: "test-user", AccessType: types.Read},
		},
		VersionList: types.KeyVersionList{
			{ID: 1, Data: []byte("tx-data1"), Status: types.Primary, CreationTime: time.Now().Unix()},
		},
		VersionHash: "tx-hash1",
	}

	key2 := &types.Key{
		ID: "tx-key2",
		ACL: types.ACL{
			{Type: types.User, ID: "test-user", AccessType: types.Read},
		},
		VersionList: types.KeyVersionList{
			{ID: 1, Data: []byte("tx-data2"), Status: types.Primary, CreationTime: time.Now().Unix()},
		},
		VersionHash: "tx-hash2",
	}

	err = tx.PutKey(ctx, key1)
	assert.NoError(t, err)

	err = tx.PutKey(ctx, key2)
	assert.NoError(t, err)

	// Keys should not be visible before commit
	_, err = backend.GetKey(ctx, "tx-key1")
	assert.ErrorIs(t, err, storage.ErrKeyNotFound)

	// Commit transaction
	err = tx.Commit()
	assert.NoError(t, err)

	// Keys should be visible after commit
	_, err = backend.GetKey(ctx, "tx-key1")
	assert.NoError(t, err)

	_, err = backend.GetKey(ctx, "tx-key2")
	assert.NoError(t, err)
}

// TestBackend_TransactionRollback tests transaction rollback.
func TestBackend_TransactionRollback(t *testing.T) {
	ctx := t.Context()
	backend := setupTestBackend(t)
	defer backend.Close()

	tx, err := backend.BeginTx(ctx)
	require.NoError(t, err)

	// Add key in transaction
	key := &types.Key{
		ID: "rollback-key",
		ACL: types.ACL{
			{Type: types.User, ID: "test-user", AccessType: types.Read},
		},
		VersionList: types.KeyVersionList{
			{ID: 1, Data: []byte("rollback-data"), Status: types.Primary, CreationTime: time.Now().Unix()},
		},
		VersionHash: "rollback-hash",
	}

	err = tx.PutKey(ctx, key)
	assert.NoError(t, err)

	// Rollback transaction
	err = tx.Rollback()
	assert.NoError(t, err)

	// Key should not be visible after rollback
	_, err = backend.GetKey(ctx, "rollback-key")
	assert.ErrorIs(t, err, storage.ErrKeyNotFound)
}

// setupTestBackend creates a test etcd backend.
// If etcd is not available, the test is skipped.
func setupTestBackend(t *testing.T) *Backend {
	t.Helper()

	backend, err := New([]string{"http://localhost:2379"}, "/test", false)
	if err != nil {
		t.Skip("etcd not available, skipping test")
	}

	// Clean up test data
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	keys, err := backend.ListKeys(ctx, "")
	if err == nil {
		for _, keyID := range keys {
			_ = backend.DeleteKey(ctx, keyID)
		}
	}

	return backend
}
