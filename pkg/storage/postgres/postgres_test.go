// Package postgres_test provides tests for the PostgreSQL storage backend.
package postgres_test

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hazayan/knox/pkg/storage"
	"github.com/hazayan/knox/pkg/storage/postgres"
	"github.com/hazayan/knox/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPostgresBackend_New tests the creation of a new PostgreSQL backend.
func TestPostgresBackend_New(t *testing.T) {
	connectionString := getTestConnectionString(t)

	// Test valid connection
	backend, err := postgres.New(connectionString, 10)
	assert.NoError(t, err)
	assert.NotNil(t, backend)
	defer backend.Close()

	// Test invalid connection string
	_, err = postgres.New("invalid-connection-string", 10)
	assert.Error(t, err)
}

// TestPostgresBackend_GetKey tests key retrieval operations.
func TestPostgresBackend_GetKey(t *testing.T) {
	backend := setupTestBackend(t)
	defer backend.Close()
	ctx := t.Context()

	// Test getting non-existent key
	key, err := backend.GetKey(ctx, "non-existent-key")
	assert.Error(t, err)
	assert.True(t, storage.IsKeyNotFound(err))
	assert.Nil(t, key)

	// Create and get a key
	testKey := createTestKey("test-get-key")
	err = backend.PutKey(ctx, testKey)
	require.NoError(t, err)

	retrievedKey, err := backend.GetKey(ctx, testKey.ID)
	assert.NoError(t, err)
	assert.Equal(t, testKey.ID, retrievedKey.ID)
	assert.Equal(t, testKey.ACL, retrievedKey.ACL)
	assert.Equal(t, testKey.VersionHash, retrievedKey.VersionHash)
	assert.Len(t, retrievedKey.VersionList, len(testKey.VersionList))
}

// TestPostgresBackend_PutKey tests key storage operations.
func TestPostgresBackend_PutKey(t *testing.T) {
	backend := setupTestBackend(t)
	defer backend.Close()
	ctx := t.Context()

	// Test creating a new key
	testKey := createTestKey("test-put-key")
	err := backend.PutKey(ctx, testKey)
	assert.NoError(t, err)

	// Test updating an existing key
	testKey.VersionHash = "updated-hash"
	err = backend.PutKey(ctx, testKey)
	assert.NoError(t, err)

	// Verify the update
	retrievedKey, err := backend.GetKey(ctx, testKey.ID)
	assert.NoError(t, err)
	assert.Equal(t, "updated-hash", retrievedKey.VersionHash)

	// Test with invalid key (should fail validation)
	invalidKey := &types.Key{
		ID:          "invalid key!", // Invalid characters
		ACL:         types.ACL{},
		VersionList: types.KeyVersionList{},
		VersionHash: "hash",
	}
	err = backend.PutKey(ctx, invalidKey)
	assert.Error(t, err)
}

// TestPostgresBackend_DeleteKey tests key deletion operations.
func TestPostgresBackend_DeleteKey(t *testing.T) {
	backend := setupTestBackend(t)
	defer backend.Close()
	ctx := t.Context()

	// Test deleting non-existent key (should not error)
	err := backend.DeleteKey(ctx, "non-existent-key")
	assert.NoError(t, err)

	// Create and then delete a key
	testKey := createTestKey("test-delete-key")
	err = backend.PutKey(ctx, testKey)
	require.NoError(t, err)

	// Verify key exists
	_, err = backend.GetKey(ctx, testKey.ID)
	assert.NoError(t, err)

	// Delete the key
	err = backend.DeleteKey(ctx, testKey.ID)
	assert.NoError(t, err)

	// Verify key is gone
	_, err = backend.GetKey(ctx, testKey.ID)
	assert.Error(t, err)
	assert.True(t, storage.IsKeyNotFound(err))
}

// TestPostgresBackend_ListKeys tests key listing operations.
func TestPostgresBackend_ListKeys(t *testing.T) {
	backend := setupTestBackend(t)
	defer backend.Close()
	ctx := t.Context()

	// Create multiple test keys
	keys := []*types.Key{
		createTestKey("service:api-key"),
		createTestKey("service:database-password"),
		createTestKey("app:config"),
		createTestKey("other:secret"),
	}

	for _, key := range keys {
		err := backend.PutKey(ctx, key)
		require.NoError(t, err)
	}

	// Test listing all keys
	allKeys, err := backend.ListKeys(ctx, "")
	assert.NoError(t, err)
	assert.Len(t, allKeys, len(keys))

	// Test listing with prefix
	serviceKeys, err := backend.ListKeys(ctx, "service:")
	assert.NoError(t, err)
	assert.Len(t, serviceKeys, 2)
	for _, key := range serviceKeys {
		assert.Contains(t, key, "service:")
	}

	// Test listing with non-matching prefix
	noMatchKeys, err := backend.ListKeys(ctx, "nonexistent:")
	assert.NoError(t, err)
	assert.Len(t, noMatchKeys, 0)
}

// TestPostgresBackend_UpdateKey tests atomic key updates.
func TestPostgresBackend_UpdateKey(t *testing.T) {
	backend := setupTestBackend(t)
	defer backend.Close()
	ctx := t.Context()

	// Create initial key
	initialKey := createTestKey("test-update-key")
	err := backend.PutKey(ctx, initialKey)
	require.NoError(t, err)

	// Test successful update
	err = backend.UpdateKey(ctx, initialKey.ID, func(key *types.Key) (*types.Key, error) {
		if key == nil {
			return nil, errors.New("key should not be nil")
		}
		key.VersionHash = "updated-in-transaction"
		return key, nil
	})
	assert.NoError(t, err)

	// Verify update
	updatedKey, err := backend.GetKey(ctx, initialKey.ID)
	assert.NoError(t, err)
	assert.Equal(t, "updated-in-transaction", updatedKey.VersionHash)

	// Test update that returns error
	err = backend.UpdateKey(ctx, initialKey.ID, func(_ *types.Key) (*types.Key, error) {
		return nil, errors.New("simulated update error")
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "simulated update error")

	// Test update that returns nil key (delete)
	err = backend.UpdateKey(ctx, initialKey.ID, func(_ *types.Key) (*types.Key, error) {
		return nil, nil // Delete the key
	})
	assert.NoError(t, err)

	// Verify key was deleted
	_, err = backend.GetKey(ctx, initialKey.ID)
	assert.Error(t, err)
	assert.True(t, storage.IsKeyNotFound(err))
}

// TestPostgresBackend_Ping tests health check operations.
func TestPostgresBackend_Ping(t *testing.T) {
	backend := setupTestBackend(t)
	defer backend.Close()
	ctx := t.Context()

	// Test healthy backend
	err := backend.Ping(ctx)
	assert.NoError(t, err)

	// Close backend and test ping fails
	backend.Close()
	err = backend.Ping(ctx)
	assert.Error(t, err)
	assert.True(t, storage.IsStorageUnavailable(err))
}

// TestPostgresBackend_Stats tests statistics collection.
func TestPostgresBackend_Stats(t *testing.T) {
	backend := setupTestBackend(t)
	defer backend.Close()
	ctx := t.Context()

	// Create some test keys
	for i := range 3 {
		key := createTestKey(fmt.Sprintf("stats-key-%d", i))
		err := backend.PutKey(ctx, key)
		require.NoError(t, err)
	}

	// Get stats - PostgreSQL backend implements StatsProvider
	stats, err := backend.Stats(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, stats)
	assert.Equal(t, int64(3), stats.TotalKeys)
	assert.Contains(t, stats.OperationCounts, "get")
	assert.Contains(t, stats.OperationCounts, "put")
	assert.Contains(t, stats.BackendSpecific, "backend")
	assert.Equal(t, "postgres", stats.BackendSpecific["backend"])
}

// TestPostgresBackend_Transaction tests transaction operations.
func TestPostgresBackend_Transaction(t *testing.T) {
	backend := setupTestBackend(t)
	defer backend.Close()
	ctx := t.Context()

	// Test successful transaction - PostgreSQL backend implements TransactionalBackend
	tx, err := backend.BeginTx(ctx)
	require.NoError(t, err)

	testKey := createTestKey("transaction-key")
	err = tx.PutKey(ctx, testKey)
	assert.NoError(t, err)

	err = tx.Commit()
	assert.NoError(t, err)

	// Verify key was committed
	retrievedKey, err := backend.GetKey(ctx, testKey.ID)
	assert.NoError(t, err)
	assert.Equal(t, testKey.ID, retrievedKey.ID)

	// Test rollback
	tx2, err := backend.BeginTx(ctx)
	require.NoError(t, err)

	rollbackKey := createTestKey("rollback-key")
	err = tx2.PutKey(ctx, rollbackKey)
	assert.NoError(t, err)

	err = tx2.Rollback()
	assert.NoError(t, err)

	// Verify rollback key doesn't exist
	_, err = backend.GetKey(ctx, rollbackKey.ID)
	assert.Error(t, err)
	assert.True(t, storage.IsKeyNotFound(err))

	// Test double commit
	tx3, err := backend.BeginTx(ctx)
	require.NoError(t, err)
	err = tx3.Commit()
	assert.NoError(t, err)
	err = tx3.Commit()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "transaction already committed")
}

// TestPostgresBackend_ConcurrentAccess tests concurrent access patterns.
func TestPostgresBackend_ConcurrentAccess(t *testing.T) {
	backend := setupTestBackend(t)
	defer backend.Close()
	ctx := t.Context()

	keyID := "concurrent-key"
	initialKey := createTestKey(keyID)
	err := backend.PutKey(ctx, initialKey)
	require.NoError(t, err)

	// Simulate concurrent updates
	done := make(chan bool, 2)

	// Update 1
	go func() {
		err := backend.UpdateKey(ctx, keyID, func(key *types.Key) (*types.Key, error) {
			time.Sleep(100 * time.Millisecond) // Simulate work
			key.VersionHash = "update-1"
			return key, nil
		})
		assert.NoError(t, err)
		done <- true
	}()

	// Update 2
	go func() {
		err := backend.UpdateKey(ctx, keyID, func(key *types.Key) (*types.Key, error) {
			time.Sleep(100 * time.Millisecond) // Simulate work
			key.VersionHash = "update-2"
			return key, nil
		})
		assert.NoError(t, err)
		done <- true
	}()

	// Wait for both updates to complete
	<-done
	<-done

	// Verify the key was updated (one of the updates won)
	finalKey, err := backend.GetKey(ctx, keyID)
	assert.NoError(t, err)
	assert.True(t, finalKey.VersionHash == "update-1" || finalKey.VersionHash == "update-2")
}

// TestPostgresBackend_ConnectionPool tests connection pool behavior.
func TestPostgresBackend_ConnectionPool(t *testing.T) {
	connectionString := getTestConnectionString(t)

	// Test with custom connection pool settings
	backend, err := postgres.New(connectionString, 5) // Small pool for testing
	assert.NoError(t, err)
	defer backend.Close()

	ctx := t.Context()

	// Perform multiple operations to test connection reuse
	for i := range 10 {
		key := createTestKey(fmt.Sprintf("pool-test-%d", i))
		err := backend.PutKey(ctx, key)
		assert.NoError(t, err)

		retrievedKey, err := backend.GetKey(ctx, key.ID)
		assert.NoError(t, err)
		assert.Equal(t, key.ID, retrievedKey.ID)
	}

	// Get stats to verify connection pool usage
	stats, err := backend.Stats(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, stats)
}

// Helper functions

func setupTestBackend(t *testing.T) *postgres.Backend {
	connectionString := getTestConnectionString(t)
	backend, err := postgres.New(connectionString, 10)
	require.NoError(t, err)

	// Clean up any existing test data
	ctx := t.Context()
	keys, err := backend.ListKeys(ctx, "")
	if err == nil {
		for _, keyID := range keys {
			_ = backend.DeleteKey(ctx, keyID)
		}
	}

	return backend
}

func getTestConnectionString(t *testing.T) string {
	connectionString := os.Getenv("TEST_POSTGRES_CONNECTION_STRING")
	if connectionString == "" {
		t.Skip("TEST_POSTGRES_CONNECTION_STRING environment variable not set")
	}
	return connectionString
}

func createTestKey(id string) *types.Key {
	return &types.Key{
		ID: id,
		ACL: types.ACL{
			{
				ID:         "user@example.com",
				Type:       types.User,
				AccessType: types.Read,
			},
			{
				ID:         "machine.example.com",
				Type:       types.Machine,
				AccessType: types.Write,
			},
		},
		VersionList: types.KeyVersionList{
			{
				ID:           1,
				Data:         []byte("primary-secret-data"),
				Status:       types.Primary,
				CreationTime: time.Now().UnixNano(),
			},
			{
				ID:           2,
				Data:         []byte("active-secret-data"),
				Status:       types.Active,
				CreationTime: time.Now().UnixNano(),
			},
		},
		VersionHash: "test-hash-" + id,
	}
}
