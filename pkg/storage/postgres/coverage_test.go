// Package postgres_test provides additional coverage tests for the PostgreSQL storage backend.
package postgres_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/hazayan/knox/pkg/storage"
	"github.com/hazayan/knox/pkg/storage/postgres"
	"github.com/hazayan/knox/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPostgresBackend_InitSchema_Coverage tests schema initialization.
func TestPostgresBackend_InitSchema_Coverage(t *testing.T) {
	t.Run("SchemaInitializationSuccess", func(t *testing.T) {
		connectionString := getTestConnectionString(t)
		backend, err := postgres.New(connectionString, 10)
		require.NoError(t, err)
		defer backend.Close()

		ctx := t.Context()

		// The schema should be initialized automatically during backend creation
		// We can verify this by performing operations
		testKey := createTestKey("schema-test-key")
		err = backend.PutKey(ctx, testKey)
		assert.NoError(t, err)

		retrievedKey, err := backend.GetKey(ctx, testKey.ID)
		assert.NoError(t, err)
		assert.Equal(t, testKey.ID, retrievedKey.ID)
	})

	t.Run("SchemaInitializationFailure", func(t *testing.T) {
		// Test with invalid connection string to trigger schema init failure
		_, err := postgres.New("postgresql://invalid:password@invalid-host:5432/invalid-db", 1)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to ping database")
	})
}

// TestPostgresBackend_Close_Coverage tests backend closure.
func TestPostgresBackend_Close_Coverage(t *testing.T) {
	t.Run("CloseSuccess", func(t *testing.T) {
		connectionString := getTestConnectionString(t)
		backend, err := postgres.New(connectionString, 10)
		require.NoError(t, err)

		// Close should succeed
		err = backend.Close()
		assert.NoError(t, err)

		// Subsequent operations should fail
		ctx := t.Context()
		err = backend.Ping(ctx)
		assert.Error(t, err)
		assert.True(t, storage.IsStorageUnavailable(err))
	})

	t.Run("DoubleClose", func(t *testing.T) {
		connectionString := getTestConnectionString(t)
		backend, err := postgres.New(connectionString, 10)
		require.NoError(t, err)

		// First close should succeed
		err = backend.Close()
		assert.NoError(t, err)

		// Second close should also succeed (idempotent)
		err = backend.Close()
		assert.NoError(t, err)
	})
}

// TestPostgresBackend_Ping_Coverage tests health checks.
func TestPostgresBackend_Ping_Coverage(t *testing.T) {
	t.Run("PingClosedBackend", func(t *testing.T) {
		connectionString := getTestConnectionString(t)
		backend, err := postgres.New(connectionString, 10)
		require.NoError(t, err)

		// Close the backend first
		err = backend.Close()
		assert.NoError(t, err)

		// Ping should fail on closed backend
		ctx := t.Context()
		err = backend.Ping(ctx)
		assert.Error(t, err)
		assert.True(t, storage.IsStorageUnavailable(err))
	})
}

// TestPostgresTransaction_Methods_Coverage tests transaction methods.
func TestPostgresTransaction_Methods_Coverage(t *testing.T) {
	connectionString := getTestConnectionString(t)
	backend, err := postgres.New(connectionString, 10)
	require.NoError(t, err)
	defer backend.Close()

	ctx := t.Context()

	t.Run("TransactionGetKeyNotFound", func(t *testing.T) {
		tx, err := backend.BeginTx(ctx)
		require.NoError(t, err)
		defer func() {
			if err := tx.Rollback(); err != nil {
				t.Logf("Rollback error: %v", err)
			}
		}()

		key, err := tx.GetKey(ctx, "non-existent-transaction-key")
		assert.Error(t, err)
		assert.Nil(t, key)
		assert.True(t, storage.IsKeyNotFound(err))
	})

	t.Run("TransactionPutKeyInvalidData", func(t *testing.T) {
		tx, err := backend.BeginTx(ctx)
		require.NoError(t, err)
		defer func() {
			if err := tx.Rollback(); err != nil {
				t.Logf("Rollback error: %v", err)
			}
		}()

		invalidKey := &types.Key{
			ID:          "invalid-transaction-key",
			ACL:         types.ACL{},
			VersionList: types.KeyVersionList{},
			VersionHash: "",
		}

		err = tx.PutKey(ctx, invalidKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key validation failed")
	})

	t.Run("TransactionDeleteNonExistentKey", func(t *testing.T) {
		tx, err := backend.BeginTx(ctx)
		require.NoError(t, err)
		defer func() {
			if err := tx.Rollback(); err != nil {
				t.Logf("Rollback error: %v", err)
			}
		}()

		err = tx.DeleteKey(ctx, "non-existent-transaction-delete-key")
		assert.NoError(t, err) // Should not error for non-existent keys
	})

	t.Run("TransactionCommitAfterRollback", func(t *testing.T) {
		tx, err := backend.BeginTx(ctx)
		require.NoError(t, err)

		// Rollback first
		err = tx.Rollback()
		assert.NoError(t, err)

		// Try to commit after rollback
		err = tx.Commit()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "transaction already rolled back")
	})

	t.Run("TransactionRollbackAfterCommit", func(t *testing.T) {
		tx, err := backend.BeginTx(ctx)
		require.NoError(t, err)

		// Commit first
		err = tx.Commit()
		assert.NoError(t, err)

		// Try to rollback after commit
		err = tx.Rollback()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "transaction already committed")
	})
}

// TestPostgresBackend_EdgeCases_Coverage tests edge cases.
func TestPostgresBackend_EdgeCases_Coverage(t *testing.T) {
	connectionString := getTestConnectionString(t)
	backend, err := postgres.New(connectionString, 10)
	require.NoError(t, err)
	defer backend.Close()

	ctx := t.Context()

	t.Run("PutKeyWithEmptyID", func(t *testing.T) {
		emptyKey := &types.Key{
			ID:          "",
			ACL:         types.ACL{},
			VersionList: types.KeyVersionList{},
			VersionHash: "hash",
		}

		err := backend.PutKey(ctx, emptyKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key validation failed")
	})

	t.Run("PutKeyWithNilACL", func(t *testing.T) {
		nilACLKey := &types.Key{
			ID:          "nil-acl-key",
			ACL:         nil,
			VersionList: types.KeyVersionList{},
			VersionHash: "hash",
		}

		err := backend.PutKey(ctx, nilACLKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key validation failed")
	})

	t.Run("PutKeyWithNilVersionList", func(t *testing.T) {
		nilVersionKey := &types.Key{
			ID:          "nil-version-key",
			ACL:         types.ACL{},
			VersionList: nil,
			VersionHash: "hash",
		}

		err := backend.PutKey(ctx, nilVersionKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key validation failed")
	})

	t.Run("GetKeyWithEmptyID", func(t *testing.T) {
		key, err := backend.GetKey(ctx, "")
		assert.Error(t, err)
		assert.Nil(t, key)
		assert.True(t, storage.IsKeyNotFound(err))
	})

	t.Run("DeleteKeyWithEmptyID", func(t *testing.T) {
		err := backend.DeleteKey(ctx, "")
		assert.NoError(t, err) // Should not error for empty IDs
	})

	t.Run("ListKeysWithSpecialCharacters", func(t *testing.T) {
		specialKey := createTestKey("service:api-key@v1.0.0")
		err := backend.PutKey(ctx, specialKey)
		require.NoError(t, err)

		keys, err := backend.ListKeys(ctx, "service:")
		assert.NoError(t, err)
		assert.Contains(t, keys, "service:api-key@v1.0.0")
	})
}

// TestPostgresBackend_ConcurrentOperations_Coverage tests concurrent operations.
func TestPostgresBackend_ConcurrentOperations_Coverage(t *testing.T) {
	connectionString := getTestConnectionString(t)
	backend, err := postgres.New(connectionString, 20) // Larger pool for concurrency
	require.NoError(t, err)
	defer backend.Close()

	ctx := t.Context()
	keyID := "concurrent-test-key"

	// Create initial key
	initialKey := createTestKey(keyID)
	err = backend.PutKey(ctx, initialKey)
	require.NoError(t, err)

	// Test concurrent reads
	t.Run("ConcurrentReads", func(t *testing.T) {
		const numReaders = 10
		done := make(chan bool, numReaders)

		for i := range numReaders {
			go func(_ int) {
				key, err := backend.GetKey(ctx, keyID)
				assert.NoError(t, err)
				assert.Equal(t, keyID, key.ID)
				done <- true
			}(i)
		}

		// Wait for all readers to complete
		for range numReaders {
			<-done
		}
	})

	// Test concurrent updates with transactions
	t.Run("ConcurrentTransactionalUpdates", func(t *testing.T) {
		const numUpdaters = 5
		done := make(chan bool, numUpdaters)

		for i := range numUpdaters {
			go func(updaterID int) {
				err := backend.UpdateKey(ctx, keyID, func(key *types.Key) (*types.Key, error) {
					if key == nil {
						return nil, errors.New("key not found")
					}
					key.VersionHash = fmt.Sprintf("updated-by-%d", updaterID)
					return key, nil
				})
				assert.NoError(t, err)
				done <- true
			}(i)
		}

		// Wait for all updaters to complete
		for range numUpdaters {
			<-done
		}

		// Verify the key was updated
		finalKey, err := backend.GetKey(ctx, keyID)
		assert.NoError(t, err)
		assert.NotEqual(t, initialKey.VersionHash, finalKey.VersionHash)
	})
}

// TestPostgresBackend_Stats_Coverage tests statistics collection.
func TestPostgresBackend_Stats_Coverage(t *testing.T) {
	connectionString := getTestConnectionString(t)
	backend, err := postgres.New(connectionString, 10)
	require.NoError(t, err)
	defer backend.Close()

	ctx := t.Context()

	t.Run("StatsWithNoKeys", func(t *testing.T) {
		// Clean up any existing keys
		keys, err := backend.ListKeys(ctx, "")
		if err == nil {
			for _, keyID := range keys {
				_ = backend.DeleteKey(ctx, keyID)
			}
		}

		stats, err := backend.Stats(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, stats)
		assert.Equal(t, int64(0), stats.TotalKeys)
		assert.Contains(t, stats.BackendSpecific, "backend")
		assert.Equal(t, "postgres", stats.BackendSpecific["backend"])
	})

	t.Run("StatsWithMultipleKeys", func(t *testing.T) {
		// Create multiple keys
		for i := range 5 {
			key := createTestKey(fmt.Sprintf("stats-key-%d", i))
			err := backend.PutKey(ctx, key)
			require.NoError(t, err)
		}

		stats, err := backend.Stats(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, stats)
		assert.Equal(t, int64(5), stats.TotalKeys)
		assert.Greater(t, stats.StorageSize, int64(0))
	})
}

// TestPostgresBackend_ConnectionPool_Coverage tests connection pool behavior.
func TestPostgresBackend_ConnectionPool_Coverage(t *testing.T) {
	t.Run("SmallConnectionPool", func(t *testing.T) {
		connectionString := getTestConnectionString(t)
		backend, err := postgres.New(connectionString, 2) // Very small pool
		require.NoError(t, err)
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
	})
}

// Helper functions - use the ones from postgres_test.go
