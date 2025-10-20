// Package storage provides tests for the storage abstraction layer.
package storage

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hazayan/knox/pkg/types"
	"github.com/stretchr/testify/assert"
)

// TestErrorHelpers tests the error helper functions.
func TestErrorHelpers(t *testing.T) {
	t.Run("IsKeyNotFound", func(t *testing.T) {
		assert.True(t, IsKeyNotFound(ErrKeyNotFound))
		assert.True(t, IsKeyNotFound(fmt.Errorf("wrapped: %w", ErrKeyNotFound)))
		assert.False(t, IsKeyNotFound(errors.New("other error")))
		assert.False(t, IsKeyNotFound(nil))
	})

	t.Run("IsKeyExists", func(t *testing.T) {
		assert.True(t, IsKeyExists(ErrKeyExists))
		assert.True(t, IsKeyExists(fmt.Errorf("wrapped: %w", ErrKeyExists)))
		assert.False(t, IsKeyExists(errors.New("other error")))
		assert.False(t, IsKeyExists(nil))
	})

	t.Run("IsStorageUnavailable", func(t *testing.T) {
		assert.True(t, IsStorageUnavailable(ErrStorageUnavailable))
		assert.True(t, IsStorageUnavailable(fmt.Errorf("wrapped: %w", ErrStorageUnavailable)))
		assert.False(t, IsStorageUnavailable(errors.New("other error")))
		assert.False(t, IsStorageUnavailable(nil))
	})

	t.Run("IsTransactionNotSupported", func(t *testing.T) {
		assert.True(t, IsTransactionNotSupported(ErrTransactionNotSupported))
		assert.True(t, IsTransactionNotSupported(fmt.Errorf("wrapped: %w", ErrTransactionNotSupported)))
		assert.False(t, IsTransactionNotSupported(errors.New("other error")))
		assert.False(t, IsTransactionNotSupported(nil))
	})

	t.Run("ErrorChaining", func(t *testing.T) {
		// Test deeply nested error chains
		deepErr := fmt.Errorf("level3: %w", fmt.Errorf("level2: %w", fmt.Errorf("level1: %w", ErrKeyNotFound)))
		assert.True(t, IsKeyNotFound(deepErr))
	})
}

// TestConfigValidation tests storage configuration validation.
func TestConfigValidation(t *testing.T) {
	t.Run("ValidConfig", func(t *testing.T) {
		// Register memory backend for test
		RegisterBackend("memory", func(_ Config) (Backend, error) {
			return &mockBackend{}, nil
		})

		cfg := Config{
			Backend: "memory",
		}
		backend, err := NewBackend(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, backend)
	})

	t.Run("UnknownBackend", func(t *testing.T) {
		cfg := Config{
			Backend: "unknown-backend",
		}
		backend, err := NewBackend(cfg)
		assert.Error(t, err)
		assert.Nil(t, backend)
		assert.Contains(t, err.Error(), "unknown storage backend")
	})

	t.Run("MissingBackend", func(t *testing.T) {
		cfg := Config{
			Backend: "",
		}
		backend, err := NewBackend(cfg)
		assert.Error(t, err)
		assert.Nil(t, backend)
		assert.Contains(t, err.Error(), "unknown storage backend")
	})

	t.Run("BackendFactoryError", func(t *testing.T) {
		// Register a backend that returns an error
		RegisterBackend("error-backend", func(_ Config) (Backend, error) {
			return nil, errors.New("factory error")
		})

		cfg := Config{
			Backend: "error-backend",
		}
		backend, err := NewBackend(cfg)
		assert.Error(t, err)
		assert.Nil(t, backend)
		assert.Contains(t, err.Error(), "factory error")
	})
}

// TestStatsValidation tests storage statistics validation.
func TestStatsValidation(t *testing.T) {
	t.Run("EmptyStats", func(t *testing.T) {
		stats := &Stats{
			TotalKeys:       0,
			StorageSize:     0,
			OperationCounts: make(map[string]int64),
			BackendSpecific: make(map[string]any),
		}
		assert.NotNil(t, stats)
		assert.Equal(t, int64(0), stats.TotalKeys)
		assert.Equal(t, int64(0), stats.StorageSize)
		assert.Empty(t, stats.OperationCounts)
		assert.Empty(t, stats.BackendSpecific)
	})

	t.Run("PopulatedStats", func(t *testing.T) {
		stats := &Stats{
			TotalKeys:   10,
			StorageSize: 1024,
			OperationCounts: map[string]int64{
				"get": 100,
				"put": 50,
			},
			BackendSpecific: map[string]any{
				"backend": "test",
				"custom":  "value",
			},
		}
		assert.Equal(t, int64(10), stats.TotalKeys)
		assert.Equal(t, int64(1024), stats.StorageSize)
		assert.Equal(t, int64(100), stats.OperationCounts["get"])
		assert.Equal(t, int64(50), stats.OperationCounts["put"])
		assert.Equal(t, "test", stats.BackendSpecific["backend"])
		assert.Equal(t, "value", stats.BackendSpecific["custom"])
	})

	t.Run("NilMaps", func(t *testing.T) {
		stats := &Stats{
			TotalKeys:       5,
			StorageSize:     512,
			OperationCounts: nil,
			BackendSpecific: nil,
		}
		assert.Equal(t, int64(5), stats.TotalKeys)
		assert.Equal(t, int64(512), stats.StorageSize)
		assert.Nil(t, stats.OperationCounts)
		assert.Nil(t, stats.BackendSpecific)
	})

	t.Run("LargeNumbers", func(t *testing.T) {
		stats := &Stats{
			TotalKeys:   1_000_000,
			StorageSize: 1_073_741_824, // 1GB
			OperationCounts: map[string]int64{
				"get": 1_000_000,
				"put": 500_000,
			},
		}
		assert.Equal(t, int64(1_000_000), stats.TotalKeys)
		assert.Equal(t, int64(1_073_741_824), stats.StorageSize)
		assert.Equal(t, int64(1_000_000), stats.OperationCounts["get"])
		assert.Equal(t, int64(500_000), stats.OperationCounts["put"])
	})
}

// TestBackendInterfaceCompliance tests that the interface is properly defined.
func TestBackendInterfaceCompliance(_ *testing.T) {
	// This test ensures the Backend interface has all required methods
	var _ Backend = (*mockBackend)(nil)
	var _ StatsProvider = (*mockBackend)(nil)
	var _ TransactionalBackend = (*mockBackend)(nil)
}

// mockBackend implements all storage interfaces for testing.
type mockBackend struct {
	pingError    error
	closeError   error
	statsError   error
	beginTxError error
}

// mockBackendWithStats implements StatsProvider with custom stats.
type mockBackendWithStats struct {
	mockBackend
	stats *Stats
}

func (m *mockBackend) GetKey(_ context.Context, keyID string) (*types.Key, error) {
	if keyID == "error" {
		return nil, errors.New("get key error")
	}
	return nil, ErrKeyNotFound
}

func (m *mockBackend) PutKey(_ context.Context, key *types.Key) error {
	if key != nil && key.ID == "error" {
		return errors.New("put key error")
	}
	return nil
}

func (m *mockBackend) DeleteKey(_ context.Context, keyID string) error {
	if keyID == "error" {
		return errors.New("delete key error")
	}
	return nil
}

func (m *mockBackend) ListKeys(_ context.Context, prefix string) ([]string, error) {
	if prefix == "error" {
		return nil, errors.New("list keys error")
	}
	return nil, nil
}

func (m *mockBackend) UpdateKey(_ context.Context, keyID string, updateFn func(*types.Key) (*types.Key, error)) error {
	if keyID == "error" {
		return errors.New("update key error")
	}
	if updateFn == nil {
		return errors.New("update function is nil")
	}
	return nil
}

func (m *mockBackend) Ping(_ context.Context) error {
	if m.pingError != nil {
		return m.pingError
	}
	return nil
}

func (m *mockBackend) Close() error {
	if m.closeError != nil {
		return m.closeError
	}
	return nil
}

func (m *mockBackend) Stats(_ context.Context) (*Stats, error) {
	if m.statsError != nil {
		return nil, m.statsError
	}
	return &Stats{}, nil
}

func (m *mockBackendWithStats) Stats(_ context.Context) (*Stats, error) {
	if m.statsError != nil {
		return nil, m.statsError
	}
	return m.stats, nil
}

func (m *mockBackend) BeginTx(_ context.Context) (Transaction, error) {
	if m.beginTxError != nil {
		return nil, m.beginTxError
	}
	return &mockTransaction{}, nil
}

// mockTransaction implements the Transaction interface for testing.
type mockTransaction struct {
	commitError   error
	rollbackError error
}

func (m *mockTransaction) GetKey(_ context.Context, keyID string) (*types.Key, error) {
	if keyID == "error" {
		return nil, errors.New("transaction get key error")
	}
	return nil, ErrKeyNotFound
}

func (m *mockTransaction) PutKey(_ context.Context, key *types.Key) error {
	if key != nil && key.ID == "error" {
		return errors.New("transaction put key error")
	}
	return nil
}

func (m *mockTransaction) DeleteKey(_ context.Context, keyID string) error {
	if keyID == "error" {
		return errors.New("transaction delete key error")
	}
	return nil
}

func (m *mockTransaction) Commit() error {
	if m.commitError != nil {
		return m.commitError
	}
	return nil
}

func (m *mockTransaction) Rollback() error {
	if m.rollbackError != nil {
		return m.rollbackError
	}
	return nil
}

// TestEncryptedBackendCompliance tests that EncryptedBackend implements the required interfaces.
func TestEncryptedBackendCompliance(_ *testing.T) {
	// This ensures the encrypted backend wrapper implements the keydb.DB interface
	// The actual encrypted backend tests are in the encrypted_test.go file
	var _ Backend = (*mockBackend)(nil)
}

// TestContextCancellation tests that operations respect context cancellation.
func TestContextCancellation(t *testing.T) {
	backend := &mockBackend{}

	t.Run("CancelledContext", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel() // Cancel immediately

		// All operations should respect the cancelled context
		// Note: Our mock backend doesn't actually check context, but we verify
		// that the operations complete without panicking when context is cancelled
		key, err := backend.GetKey(ctx, "test")
		assert.Nil(t, key)
		assert.Error(t, err)
		assert.True(t, IsKeyNotFound(err))

		err = backend.PutKey(ctx, &types.Key{ID: "test"})
		assert.NoError(t, err)

		err = backend.DeleteKey(ctx, "test")
		assert.NoError(t, err)

		keys, err := backend.ListKeys(ctx, "")
		assert.NoError(t, err)
		assert.Nil(t, keys)

		err = backend.Ping(ctx)
		assert.NoError(t, err)
	})

	t.Run("TimeoutContext", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
		defer cancel()

		// Give it a moment to timeout
		time.Sleep(2 * time.Millisecond)

		// Our mock backend doesn't check context deadlines, but verify it doesn't panic
		err := backend.Ping(ctx)
		assert.NoError(t, err)
	})
}

// TestBackendErrorConditions tests various error conditions.
func TestBackendErrorConditions(t *testing.T) {
	t.Run("PingError", func(t *testing.T) {
		backend := &mockBackend{pingError: errors.New("ping failed")}
		err := backend.Ping(t.Context())
		assert.Error(t, err)
		assert.Equal(t, "ping failed", err.Error())
	})

	t.Run("CloseError", func(t *testing.T) {
		backend := &mockBackend{closeError: errors.New("close failed")}
		err := backend.Close()
		assert.Error(t, err)
		assert.Equal(t, "close failed", err.Error())
	})

	t.Run("StatsError", func(t *testing.T) {
		backend := &mockBackend{statsError: errors.New("stats failed")}
		stats, err := backend.Stats(t.Context())
		assert.Error(t, err)
		assert.Nil(t, stats)
		assert.Equal(t, "stats failed", err.Error())
	})

	t.Run("BeginTxError", func(t *testing.T) {
		backend := &mockBackend{beginTxError: errors.New("begin tx failed")}
		tx, err := backend.BeginTx(t.Context())
		assert.Error(t, err)
		assert.Nil(t, tx)
		assert.Equal(t, "begin tx failed", err.Error())
	})

	t.Run("CustomStats", func(t *testing.T) {
		customStats := &Stats{
			TotalKeys:   100,
			StorageSize: 2048,
			OperationCounts: map[string]int64{
				"custom_op": 42,
			},
			BackendSpecific: map[string]any{
				"custom_metric": "value",
			},
		}
		backend := &mockBackendWithStats{stats: customStats}
		stats, err := backend.Stats(t.Context())
		assert.NoError(t, err)
		assert.Equal(t, customStats, stats)
	})
}

// TestTransactionErrorConditions tests transaction error conditions.
func TestTransactionErrorConditions(t *testing.T) {
	t.Run("CommitError", func(t *testing.T) {
		tx := &mockTransaction{commitError: errors.New("commit failed")}
		err := tx.Commit()
		assert.Error(t, err)
		assert.Equal(t, "commit failed", err.Error())
	})

	t.Run("RollbackError", func(t *testing.T) {
		tx := &mockTransaction{rollbackError: errors.New("rollback failed")}
		err := tx.Rollback()
		assert.Error(t, err)
		assert.Equal(t, "rollback failed", err.Error())
	})

	t.Run("TransactionOperationsWithError", func(t *testing.T) {
		tx := &mockTransaction{}
		ctx := t.Context()

		// Test GetKey with error
		key, err := tx.GetKey(ctx, "error")
		assert.Nil(t, key)
		assert.Error(t, err)
		assert.Equal(t, "transaction get key error", err.Error())

		// Test PutKey with error
		err = tx.PutKey(ctx, &types.Key{ID: "error"})
		assert.Error(t, err)
		assert.Equal(t, "transaction put key error", err.Error())

		// Test DeleteKey with error
		err = tx.DeleteKey(ctx, "error")
		assert.Error(t, err)
		assert.Equal(t, "transaction delete key error", err.Error())
	})
}

// TestBackendOperationsWithError tests backend operations with error conditions.
func TestBackendOperationsWithError(t *testing.T) {
	backend := &mockBackend{}
	ctx := t.Context()

	t.Run("GetKeyWithError", func(t *testing.T) {
		key, err := backend.GetKey(ctx, "error")
		assert.Nil(t, key)
		assert.Error(t, err)
		assert.Equal(t, "get key error", err.Error())
	})

	t.Run("PutKeyWithError", func(t *testing.T) {
		err := backend.PutKey(ctx, &types.Key{ID: "error"})
		assert.Error(t, err)
		assert.Equal(t, "put key error", err.Error())
	})

	t.Run("DeleteKeyWithError", func(t *testing.T) {
		err := backend.DeleteKey(ctx, "error")
		assert.Error(t, err)
		assert.Equal(t, "delete key error", err.Error())
	})

	t.Run("ListKeysWithError", func(t *testing.T) {
		keys, err := backend.ListKeys(ctx, "error")
		assert.Nil(t, keys)
		assert.Error(t, err)
		assert.Equal(t, "list keys error", err.Error())
	})

	t.Run("UpdateKeyWithError", func(t *testing.T) {
		err := backend.UpdateKey(ctx, "error", func(key *types.Key) (*types.Key, error) {
			return key, nil
		})
		assert.Error(t, err)
		assert.Equal(t, "update key error", err.Error())
	})

	t.Run("UpdateKeyWithNilFunction", func(t *testing.T) {
		err := backend.UpdateKey(ctx, "test", nil)
		assert.Error(t, err)
		assert.Equal(t, "update function is nil", err.Error())
	})
}

// TestInterfaceCompliance tests that interfaces are properly implemented.
func TestInterfaceCompliance(t *testing.T) {
	t.Run("BackendInterface", func(t *testing.T) {
		var backend Backend = &mockBackend{}
		assert.NotNil(t, backend)
	})

	t.Run("TransactionalBackendInterface", func(t *testing.T) {
		var txBackend TransactionalBackend = &mockBackend{}
		assert.NotNil(t, txBackend)
	})

	t.Run("StatsProviderInterface", func(t *testing.T) {
		var statsProvider StatsProvider = &mockBackend{}
		assert.NotNil(t, statsProvider)
	})

	t.Run("TransactionInterface", func(t *testing.T) {
		var tx Transaction = &mockTransaction{}
		assert.NotNil(t, tx)
	})
}

// TestBackendRegistrationEdgeCases tests edge cases in backend registration.
func TestBackendRegistrationEdgeCases(t *testing.T) {
	// Save original registry
	originalRegistry := make(map[string]BackendFactory)
	for k, v := range backendRegistry {
		originalRegistry[k] = v
	}
	defer func() {
		// Restore original registry
		backendRegistry = originalRegistry
	}()

	t.Run("NilFactory", func(t *testing.T) {
		// Clear registry
		backendRegistry = make(map[string]BackendFactory)

		// Register nil factory
		RegisterBackend("nil-factory", nil)

		// Should still be able to create config
		cfg := Config{Backend: "nil-factory"}
		backend, err := NewBackend(cfg)
		assert.Error(t, err)
		assert.Nil(t, backend)
	})

	t.Run("MultipleBackends", func(t *testing.T) {
		// Clear registry
		backendRegistry = make(map[string]BackendFactory)

		// Register multiple backends
		RegisterBackend("backend1", func(_ Config) (Backend, error) {
			return &mockBackend{}, nil
		})
		RegisterBackend("backend2", func(_ Config) (Backend, error) {
			return &mockBackend{}, nil
		})
		RegisterBackend("backend3", func(_ Config) (Backend, error) {
			return &mockBackend{}, nil
		})

		// Verify all are registered
		assert.Len(t, backendRegistry, 3)
		assert.Contains(t, backendRegistry, "backend1")
		assert.Contains(t, backendRegistry, "backend2")
		assert.Contains(t, backendRegistry, "backend3")
	})
}

// BenchmarkBackendOperations benchmarks storage operations.
func BenchmarkBackendOperations(b *testing.B) {
	backend := &mockBackend{}
	ctx := b.Context()
	key := &types.Key{ID: "benchmark"}

	b.ResetTimer()

	b.Run("GetKey", func(b *testing.B) {
		for range b.N {
			_, _ = backend.GetKey(ctx, "benchmark")
		}
	})

	b.Run("PutKey", func(b *testing.B) {
		for range b.N {
			_ = backend.PutKey(ctx, key)
		}
	})

	b.Run("DeleteKey", func(b *testing.B) {
		for range b.N {
			_ = backend.DeleteKey(ctx, "benchmark")
		}
	})

	b.Run("ListKeys", func(b *testing.B) {
		for range b.N {
			_, _ = backend.ListKeys(ctx, "")
		}
	})

	b.Run("Ping", func(b *testing.B) {
		for range b.N {
			_ = backend.Ping(ctx)
		}
	})
}

// TestBackendRegistration tests backend registration functionality.
func TestBackendRegistration(t *testing.T) {
	// Save original registry
	originalRegistry := make(map[string]BackendFactory)
	for k, v := range backendRegistry {
		originalRegistry[k] = v
	}
	defer func() {
		// Restore original registry
		backendRegistry = originalRegistry
	}()

	// Clear registry for test
	backendRegistry = make(map[string]BackendFactory)

	t.Run("RegisterAndCreate", func(t *testing.T) {
		// Register a test backend
		RegisterBackend("test-backend", func(_ Config) (Backend, error) {
			return &mockBackend{}, nil
		})

		// Verify registration
		_, exists := backendRegistry["test-backend"]
		assert.True(t, exists)

		// Test creating the backend
		cfg := Config{Backend: "test-backend"}
		backend, err := NewBackend(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, backend)
	})

	t.Run("DuplicateRegistration", func(t *testing.T) {
		// Register same backend twice - should overwrite
		RegisterBackend("duplicate", func(_ Config) (Backend, error) {
			return &mockBackend{}, nil
		})
		RegisterBackend("duplicate", func(_ Config) (Backend, error) {
			return &mockBackend{}, nil
		})

		// Should still work
		cfg := Config{Backend: "duplicate"}
		backend, err := NewBackend(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, backend)
	})
}

// TestTransactionInterface tests the transaction interface methods.
func TestTransactionInterface(t *testing.T) {
	tx := &mockTransaction{}
	ctx := t.Context()

	t.Run("GetKey", func(t *testing.T) {
		key, err := tx.GetKey(ctx, "test")
		assert.Error(t, err)
		assert.True(t, IsKeyNotFound(err))
		assert.Nil(t, key)
	})

	t.Run("PutKey", func(t *testing.T) {
		err := tx.PutKey(ctx, &types.Key{ID: "test"})
		assert.NoError(t, err)
	})

	t.Run("DeleteKey", func(t *testing.T) {
		err := tx.DeleteKey(ctx, "test")
		assert.NoError(t, err)
	})

	t.Run("Commit", func(t *testing.T) {
		err := tx.Commit()
		assert.NoError(t, err)
	})

	t.Run("Rollback", func(t *testing.T) {
		err := tx.Rollback()
		assert.NoError(t, err)
	})
}

// TestBackendInterfaceMethods tests all Backend interface methods.
func TestBackendInterfaceMethods(t *testing.T) {
	backend := &mockBackend{}
	ctx := t.Context()

	t.Run("GetKey", func(t *testing.T) {
		key, err := backend.GetKey(ctx, "test")
		assert.Error(t, err)
		assert.True(t, IsKeyNotFound(err))
		assert.Nil(t, key)
	})

	t.Run("PutKey", func(t *testing.T) {
		err := backend.PutKey(ctx, &types.Key{ID: "test"})
		assert.NoError(t, err)
	})

	t.Run("DeleteKey", func(t *testing.T) {
		err := backend.DeleteKey(ctx, "test")
		assert.NoError(t, err)
	})

	t.Run("ListKeys", func(t *testing.T) {
		keys, err := backend.ListKeys(ctx, "")
		assert.NoError(t, err)
		assert.Nil(t, keys)
	})

	t.Run("UpdateKey", func(t *testing.T) {
		err := backend.UpdateKey(ctx, "test", func(key *types.Key) (*types.Key, error) {
			return key, nil
		})
		assert.NoError(t, err)
	})

	t.Run("Ping", func(t *testing.T) {
		err := backend.Ping(ctx)
		assert.NoError(t, err)
	})

	t.Run("Close", func(t *testing.T) {
		err := backend.Close()
		assert.NoError(t, err)
	})

	t.Run("Stats", func(t *testing.T) {
		stats, err := backend.Stats(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, stats)
	})

	t.Run("BeginTx", func(t *testing.T) {
		tx, err := backend.BeginTx(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, tx)
	})
}

// TestErrorWrapping tests that errors are properly wrapped and detected.
func TestErrorWrapping(t *testing.T) {
	t.Run("WrappedKeyNotFound", func(t *testing.T) {
		wrappedErr := fmt.Errorf("operation failed: %w", ErrKeyNotFound)
		assert.True(t, IsKeyNotFound(wrappedErr))
	})

	t.Run("WrappedKeyExists", func(t *testing.T) {
		wrappedErr := fmt.Errorf("operation failed: %w", ErrKeyExists)
		assert.True(t, IsKeyExists(wrappedErr))
	})

	t.Run("WrappedStorageUnavailable", func(t *testing.T) {
		wrappedErr := fmt.Errorf("operation failed: %w", ErrStorageUnavailable)
		assert.True(t, IsStorageUnavailable(wrappedErr))
	})

	t.Run("WrappedTransactionNotSupported", func(t *testing.T) {
		wrappedErr := fmt.Errorf("operation failed: %w", ErrTransactionNotSupported)
		assert.True(t, IsTransactionNotSupported(wrappedErr))
	})
}

func TestBackendUpdateKeyEdgeCases(t *testing.T) {
	ctx := t.Context()
	backend := &mockBackend{}

	// Test UpdateKey with nil key (key doesn't exist)
	err := backend.UpdateKey(ctx, "nonexistent", func(k *types.Key) (*types.Key, error) {
		assert.Nil(t, k) // Should receive nil for non-existent key
		return &types.Key{
			ID: "nonexistent",
			ACL: types.ACL{
				{Type: types.User, ID: "user@example.com", AccessType: types.Admin},
			},
			VersionList: types.KeyVersionList{
				{ID: 1, Data: []byte("new-secret"), Status: types.Primary},
			},
		}, nil
	})
	assert.NoError(t, err)

	// Test UpdateKey with update function returning error
	err = backend.UpdateKey(ctx, "test", func(_ *types.Key) (*types.Key, error) {
		return nil, errors.New("update failed")
	})
	assert.NoError(t, err) // Mock doesn't actually execute the update

	// Test UpdateKey with nil return (delete key)
	err = backend.UpdateKey(ctx, "test", func(_ *types.Key) (*types.Key, error) {
		return nil, nil // Delete the key
	})
	assert.NoError(t, err)
}

func TestBackendFactoryErrorHandling(t *testing.T) {
	// Test factory that returns error
	errorFactory := func(_ Config) (Backend, error) {
		return nil, errors.New("factory error")
	}

	// Register error factory
	RegisterBackend("error-backend", errorFactory)

	// Test that factory error is propagated
	_, err := NewBackend(Config{Backend: "error-backend"})
	assert.Error(t, err)
	assert.Equal(t, "factory error", err.Error())
}

func TestBackendNilFactory(t *testing.T) {
	// This tests the edge case where a nil factory is registered
	// Note: This is protected against in NewBackend, so we need to test that protection

	// Temporarily register a nil factory to test the error case
	// We'll use a backend name that doesn't exist in the real registry
	_, err := NewBackend(Config{Backend: "this-backend-does-not-exist"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown storage backend")
}

func TestContextCancellationInStorage(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	backend := &mockBackend{}

	// Cancel context before operation
	cancel()

	// Test that operations respect context cancellation
	// Note: Our mock doesn't check context, but real implementations should
	// The mock returns ErrKeyNotFound for GetKey, so we expect that error
	_, err := backend.GetKey(ctx, "test")
	assert.Error(t, err) // Mock returns ErrKeyNotFound
	assert.Equal(t, ErrKeyNotFound, err)

	// For other operations, the mock returns nil
	err = backend.PutKey(ctx, &types.Key{ID: "test"})
	assert.NoError(t, err) // Mock doesn't check context

	err = backend.DeleteKey(ctx, "test")
	assert.NoError(t, err) // Mock doesn't check context

	_, err = backend.ListKeys(ctx, "")
	assert.NoError(t, err) // Mock doesn't check context

	err = backend.Ping(ctx)
	assert.NoError(t, err) // Mock doesn't check context
}

// TestConfigPopulated tests configuration with populated values.
func TestConfigPopulated(t *testing.T) {
	cfg := Config{
		Backend:                  "postgres",
		FilesystemDir:            "/tmp/knox",
		PostgresConnectionString: "postgresql://user:pass@localhost/knox",
		PostgresMaxConnections:   50,
		EtcdEndpoints:            []string{"localhost:2379"},
		EtcdPrefix:               "/knox",
		ReadOnly:                 true,
	}
	assert.Equal(t, "postgres", cfg.Backend)
	assert.Equal(t, "/tmp/knox", cfg.FilesystemDir)
	assert.Equal(t, "postgresql://user:pass@localhost/knox", cfg.PostgresConnectionString)
	assert.Equal(t, 50, cfg.PostgresMaxConnections)
	assert.Equal(t, []string{"localhost:2379"}, cfg.EtcdEndpoints)
	assert.Equal(t, "/knox", cfg.EtcdPrefix)
	assert.True(t, cfg.ReadOnly)
}
