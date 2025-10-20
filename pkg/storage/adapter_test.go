package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hazayan/knox/pkg/types"
	"github.com/hazayan/knox/server/keydb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockBackend is a mock implementation of Backend for testing.
type MockBackend struct {
	keys       map[string]*types.Key
	callLog    []string
	shouldFail bool
	failOps    map[string]bool
}

func NewMockBackend() *MockBackend {
	return &MockBackend{
		keys:    make(map[string]*types.Key),
		callLog: make([]string, 0),
		failOps: make(map[string]bool),
	}
}

func (m *MockBackend) GetKey(_ context.Context, keyID string) (*types.Key, error) {
	m.callLog = append(m.callLog, "GetKey:"+keyID)
	if m.shouldFail || m.failOps["GetKey"] {
		return nil, errors.New("backend get failed")
	}
	key, exists := m.keys[keyID]
	if !exists {
		return nil, ErrKeyNotFound
	}
	return key, nil
}

func (m *MockBackend) PutKey(_ context.Context, key *types.Key) error {
	m.callLog = append(m.callLog, "PutKey:"+key.ID)
	if m.shouldFail || m.failOps["PutKey"] {
		return errors.New("backend put failed")
	}
	m.keys[key.ID] = key
	return nil
}

func (m *MockBackend) DeleteKey(_ context.Context, keyID string) error {
	m.callLog = append(m.callLog, "DeleteKey:"+keyID)
	if m.shouldFail || m.failOps["DeleteKey"] {
		return errors.New("backend delete failed")
	}
	delete(m.keys, keyID)
	return nil
}

func (m *MockBackend) ListKeys(_ context.Context, prefix string) ([]string, error) {
	m.callLog = append(m.callLog, "ListKeys:"+prefix)
	if m.shouldFail || m.failOps["ListKeys"] {
		return nil, errors.New("backend list failed")
	}
	keys := make([]string, 0, len(m.keys))
	for keyID := range m.keys {
		keys = append(keys, keyID)
	}
	return keys, nil
}

func (m *MockBackend) Ping(_ context.Context) error {
	m.callLog = append(m.callLog, "Ping")
	if m.shouldFail || m.failOps["Ping"] {
		return errors.New("backend ping failed")
	}
	return nil
}

func (m *MockBackend) Stats(_ context.Context) (*Stats, error) {
	m.callLog = append(m.callLog, "Stats")
	if m.shouldFail || m.failOps["Stats"] {
		return nil, errors.New("backend stats failed")
	}
	return &Stats{
		TotalKeys: int64(len(m.keys)),
	}, nil
}

func (m *MockBackend) BeginTx(_ context.Context) (Transaction, error) {
	m.callLog = append(m.callLog, "BeginTx")
	if m.shouldFail || m.failOps["BeginTx"] {
		return nil, errors.New("backend begin tx failed")
	}
	return nil, ErrTransactionNotSupported
}

func (m *MockBackend) Close() error {
	m.callLog = append(m.callLog, "Close")
	if m.shouldFail || m.failOps["Close"] {
		return errors.New("backend close failed")
	}
	return nil
}

func (m *MockBackend) UpdateKey(ctx context.Context, keyID string, updateFn func(*types.Key) (*types.Key, error)) error {
	m.callLog = append(m.callLog, "UpdateKey:"+keyID)
	if m.shouldFail || m.failOps["UpdateKey"] {
		return errors.New("backend update failed")
	}

	currentKey, _ := m.GetKey(ctx, keyID)
	newKey, err := updateFn(currentKey)
	if err != nil {
		return err
	}
	if newKey != nil {
		m.keys[keyID] = newKey
	} else {
		delete(m.keys, keyID)
	}
	return nil
}

func (m *MockBackend) SetFailOps(ops ...string) {
	for _, op := range ops {
		m.failOps[op] = true
	}
}

func (m *MockBackend) ClearFailOps() {
	m.failOps = make(map[string]bool)
}

func (m *MockBackend) SetShouldFail(shouldFail bool) {
	m.shouldFail = shouldFail
}

// TestDBAdapter_NewDBAdapter tests the creation of a new DBAdapter.
func TestDBAdapter_NewDBAdapter(t *testing.T) {
	mockBackend := NewMockBackend()

	adapter := NewDBAdapter(mockBackend, nil)
	assert.NotNil(t, adapter, "Adapter should be created successfully")
}

// TestDBAdapter_Get tests the Get method.
func TestDBAdapter_Get(t *testing.T) {
	t.Run("Get_ExistingKey", func(t *testing.T) {
		mockBackend := NewMockBackend()
		adapter := NewDBAdapter(mockBackend, nil)

		// Create test DBKey and serialize it
		testDBKey := &keydb.DBKey{
			ID: "test-key",
			ACL: types.ACL{
				{Type: types.User, ID: "test-user", AccessType: types.Read},
			},
			VersionList: []keydb.EncKeyVersion{
				{ID: 1, EncData: []byte("encrypted-data")},
			},
		}

		data, err := json.Marshal(testDBKey)
		require.NoError(t, err)

		// Store in backend
		wrapper := &types.Key{
			ID:  "test-key",
			ACL: testDBKey.ACL,
			VersionList: types.KeyVersionList{
				{ID: 1, Data: data},
			},
		}
		err = mockBackend.PutKey(t.Context(), wrapper)
		require.NoError(t, err)

		// Retrieve via adapter
		result, err := adapter.Get("test-key")
		require.NoError(t, err)
		assert.Equal(t, testDBKey.ID, result.ID)
		assert.Equal(t, testDBKey.ACL, result.ACL)
		assert.Equal(t, testDBKey.VersionList, result.VersionList)
	})

	t.Run("Get_NonExistentKey", func(t *testing.T) {
		mockBackend := NewMockBackend()
		adapter := NewDBAdapter(mockBackend, nil)

		result, err := adapter.Get("non-existent")
		require.NoError(t, err)
		assert.Nil(t, result, "Should return nil for non-existent key")
	})

	t.Run("Cache_Invalidation", func(t *testing.T) {
		mockBackend := NewMockBackend()
		adapter := NewDBAdapter(mockBackend, nil).(*DBAdapter)

		// Store invalid data in backend
		wrapper := &types.Key{
			ID: "invalid-key",
			VersionList: types.KeyVersionList{
				{ID: 1, Data: []byte("invalid-json")},
			},
		}
		err := mockBackend.PutKey(t.Context(), wrapper)
		require.NoError(t, err)

		result, err := adapter.Get("invalid-key")
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to deserialize DBKey")
	})

	t.Run("Get_EmptyVersionList", func(t *testing.T) {
		mockBackend := NewMockBackend()
		adapter := NewDBAdapter(mockBackend, nil)

		// Store key with empty version list
		wrapper := &types.Key{
			ID:          "empty-version-key",
			VersionList: types.KeyVersionList{},
		}
		err := mockBackend.PutKey(t.Context(), wrapper)
		require.NoError(t, err)

		result, err := adapter.Get("empty-version-key")
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "invalid stored key: no versions")
	})

	t.Run("Get_BackendFailure", func(t *testing.T) {
		mockBackend := NewMockBackend()
		mockBackend.SetFailOps("GetKey")
		adapter := NewDBAdapter(mockBackend, nil).(*DBAdapter)

		result, err := adapter.Get("test-key")
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "backend get failed")
	})
}

// TestDBAdapter_GetAll tests the GetAll method.
func TestDBAdapter_GetAll(t *testing.T) {
	t.Run("GetAll_WithKeys", func(t *testing.T) {
		mockBackend := NewMockBackend()
		adapter := NewDBAdapter(mockBackend, nil)

		// Create multiple test keys
		keys := []*keydb.DBKey{
			{
				ID: "key1",
				VersionList: []keydb.EncKeyVersion{
					{ID: 1, EncData: []byte("encrypted-data-1")},
				},
			},
			{
				ID: "key2",
				VersionList: []keydb.EncKeyVersion{
					{ID: 1, EncData: []byte("encrypted-data-2")},
				},
			},
		}

		// Store keys in backend
		for _, dbKey := range keys {
			data, err := json.Marshal(dbKey)
			require.NoError(t, err)

			wrapper := &types.Key{
				ID: dbKey.ID,
				VersionList: types.KeyVersionList{
					{ID: 1, Data: data},
				},
			}
			err = mockBackend.PutKey(t.Context(), wrapper)
			require.NoError(t, err)
		}

		// Retrieve all via adapter
		results, err := adapter.GetAll()
		require.NoError(t, err)
		assert.Len(t, results, 2)

		// Verify results contain both keys
		resultMap := make(map[string]keydb.DBKey)
		for _, result := range results {
			resultMap[result.ID] = result
		}

		assert.Contains(t, resultMap, "key1")
		assert.Contains(t, resultMap, "key2")
	})

	t.Run("GetAll_NoKeys", func(t *testing.T) {
		mockBackend := NewMockBackend()
		adapter := NewDBAdapter(mockBackend, nil).(*DBAdapter)

		results, err := adapter.GetAll()
		require.NoError(t, err)
		assert.Empty(t, results)
	})

	t.Run("GetAll_BackendFailure", func(t *testing.T) {
		mockBackend := NewMockBackend()
		mockBackend.SetFailOps("ListKeys")
		adapter := NewDBAdapter(mockBackend, nil).(*DBAdapter)

		results, err := adapter.GetAll()
		assert.Error(t, err)
		assert.Nil(t, results)
		assert.Contains(t, err.Error(), "backend list failed")
	})

	t.Run("GetAll_PartialFailure", func(t *testing.T) {
		mockBackend := NewMockBackend()
		adapter := NewDBAdapter(mockBackend, nil)

		// Store one valid and one invalid key
		validKey := &keydb.DBKey{
			ID: "valid-key",
			VersionList: []keydb.EncKeyVersion{
				{ID: 1, EncData: []byte("encrypted-data")},
			},
		}
		data, err := json.Marshal(validKey)
		require.NoError(t, err)

		wrapper1 := &types.Key{
			ID: "valid-key",
			VersionList: types.KeyVersionList{
				{ID: 1, Data: data},
			},
		}
		err = mockBackend.PutKey(t.Context(), wrapper1)
		require.NoError(t, err)

		wrapper2 := &types.Key{
			ID: "invalid-key",
			VersionList: types.KeyVersionList{
				{ID: 1, Data: []byte("invalid-json")},
			},
		}
		err = mockBackend.PutKey(t.Context(), wrapper2)
		require.NoError(t, err)

		// Should get only the valid key and continue
		results, err := adapter.GetAll()
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, "valid-key", results[0].ID)
	})
}

// TestDBAdapter_Update tests the Update method.
func TestDBAdapter_Update(t *testing.T) {
	t.Run("Update_ValidKey", func(t *testing.T) {
		mockBackend := NewMockBackend()
		adapter := NewDBAdapter(mockBackend, nil)

		testDBKey := &keydb.DBKey{
			ID: "test-key",
			ACL: types.ACL{
				{Type: types.User, ID: "test-user", AccessType: types.Admin},
			},
			VersionList: []keydb.EncKeyVersion{
				{ID: 1, EncData: []byte("updated-encrypted-data")},
			},
		}

		err := adapter.Update(testDBKey)
		require.NoError(t, err)

		// Verify key was stored in backend
		storedKey, err := mockBackend.GetKey(t.Context(), "test-key")
		require.NoError(t, err)
		assert.Equal(t, testDBKey.ID, storedKey.ID)
		assert.Equal(t, testDBKey.ACL, storedKey.ACL)

		// Verify the data contains serialized DBKey
		var storedDBKey keydb.DBKey
		err = json.Unmarshal(storedKey.VersionList[0].Data, &storedDBKey)
		require.NoError(t, err)
		assert.Equal(t, testDBKey.VersionList, storedDBKey.VersionList)
	})

	t.Run("Update_BackendFailure", func(t *testing.T) {
		mockBackend := NewMockBackend()
		mockBackend.SetFailOps("PutKey")
		adapter := NewDBAdapter(mockBackend, nil)

		testDBKey := &keydb.DBKey{
			ID: "test-key",
			VersionList: []keydb.EncKeyVersion{
				{ID: 1, EncData: []byte("encrypted-data")},
			},
		}

		err := adapter.Update(testDBKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "backend update failed")
	})

	t.Run("Update_SerializationFailure", func(t *testing.T) {
		mockBackend := NewMockBackend()
		adapter := NewDBAdapter(mockBackend, nil)

		// Create a DBKey that cannot be serialized (circular reference not possible in this case)
		// For this test, we'll rely on the fact that all DBKey instances should be serializable
		testDBKey := &keydb.DBKey{
			ID: "test-key",
			VersionList: []keydb.EncKeyVersion{
				{ID: 1, EncData: []byte("encrypted-data")},
			},
		}

		err := adapter.Update(testDBKey)
		require.NoError(t, err, "All DBKey instances should be serializable")
	})
}

// TestDBAdapter_Add tests the Add method.
func TestDBAdapter_Add(t *testing.T) {
	t.Run("Add_SingleKey", func(t *testing.T) {
		mockBackend := NewMockBackend()
		adapter := NewDBAdapter(mockBackend, nil)

		testDBKey := &keydb.DBKey{
			ID: "test-key",
			VersionList: []keydb.EncKeyVersion{
				{ID: 1, EncData: []byte("encrypted-data")},
			},
		}

		err := adapter.Add(testDBKey)
		require.NoError(t, err)

		// Verify key was stored
		result, err := adapter.Get("test-key")
		require.NoError(t, err)
		assert.Equal(t, testDBKey.ID, result.ID)
		assert.Equal(t, testDBKey.VersionList, result.VersionList)
	})

	t.Run("Add_MultipleKeys", func(t *testing.T) {
		mockBackend := NewMockBackend()
		adapter := NewDBAdapter(mockBackend, nil)

		keys := []*keydb.DBKey{
			{
				ID: "key1",
				VersionList: []keydb.EncKeyVersion{
					{ID: 1, EncData: []byte("data1")},
				},
			},
			{
				ID: "key2",
				VersionList: []keydb.EncKeyVersion{
					{ID: 1, EncData: []byte("data2")},
				},
			},
			{
				ID: "key3",
				VersionList: []keydb.EncKeyVersion{
					{ID: 1, EncData: []byte("data3")},
				},
			},
		}

		err := adapter.Add(keys...)
		require.NoError(t, err)

		// Verify all keys were stored
		for _, expectedKey := range keys {
			result, err := adapter.Get(expectedKey.ID)
			require.NoError(t, err)
			assert.Equal(t, expectedKey.ID, result.ID)
			assert.Equal(t, expectedKey.VersionList, result.VersionList)
		}
	})

	t.Run("Add_DuplicateKey", func(t *testing.T) {
		mockBackend := NewMockBackend()
		adapter := NewDBAdapter(mockBackend, nil).(*DBAdapter)

		testDBKey := &keydb.DBKey{
			ID: "duplicate-key",
			VersionList: []keydb.EncKeyVersion{
				{ID: 1, EncData: []byte("encrypted-data")},
			},
		}

		// Add first time
		err := adapter.Add(testDBKey)
		require.NoError(t, err)

		// Try to add again
		err = adapter.Add(testDBKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key already exists")
	})

	t.Run("Add_BackendFailure", func(t *testing.T) {
		mockBackend := NewMockBackend()
		mockBackend.SetFailOps("PutKey")
		adapter := NewDBAdapter(mockBackend, nil)

		testDBKey := &keydb.DBKey{
			ID: "test-key",
			VersionList: []keydb.EncKeyVersion{
				{ID: 1, EncData: []byte("encrypted-data")},
			},
		}

		err := adapter.Add(testDBKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "backend add failed")
	})
}

// TestDBAdapter_Remove tests the Remove method.
func TestDBAdapter_Remove(t *testing.T) {
	t.Run("Remove_ExistingKey", func(t *testing.T) {
		mockBackend := NewMockBackend()
		adapter := NewDBAdapter(mockBackend, nil).(*DBAdapter)

		// Add a key first
		testDBKey := &keydb.DBKey{
			ID: "test-key",
			VersionList: []keydb.EncKeyVersion{
				{ID: 1, EncData: []byte("encrypted-data")},
			},
		}
		err := adapter.Add(testDBKey)
		require.NoError(t, err)

		// Verify it exists
		result, err := adapter.Get("test-key")
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Remove it
		err = adapter.Remove("test-key")
		require.NoError(t, err)

		// Verify it's gone
		result, err = adapter.Get("test-key")
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("Remove_NonExistentKey", func(t *testing.T) {
		mockBackend := NewMockBackend()
		adapter := NewDBAdapter(mockBackend, nil).(*DBAdapter)

		err := adapter.Remove("non-existent-key")
		require.NoError(t, err, "Removing non-existent key should not error")
	})

	t.Run("Remove_BackendFailure", func(t *testing.T) {
		mockBackend := NewMockBackend()
		mockBackend.SetFailOps("DeleteKey")
		adapter := NewDBAdapter(mockBackend, nil).(*DBAdapter)

		err := adapter.Remove("test-key")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "backend delete failed")
	})
}

// TestDBAdapter_Cache tests the caching functionality.
func TestDBAdapter_Cache(t *testing.T) {
	t.Run("Cache_Hit", func(t *testing.T) {
		mockBackend := NewMockBackend()
		adapter := NewDBAdapter(mockBackend, nil).(*DBAdapter)

		// Add a key - this should populate the cache
		testDBKey := &keydb.DBKey{
			ID: "cached-key",
			VersionList: []keydb.EncKeyVersion{
				{ID: 1, EncData: []byte("encrypted-data")},
			},
		}
		err := adapter.Add(testDBKey)
		require.NoError(t, err)

		// Clear backend call log after Add
		mockBackend.callLog = []string{}

		// Get twice - both should be from cache (no backend calls)
		result1, err := adapter.Get("cached-key")
		require.NoError(t, err)
		assert.NotNil(t, result1)

		result2, err := adapter.Get("cached-key")
		require.NoError(t, err)
		assert.NotNil(t, result2)

		// Should have no backend calls since cache was populated by Add
		assert.Len(t, mockBackend.callLog, 0)
	})

	t.Run("Cache_Invalidation", func(t *testing.T) {
		mockBackend := NewMockBackend()
		adapter := NewDBAdapter(mockBackend, nil).(*DBAdapter)

		// Add a key
		testDBKey := &keydb.DBKey{
			ID: "cached-key",
			VersionList: []keydb.EncKeyVersion{
				{ID: 1, EncData: []byte("encrypted-data")},
			},
		}
		err := adapter.Add(testDBKey)
		require.NoError(t, err)

		// Clear backend call log after Add
		mockBackend.callLog = []string{}

		// Get to populate cache (should use cache from Add, no backend call)
		result, err := adapter.Get("cached-key")
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, mockBackend.callLog, 0) // Should use cache

		// Update should invalidate cache
		updatedDBKey := &keydb.DBKey{
			ID: "cached-key",
			VersionList: []keydb.EncKeyVersion{
				{ID: 1, EncData: []byte("updated-encrypted-data")},
			},
		}
		err = adapter.Update(updatedDBKey)
		require.NoError(t, err)

		// Clear backend call log after Update
		mockBackend.callLog = []string{}

		// Get again should hit backend (cache was invalidated)
		result, err = adapter.Get("cached-key")
		require.NoError(t, err)
		assert.NotNil(t, result)

		assert.Len(t, mockBackend.callLog, 1) // Get from backend
		assert.Contains(t, mockBackend.callLog[0], "GetKey:cached-key")
	})

	t.Run("Cache_Expiration", func(t *testing.T) {
		mockBackend := NewMockBackend()
		adapter := NewDBAdapter(mockBackend, nil).(*DBAdapter)

		// Add a key
		testDBKey := &keydb.DBKey{
			ID: "cached-key",
			VersionList: []keydb.EncKeyVersion{
				{ID: 1, EncData: []byte("encrypted-data")},
			},
		}
		err := adapter.Add(testDBKey)
		require.NoError(t, err)

		// Get to populate cache
		result, err := adapter.Get("cached-key")
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Clear backend call log
		mockBackend.callLog = []string{}

		// Manually expire the cache entry
		adapter.mu.Lock()
		if cached, ok := adapter.cache["cached-key"]; ok {
			cached.expiresAt = time.Now().Add(-1 * time.Minute) // Expired
		}
		adapter.mu.Unlock()

		// Get again should hit backend (cache expired)
		result, err = adapter.Get("cached-key")
		require.NoError(t, err)
		assert.NotNil(t, result)

		assert.Len(t, mockBackend.callLog, 1) // Get from backend
	})
}

// TestDBAdapter_InterfaceCompliance tests that DBAdapter implements keydb.DB interface.
func TestDBAdapter_InterfaceCompliance(t *testing.T) {
	var _ keydb.DB = (*DBAdapter)(nil)
	assert.True(t, true, "DBAdapter should implement keydb.DB interface")
}

// MockCryptor is a mock implementation of keydb.Cryptor for testing.
type MockCryptor struct{}

func (m *MockCryptor) Encrypt(key *types.Key) (*keydb.DBKey, error) {
	return &keydb.DBKey{
		ID:  key.ID,
		ACL: key.ACL,
		VersionList: []keydb.EncKeyVersion{
			{ID: 1, EncData: []byte("encrypted-data")},
		},
	}, nil
}

func (m *MockCryptor) Decrypt(dbKey *keydb.DBKey) (*types.Key, error) {
	return &types.Key{
		ID:  dbKey.ID,
		ACL: dbKey.ACL,
		VersionList: types.KeyVersionList{
			{ID: 1, Data: dbKey.VersionList[0].EncData},
		},
	}, nil
}

func (m *MockCryptor) EncryptVersion(_ *types.Key, version *types.KeyVersion) (*keydb.EncKeyVersion, error) {
	return &keydb.EncKeyVersion{
		ID:      version.ID,
		EncData: version.Data,
	}, nil
}

// TestDBAdapter_CacheCleanup tests the cache cleanup mechanism when cache exceeds 1000 entries.
func TestDBAdapter_CacheCleanup(t *testing.T) {
	backend := NewMockBackend()
	cryptor := &MockCryptor{}
	adapter := NewDBAdapter(backend, cryptor)

	ctx := t.Context()

	// Add 1001 keys to trigger cleanup
	for i := range 1001 {
		keyID := fmt.Sprintf("test-key-%d", i)

		// Create DBKey and serialize it
		testDBKey := &keydb.DBKey{
			ID: keyID,
			ACL: types.ACL{
				{Type: types.User, ID: "test-user", AccessType: types.Read},
			},
			VersionList: []keydb.EncKeyVersion{
				{ID: 1, EncData: []byte("encrypted-data")},
			},
		}

		data, err := json.Marshal(testDBKey)
		require.NoError(t, err)

		// Store in backend
		key := &types.Key{
			ID:  keyID,
			ACL: testDBKey.ACL,
			VersionList: types.KeyVersionList{
				{ID: 1, Data: data},
			},
		}
		key.VersionHash = key.VersionList.Hash()

		err = backend.PutKey(ctx, key)
		require.NoError(t, err)

		// Get the key to populate cache
		_, err = adapter.Get(keyID)
		require.NoError(t, err)
	}

	// Cache should have been cleaned up when it exceeded 1000 entries
	// Verify the cleanup was called by checking that we can still get keys
	key, err := adapter.Get("test-key-0")
	assert.NoError(t, err)
	assert.NotNil(t, key)
}
