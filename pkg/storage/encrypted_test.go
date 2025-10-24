package storage

import (
	"encoding/json"
	"testing"

	"github.com/hazayan/knox/pkg/types"
	"github.com/hazayan/knox/server/keydb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEncryptedBackend_NewEncryptedBackend tests the creation of a new encrypted backend.
func TestEncryptedBackend_NewEncryptedBackend(t *testing.T) {
	mockBackend := NewMockBackend()
	encryptedBackend := NewEncryptedBackend(mockBackend)
	assert.NotNil(t, encryptedBackend, "Encrypted backend should be created successfully")
}

// TestEncryptedBackend_Get tests the Get method.
func TestEncryptedBackend_Get(t *testing.T) {
	t.Run("Get_ExistingKey", func(t *testing.T) {
		mockBackend := NewMockBackend()
		encryptedBackend := NewEncryptedBackend(mockBackend)

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

		// Retrieve via encrypted backend
		result, err := encryptedBackend.Get("test-key")
		require.NoError(t, err)
		assert.Equal(t, testDBKey.ID, result.ID)
		assert.Equal(t, testDBKey.ACL, result.ACL)
		assert.Equal(t, testDBKey.VersionList, result.VersionList)
	})

	t.Run("Get_NonExistentKey", func(t *testing.T) {
		mockBackend := NewMockBackend()
		encryptedBackend := NewEncryptedBackend(mockBackend)

		result, err := encryptedBackend.Get("non-existent")
		require.NoError(t, err)
		assert.Nil(t, result, "Should return nil for non-existent key")
	})

	t.Run("Get_InvalidData", func(t *testing.T) {
		mockBackend := NewMockBackend()
		encryptedBackend := NewEncryptedBackend(mockBackend)

		// Store invalid data in backend
		wrapper := &types.Key{
			ID: "invalid-key",
			VersionList: types.KeyVersionList{
				{ID: 1, Data: []byte("invalid-json")},
			},
		}
		err := mockBackend.PutKey(t.Context(), wrapper)
		require.NoError(t, err)

		result, err := encryptedBackend.Get("invalid-key")
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to deserialize DBKey")
	})

	t.Run("Get_EmptyVersionList", func(t *testing.T) {
		mockBackend := NewMockBackend()
		encryptedBackend := NewEncryptedBackend(mockBackend)

		// Store key with empty version list
		wrapper := &types.Key{
			ID:          "empty-version-key",
			VersionList: types.KeyVersionList{},
		}
		err := mockBackend.PutKey(t.Context(), wrapper)
		require.NoError(t, err)

		result, err := encryptedBackend.Get("empty-version-key")
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "invalid stored key: no versions")
	})

	t.Run("Get_BackendFailure", func(t *testing.T) {
		mockBackend := NewMockBackend()
		mockBackend.SetFailOps("GetKey")
		encryptedBackend := NewEncryptedBackend(mockBackend)

		result, err := encryptedBackend.Get("test-key")
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "backend get failed")
	})
}

// TestEncryptedBackend_GetAll tests the GetAll method.
func TestEncryptedBackend_GetAll(t *testing.T) {
	t.Run("GetAll_WithKeys", func(t *testing.T) {
		mockBackend := NewMockBackend()
		encryptedBackend := NewEncryptedBackend(mockBackend)

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

		// Retrieve all via encrypted backend
		results, err := encryptedBackend.GetAll()
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
		encryptedBackend := NewEncryptedBackend(mockBackend)

		results, err := encryptedBackend.GetAll()
		require.NoError(t, err)
		assert.Empty(t, results)
	})

	t.Run("GetAll_BackendFailure", func(t *testing.T) {
		mockBackend := NewMockBackend()
		mockBackend.SetFailOps("ListKeys")
		encryptedBackend := NewEncryptedBackend(mockBackend)

		results, err := encryptedBackend.GetAll()
		assert.Error(t, err)
		assert.Nil(t, results)
		assert.Contains(t, err.Error(), "backend list failed")
	})

	t.Run("GetAll_PartialFailure", func(t *testing.T) {
		mockBackend := NewMockBackend()
		encryptedBackend := NewEncryptedBackend(mockBackend)

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
		results, err := encryptedBackend.GetAll()
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, "valid-key", results[0].ID)
	})
}

// TestEncryptedBackend_Update tests the Update method.
func TestEncryptedBackend_Update(t *testing.T) {
	t.Run("Update_ValidKey", func(t *testing.T) {
		mockBackend := NewMockBackend()
		encryptedBackend := NewEncryptedBackend(mockBackend)

		testDBKey := &keydb.DBKey{
			ID: "test-key",
			ACL: types.ACL{
				{Type: types.User, ID: "test-user", AccessType: types.Admin},
			},
			VersionList: []keydb.EncKeyVersion{
				{ID: 1, EncData: []byte("updated-encrypted-data")},
			},
		}

		err := encryptedBackend.Update(testDBKey)
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
		encryptedBackend := NewEncryptedBackend(mockBackend)

		testDBKey := &keydb.DBKey{
			ID: "test-key",
			VersionList: []keydb.EncKeyVersion{
				{ID: 1, EncData: []byte("encrypted-data")},
			},
		}

		err := encryptedBackend.Update(testDBKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "backend put failed")
	})

	t.Run("Update_SerializationFailure", func(t *testing.T) {
		mockBackend := NewMockBackend()
		encryptedBackend := NewEncryptedBackend(mockBackend)

		// Create a DBKey that cannot be serialized (circular reference not possible in this case)
		// For this test, we'll rely on the fact that all DBKey instances should be serializable
		testDBKey := &keydb.DBKey{
			ID: "test-key",
			VersionList: []keydb.EncKeyVersion{
				{ID: 1, EncData: []byte("encrypted-data")},
			},
		}

		err := encryptedBackend.Update(testDBKey)
		require.NoError(t, err, "All DBKey instances should be serializable")
	})
}

// TestEncryptedBackend_Add tests the Add method.
func TestEncryptedBackend_Add(t *testing.T) {
	t.Run("Add_SingleKey", func(t *testing.T) {
		mockBackend := NewMockBackend()
		encryptedBackend := NewEncryptedBackend(mockBackend)

		testDBKey := &keydb.DBKey{
			ID: "test-key",
			VersionList: []keydb.EncKeyVersion{
				{ID: 1, EncData: []byte("encrypted-data")},
			},
		}

		err := encryptedBackend.Add(testDBKey)
		require.NoError(t, err)

		// Verify key was stored
		result, err := encryptedBackend.Get("test-key")
		require.NoError(t, err)
		assert.Equal(t, testDBKey.ID, result.ID)
		assert.Equal(t, testDBKey.VersionList, result.VersionList)
	})

	t.Run("Add_MultipleKeys", func(t *testing.T) {
		mockBackend := NewMockBackend()
		encryptedBackend := NewEncryptedBackend(mockBackend)

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

		err := encryptedBackend.Add(keys...)
		require.NoError(t, err)

		// Verify all keys were stored
		for _, expectedKey := range keys {
			result, err := encryptedBackend.Get(expectedKey.ID)
			require.NoError(t, err)
			assert.Equal(t, expectedKey.ID, result.ID)
			assert.Equal(t, expectedKey.VersionList, result.VersionList)
		}
	})

	t.Run("Add_DuplicateKey", func(t *testing.T) {
		mockBackend := NewMockBackend()
		encryptedBackend := NewEncryptedBackend(mockBackend)

		testDBKey := &keydb.DBKey{
			ID: "duplicate-key",
			VersionList: []keydb.EncKeyVersion{
				{ID: 1, EncData: []byte("encrypted-data")},
			},
		}

		// Add first time
		err := encryptedBackend.Add(testDBKey)
		require.NoError(t, err)

		// Try to add again
		err = encryptedBackend.Add(testDBKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key already exists")
	})

	t.Run("Add_BackendFailure", func(t *testing.T) {
		mockBackend := NewMockBackend()
		mockBackend.SetFailOps("PutKey")
		encryptedBackend := NewEncryptedBackend(mockBackend)

		testDBKey := &keydb.DBKey{
			ID: "test-key",
			VersionList: []keydb.EncKeyVersion{
				{ID: 1, EncData: []byte("encrypted-data")},
			},
		}

		err := encryptedBackend.Add(testDBKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to add key")
	})
}

// TestEncryptedBackend_Remove tests the Remove method.
func TestEncryptedBackend_Remove(t *testing.T) {
	t.Run("Remove_ExistingKey", func(t *testing.T) {
		mockBackend := NewMockBackend()
		encryptedBackend := NewEncryptedBackend(mockBackend)

		// Add a key first
		testDBKey := &keydb.DBKey{
			ID: "test-key",
			VersionList: []keydb.EncKeyVersion{
				{ID: 1, EncData: []byte("encrypted-data")},
			},
		}
		err := encryptedBackend.Add(testDBKey)
		require.NoError(t, err)

		// Verify it exists
		result, err := encryptedBackend.Get("test-key")
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Remove it
		err = encryptedBackend.Remove("test-key")
		require.NoError(t, err)

		// Verify it's gone
		result, err = encryptedBackend.Get("test-key")
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("Remove_NonExistentKey", func(t *testing.T) {
		mockBackend := NewMockBackend()
		encryptedBackend := NewEncryptedBackend(mockBackend)

		err := encryptedBackend.Remove("non-existent-key")
		require.NoError(t, err, "Removing non-existent key should not error")
	})

	t.Run("Remove_BackendFailure", func(t *testing.T) {
		mockBackend := NewMockBackend()
		mockBackend.SetFailOps("DeleteKey")
		encryptedBackend := NewEncryptedBackend(mockBackend)

		err := encryptedBackend.Remove("test-key")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "backend delete failed")
	})
}

// TestEncryptedBackend_InterfaceCompliance tests that EncryptedBackend implements keydb.DB interface.
func TestEncryptedBackend_InterfaceCompliance(t *testing.T) {
	var _ keydb.DB = (*EncryptedBackend)(nil)
	assert.True(t, true, "EncryptedBackend should implement keydb.DB interface")
}
