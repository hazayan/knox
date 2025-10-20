package dbus

import (
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/hazayan/knox/pkg/config"
	"github.com/hazayan/knox/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockAPIClient is a mock implementation of client.APIClient.
type MockAPIClient struct {
	mock.Mock
}

func (m *MockAPIClient) GetKey(keyID string) (*types.Key, error) {
	args := m.Called(keyID)
	return args.Get(0).(*types.Key), args.Error(1)
}

func (m *MockAPIClient) NetworkGetKey(keyID string) (*types.Key, error) {
	args := m.Called(keyID)
	return args.Get(0).(*types.Key), args.Error(1)
}

func (m *MockAPIClient) GetKeyWithStatus(keyID string, status types.VersionStatus) (*types.Key, error) {
	args := m.Called(keyID, status)
	return args.Get(0).(*types.Key), args.Error(1)
}

func (m *MockAPIClient) NetworkGetKeyWithStatus(keyID string, status types.VersionStatus) (*types.Key, error) {
	args := m.Called(keyID, status)
	return args.Get(0).(*types.Key), args.Error(1)
}

func (m *MockAPIClient) GetKeys(keys map[string]string) ([]string, error) {
	args := m.Called(keys)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockAPIClient) CreateKey(keyID string, data []byte, acl types.ACL) (uint64, error) {
	args := m.Called(keyID, data, acl)
	return args.Get(0).(uint64), args.Error(1)
}

func (m *MockAPIClient) GetACL(keyID string) (*types.ACL, error) {
	args := m.Called(keyID)
	return args.Get(0).(*types.ACL), args.Error(1)
}

func (m *MockAPIClient) AddVersion(keyID string, data []byte) (uint64, error) {
	args := m.Called(keyID, data)
	return args.Get(0).(uint64), args.Error(1)
}

func (m *MockAPIClient) UpdateVersion(keyID, versionID string, status types.VersionStatus) error {
	args := m.Called(keyID, versionID, status)
	return args.Error(0)
}

func (m *MockAPIClient) CacheGetKey(keyID string) (*types.Key, error) {
	args := m.Called(keyID)
	return args.Get(0).(*types.Key), args.Error(1)
}

func (m *MockAPIClient) CacheGetKeyWithStatus(keyID string, status types.VersionStatus) (*types.Key, error) {
	args := m.Called(keyID, status)
	return args.Get(0).(*types.Key), args.Error(1)
}

func (m *MockAPIClient) Update(keyID string, status types.VersionStatus, versionID uint64) error {
	args := m.Called(keyID, status, versionID)
	return args.Error(0)
}

func (m *MockAPIClient) DeleteKey(keyID string) error {
	args := m.Called(keyID)
	return args.Error(0)
}

func (m *MockAPIClient) PutAccess(keyID string, acl ...types.Access) error {
	args := m.Called(keyID, acl)
	return args.Error(0)
}

func (m *MockAPIClient) GetAccess(keyID string) (types.ACL, error) {
	args := m.Called(keyID)
	return args.Get(0).(types.ACL), args.Error(1)
}

func TestNewBridge(t *testing.T) {
	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}

	bridge, err := NewBridge(cfg, mockClient)
	assert.NoError(t, err)
	assert.NotNil(t, bridge)
	assert.Equal(t, mockClient, bridge.knoxClient)
	assert.Equal(t, cfg, bridge.config)
	assert.NotNil(t, bridge.sessionMgr)
	assert.NotNil(t, bridge.collections)
	assert.NotNil(t, bridge.aliases)
}

func TestBridge_CreateCollection(t *testing.T) {
	t.Skip("Skipping integration test that requires D-Bus connection")
	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}
	bridge, _ := NewBridge(cfg, mockClient)

	// Test creating a collection with valid properties
	properties := map[string]dbus.Variant{
		"org.freedesktop.Secret.Collection.Label": dbus.MakeVariant("Test Collection"),
	}

	collectionPath, promptPath, dbusErr := bridge.CreateCollection(properties, "")
	assert.Nil(t, dbusErr)
	assert.NotEqual(t, "/", collectionPath)
	assert.Equal(t, "/", promptPath)

	// Test creating a collection with invalid label
	properties = map[string]dbus.Variant{
		"org.freedesktop.Secret.Collection.Label": dbus.MakeVariant(""),
	}

	collectionPath, promptPath, dbusErr = bridge.CreateCollection(properties, "")
	assert.Nil(t, dbusErr)
	assert.NotEqual(t, "/", collectionPath)
	assert.Equal(t, "/", promptPath)

	// Test creating a collection with alias
	properties = map[string]dbus.Variant{
		"org.freedesktop.Secret.Collection.Label": dbus.MakeVariant("Aliased Collection"),
	}

	collectionPath, promptPath, dbusErr = bridge.CreateCollection(properties, "test-alias")
	assert.Nil(t, dbusErr)
	assert.NotEqual(t, "/", collectionPath)
	assert.Equal(t, "/", promptPath)
}

func TestBridge_ReadAlias(t *testing.T) {
	t.Skip("Skipping integration test that requires D-Bus connection")
	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}
	bridge, _ := NewBridge(cfg, mockClient)

	// Test reading default collection alias
	collectionPath, dbusErr := bridge.ReadAlias(DefaultCollection)
	assert.Nil(t, dbusErr)
	assert.Equal(t, "/", collectionPath) // No collections created yet

	// Test reading session collection alias
	collectionPath, dbusErr = bridge.ReadAlias(SessionCollection)
	assert.Nil(t, dbusErr)
	assert.Equal(t, "/", collectionPath) // No collections created yet

	// Test reading non-existent alias
	collectionPath, dbusErr = bridge.ReadAlias("nonexistent")
	assert.Nil(t, dbusErr)
	assert.Equal(t, "/", collectionPath)
}

func TestBridge_SetAlias(t *testing.T) {
	t.Skip("Skipping integration test that requires D-Bus connection")
	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}
	bridge, _ := NewBridge(cfg, mockClient)

	// Create a collection first
	properties := map[string]dbus.Variant{
		"org.freedesktop.Secret.Collection.Label": dbus.MakeVariant("Test Collection"),
	}
	collectionPath, _, _ := bridge.CreateCollection(properties, "")

	// Test setting a valid alias (SetAlias returns void)
	_ = bridge.SetAlias("test-alias", collectionPath)

	// Verify the alias was set
	readPath, dbusErr := bridge.ReadAlias("test-alias")
	assert.Nil(t, dbusErr)
	assert.Equal(t, collectionPath, readPath)

	// Test setting alias with invalid name (SetAlias returns void, should fail silently)
	_ = bridge.SetAlias("", collectionPath)

	// Test setting alias for non-existent collection (SetAlias returns void, should fail silently)
	_ = bridge.SetAlias("invalid", "/org/freedesktop/secrets/collection/nonexistent")
}

func TestBridge_DeleteCollection(t *testing.T) {
	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}
	bridge, _ := NewBridge(cfg, mockClient)

	// Disable authentication for this test
	bridge.authManager.SetEnabled(false)

	// Create test collections manually (bypassing D-Bus export)
	collection := NewCollection(bridge, "test-collection", "Test Collection")
	bridge.collections["test-collection"] = collection
	bridge.aliases["test-collection"] = collection.Path()

	// Set up mock for DeleteKey calls
	mockClient.On("DeleteKey", mock.Anything).Return(nil)

	// Delete the collection
	dbusErr := bridge.DeleteCollection(collection.Path())
	assert.Nil(t, dbusErr)

	// Verify collection was removed - ReadAlias should return root path for non-existent alias
	path, dbusErr := bridge.ReadAlias("test-collection")
	assert.Nil(t, dbusErr)
	assert.Equal(t, dbus.ObjectPath("/"), path) // Should return root path for non-existent alias

	// Verify collection was removed from collections map
	_, exists := bridge.collections["test-collection"]
	assert.False(t, exists)

	// Test deleting non-existent collection
	dbusErr = bridge.DeleteCollection("/org/freedesktop/secrets/collection/nonexistent")
	assert.NotNil(t, dbusErr)

	// Test deleting default collection (should fail)
	defaultColl := NewCollection(bridge, DefaultCollection, "Default")
	bridge.collections[DefaultCollection] = defaultColl
	dbusErr = bridge.DeleteCollection(defaultColl.Path())
	assert.NotNil(t, dbusErr)
}

func TestBridge_SearchItems(t *testing.T) {
	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}
	bridge, _ := NewBridge(cfg, mockClient)

	// Test searching with no collections
	attributes := map[string]string{
		"service": "test-service",
	}

	unlocked, locked, dbusErr := bridge.SearchItems(attributes)
	assert.Nil(t, dbusErr)
	assert.Empty(t, unlocked)
	assert.Empty(t, locked)
}

func TestBridge_OpenSession(t *testing.T) {
	t.Skip("Skipping integration test that requires D-Bus connection")
	// This test requires actual D-Bus connection and is tested in integration tests
}

func TestBridge_GetSecrets(t *testing.T) {
	t.Skip("Skipping integration test that requires D-Bus connection")
	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}
	bridge, _ := NewBridge(cfg, mockClient)

	// Open a session first
	_, sessionPath, _ := bridge.OpenSession("plain", dbus.MakeVariant(""))

	// Test getting secrets with no items
	secrets, dbusErr := bridge.GetSecrets([]dbus.ObjectPath{}, sessionPath)
	assert.Nil(t, dbusErr)
	assert.Empty(t, secrets)

	// Test getting secrets with invalid session
	secrets, dbusErr = bridge.GetSecrets([]dbus.ObjectPath{}, "/invalid/session")
	assert.NotNil(t, dbusErr)
	assert.Nil(t, secrets)
}

func TestBridge_Unlock(t *testing.T) {
	t.Skip("Skipping integration test that requires D-Bus connection")
	// This test requires actual D-Bus connection and is tested in integration tests
}

func TestBridge_Lock(t *testing.T) {
	t.Skip("Skipping integration test that requires D-Bus connection")
	// This test requires actual D-Bus connection and is tested in integration tests
}

func TestBridge_createDefaultCollections(t *testing.T) {
	t.Skip("Skipping integration test that requires D-Bus connection")
	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}
	bridge, _ := NewBridge(cfg, mockClient)

	// Test creating default collections
	err := bridge.createDefaultCollections()
	assert.NoError(t, err)

	// Verify default and session collections were created
	assert.Contains(t, bridge.collections, DefaultCollection)
	assert.Contains(t, bridge.collections, SessionCollection)

	// Verify collections have correct properties
	defaultColl := bridge.collections[DefaultCollection]
	assert.Equal(t, "Default", defaultColl.label)
	assert.Equal(t, "test:default:", defaultColl.prefix)

	sessionColl := bridge.collections[SessionCollection]
	assert.Equal(t, "Session", sessionColl.label)
	assert.Equal(t, "test:session:", sessionColl.prefix)
}

func TestBridge_Stop(t *testing.T) {
	t.Skip("Skipping integration test that requires D-Bus connection")
	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}
	bridge, _ := NewBridge(cfg, mockClient)

	// Create a mock connection
	// bridge.conn would be set during Start() in real usage

	// Add some collections
	bridge.collections["test"] = &Collection{
		name:   "test",
		path:   "/org/freedesktop/secrets/collection/test",
		bridge: bridge,
	}

	// Test stopping the bridge
	err := bridge.Stop()
	assert.NoError(t, err)
}

func TestServiceConstants(t *testing.T) {
	// Test service constants
	assert.Equal(t, "/org/freedesktop/secrets", string(ServicePath))
	assert.Equal(t, "org.freedesktop.Secret.Service", ServiceInterface)
	assert.Equal(t, "default", DefaultCollection)
	assert.Equal(t, "session", SessionCollection)
	assert.Equal(t, "/org/freedesktop/secrets/collection/", CollectionPrefix)
}

// TestHelperFunctions tests helper functions used in the service.
func TestHelperFunctions(t *testing.T) {
	// Test hasPrefix function
	assert.True(t, hasPrefix("/test/path", "/test"))
	assert.False(t, hasPrefix("/test/path", "/other"))

	// Test splitPath function
	parts := splitPath("/collection/item")
	assert.Equal(t, []string{"collection", "item"}, parts)

	parts = splitPath("collection/item/")
	assert.Equal(t, []string{"collection", "item"}, parts)
}

// TestProcessObjects tests the processObjects method.
func TestProcessObjects(t *testing.T) {
	t.Run("ProcessObjects_Collections", func(t *testing.T) {
		cfg := &config.DBusConfig{
			DBus: config.DBusConnectionConfig{
				BusType:     "session",
				ServiceName: "org.freedesktop.secrets.test",
			},
			Knox: config.DBusKnoxConfig{
				NamespacePrefix: "test",
			},
		}
		bridge, _ := NewBridge(cfg, &MockAPIClient{})

		// Create test collections
		collection1 := &Collection{name: "test1", items: make(map[string]*Item)}
		collection2 := &Collection{name: "test2", items: make(map[string]*Item)}
		bridge.collections["test1"] = collection1
		bridge.collections["test2"] = collection2

		var processedObjects []any
		action := func(obj any) {
			processedObjects = append(processedObjects, obj)
		}

		objects := []dbus.ObjectPath{
			"/org/freedesktop/secrets/collection/test1",
			"/org/freedesktop/secrets/collection/test2",
		}

		result := bridge.processObjects(objects, action)

		assert.Equal(t, objects, result)
		assert.Len(t, processedObjects, 2)
		assert.Contains(t, processedObjects, collection1)
		assert.Contains(t, processedObjects, collection2)
	})

	t.Run("ProcessObjects_Items", func(t *testing.T) {
		cfg := &config.DBusConfig{
			DBus: config.DBusConnectionConfig{
				BusType:     "session",
				ServiceName: "org.freedesktop.secrets.test",
			},
			Knox: config.DBusKnoxConfig{
				NamespacePrefix: "test",
			},
		}
		bridge, _ := NewBridge(cfg, &MockAPIClient{})

		// Create test collection with items
		collection := &Collection{name: "test", items: make(map[string]*Item)}
		item1 := &Item{label: "item1", path: "/org/freedesktop/secrets/collection/test/item1"}
		item2 := &Item{label: "item2", path: "/org/freedesktop/secrets/collection/test/item2"}
		collection.items["/org/freedesktop/secrets/collection/test/item1"] = item1
		collection.items["/org/freedesktop/secrets/collection/test/item2"] = item2
		bridge.collections["test"] = collection

		var processedObjects []any
		action := func(obj any) {
			processedObjects = append(processedObjects, obj)
		}

		objects := []dbus.ObjectPath{
			"/org/freedesktop/secrets/collection/test/item1",
			"/org/freedesktop/secrets/collection/test/item2",
		}

		result := bridge.processObjects(objects, action)

		assert.Equal(t, objects, result)
		assert.Len(t, processedObjects, 2)
		assert.Contains(t, processedObjects, item1)
		assert.Contains(t, processedObjects, item2)
	})

	t.Run("ProcessObjects_MixedTypes", func(t *testing.T) {
		cfg := &config.DBusConfig{
			DBus: config.DBusConnectionConfig{
				BusType:     "session",
				ServiceName: "org.freedesktop.secrets.test",
			},
			Knox: config.DBusKnoxConfig{
				NamespacePrefix: "test",
			},
		}
		bridge, _ := NewBridge(cfg, &MockAPIClient{})

		// Create test collection with items
		collection := &Collection{name: "test", items: make(map[string]*Item)}
		item1 := &Item{label: "item1", path: "/org/freedesktop/secrets/collection/test/item1"}
		collection.items["/org/freedesktop/secrets/collection/test/item1"] = item1
		bridge.collections["test"] = collection

		var processedObjects []any
		action := func(obj any) {
			processedObjects = append(processedObjects, obj)
		}

		objects := []dbus.ObjectPath{
			"/org/freedesktop/secrets/collection/test",       // collection
			"/org/freedesktop/secrets/collection/test/item1", // item
		}

		result := bridge.processObjects(objects, action)

		assert.Equal(t, objects, result)
		assert.Len(t, processedObjects, 2)
		assert.Contains(t, processedObjects, collection)
		assert.Contains(t, processedObjects, item1)
	})

	t.Run("ProcessObjects_UnknownPaths", func(t *testing.T) {
		cfg := &config.DBusConfig{
			DBus: config.DBusConnectionConfig{
				BusType:     "session",
				ServiceName: "org.freedesktop.secrets.test",
			},
			Knox: config.DBusKnoxConfig{
				NamespacePrefix: "test",
			},
		}
		bridge, _ := NewBridge(cfg, &MockAPIClient{})

		var processedObjects []any
		action := func(obj any) {
			processedObjects = append(processedObjects, obj)
		}

		objects := []dbus.ObjectPath{
			"/unknown/path",
			"/org/freedesktop/secrets/collection/nonexistent",
			"/org/freedesktop/secrets/collection/test/nonexistent",
		}

		result := bridge.processObjects(objects, action)

		assert.Empty(t, result)           // No objects should be processed for unknown paths
		assert.Empty(t, processedObjects) // No objects should be processed for unknown paths
	})

	t.Run("ProcessObjects_EmptyObjects", func(t *testing.T) {
		cfg := &config.DBusConfig{
			DBus: config.DBusConnectionConfig{
				BusType:     "session",
				ServiceName: "org.freedesktop.secrets.test",
			},
			Knox: config.DBusKnoxConfig{
				NamespacePrefix: "test",
			},
		}
		bridge, _ := NewBridge(cfg, &MockAPIClient{})

		var processedObjects []any
		action := func(obj any) {
			processedObjects = append(processedObjects, obj)
		}

		result := bridge.processObjects([]dbus.ObjectPath{}, action)

		assert.Empty(t, result)
		assert.Empty(t, processedObjects)
	})
}

func TestBridge_Integration(t *testing.T) {
	t.Skip("Skipping integration test that requires D-Bus connection")
	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}
	bridge, err := NewBridge(cfg, mockClient)
	assert.NoError(t, err)

	// Create default collections
	err = bridge.createDefaultCollections()
	assert.NoError(t, err)

	// Test alias operations
	properties := map[string]dbus.Variant{
		"org.freedesktop.Secret.Collection.Label": dbus.MakeVariant("Integration Test"),
	}
	collectionPath, _, _ := bridge.CreateCollection(properties, "integration-alias")

	// Set and read alias (SetAlias returns void)
	_ = bridge.SetAlias("integration-alias", collectionPath)

	readPath, dbusErr := bridge.ReadAlias("integration-alias")
	assert.Nil(t, dbusErr)
	assert.Equal(t, collectionPath, readPath)

	// Test session operations
	output, sessionPath, dbusErr := bridge.OpenSession("plain", dbus.MakeVariant(""))
	assert.Nil(t, dbusErr)
	assert.NotEmpty(t, output)
	assert.NotEqual(t, "/", sessionPath)

	// Test search with no matches
	attributes := map[string]string{"nonexistent": "value"}
	unlocked, locked, dbusErr := bridge.SearchItems(attributes)
	assert.Nil(t, dbusErr)
	assert.Empty(t, unlocked)
	assert.Empty(t, locked)
}

func TestBridge_ContextOperations(t *testing.T) {
	t.Skip("Skipping integration test that requires D-Bus connection")
	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}
	bridge, _ := NewBridge(cfg, mockClient)

	// Test operations with context
	_ = t.Context()

	// Create a collection with context
	properties := map[string]dbus.Variant{
		"org.freedesktop.Secret.Collection.Label": dbus.MakeVariant("Context Test"),
	}
	collectionPath, _, _ := bridge.CreateCollection(properties, "")

	// The bridge should handle operations without context issues
	assert.NotEqual(t, "/", collectionPath)

	// Test that bridge can be used in goroutine safely
	done := make(chan bool)
	go func() {
		_, _, _ = bridge.OpenSession("plain", dbus.MakeVariant(""))
		done <- true
	}()
	<-done
}

// TestItemMetadataPersistence verifies that item metadata (label and attributes)
// is properly persisted to Knox and can be retrieved.
func TestItemMetadataPersistenceService(t *testing.T) {
	// Create a test collection
	bridge := &Bridge{
		config: &config.DBusConfig{
			Knox: config.DBusKnoxConfig{
				NamespacePrefix: "test",
			},
		},
	}

	testCollection := &Collection{
		name:   "test-collection",
		path:   "/org/freedesktop/secrets/collection/test-collection",
		prefix: "test:test-collection:",
		bridge: bridge,
		items:  make(map[string]*Item),
	}

	// Test metadata that should be persisted
	metadata := &ItemMetadata{
		Label: "Test API Key",
		Attributes: map[string]string{
			"service":     "api-service",
			"environment": "production",
			"type":        "api-key",
			"owner":       "test-team",
		},
		Created:  time.Now().Unix(),
		Modified: time.Now().Unix(),
	}

	secretData := []byte("super-secret-api-key-12345")

	// Test combining metadata with secret data
	combinedData, err := CombineMetadataWithSecret(metadata, secretData)
	assert.NoError(t, err)
	assert.NotEmpty(t, combinedData)

	// Test extracting metadata from combined data
	extractedMetadata, extractedSecret, err := ExtractMetadataFromKeyData(combinedData)
	assert.NoError(t, err)
	assert.NotNil(t, extractedMetadata)
	assert.Equal(t, secretData, extractedSecret)

	// Verify metadata was preserved
	assert.Equal(t, "Test API Key", extractedMetadata.Label)
	assert.Equal(t, map[string]string{
		"service":     "api-service",
		"environment": "production",
		"type":        "api-key",
		"owner":       "test-team",
	}, extractedMetadata.Attributes)
	assert.Equal(t, metadata.Created, extractedMetadata.Created)
	assert.Equal(t, metadata.Modified, extractedMetadata.Modified)

	// Test creating item from Knox key with metadata
	testKey := &types.Key{
		ID: "test:test-collection:test-api-key",
		VersionList: types.KeyVersionList{
			{
				ID:           1,
				Data:         combinedData,
				Status:       types.Primary,
				CreationTime: time.Now().UnixNano(),
			},
		},
	}

	// Create item from Knox key (simulating loading from storage)
	loadedItem := createItemFromKnoxKey(testCollection, testKey)
	assert.NotNil(t, loadedItem)

	// Verify all metadata was correctly loaded
	assert.Equal(t, "Test API Key", loadedItem.GetLabel())
	assert.Equal(t, map[string]string{
		"service":     "api-service",
		"environment": "production",
		"type":        "api-key",
		"owner":       "test-team",
	}, loadedItem.GetAttributes())

	// Test with legacy format (no metadata)
	legacyKey := &types.Key{
		ID: "test:test-collection:legacy-item",
		VersionList: types.KeyVersionList{
			{
				ID:           1,
				Data:         []byte("legacy-secret-data"),
				Status:       types.Primary,
				CreationTime: time.Now().UnixNano(),
			},
		},
	}

	legacyItem := createItemFromKnoxKey(testCollection, legacyKey)
	assert.NotNil(t, legacyItem)
	assert.Equal(t, "legacy-item", legacyItem.GetLabel()) // Should use item ID as label
	assert.Empty(t, legacyItem.GetAttributes())
}

func TestBridge_ErrorConditions(t *testing.T) {
	// Test bridge creation with nil config
	bridge, err := NewBridge(nil, &MockAPIClient{})
	assert.Error(t, err)
	assert.Nil(t, bridge)

	// Test bridge creation with nil client
	bridge, err = NewBridge(&config.DBusConfig{}, nil)
	assert.Error(t, err)
	assert.Nil(t, bridge)

	// Test bridge creation with invalid config
	invalidCfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType: "invalid-bus-type",
		},
	}
	bridge, err = NewBridge(invalidCfg, &MockAPIClient{})
	assert.Error(t, err)
	assert.Nil(t, bridge)
}

// TestBridge_Metrics tests that metrics are recorded for various operations.
func TestBridge_Metrics(t *testing.T) {
	// Skip this test as it requires a real D-Bus connection
	t.Skip("Skipping Bridge_Metrics test due to D-Bus connection requirement")
}

func BenchmarkBridgeOperations(b *testing.B) {
	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			NamespacePrefix: "test",
		},
	}
	mockClient := &MockAPIClient{}
	bridge, _ := NewBridge(cfg, mockClient)

	b.ResetTimer()

	b.Run("OpenSession", func(b *testing.B) {
		for range b.N {
			_, _, _ = bridge.OpenSession("plain", dbus.MakeVariant(""))
		}
	})

	b.Run("SearchItems", func(b *testing.B) {
		for range b.N {
			_, _, _ = bridge.SearchItems(map[string]string{})
		}
	})

	b.Run("Unlock", func(b *testing.B) {
		for range b.N {
			_, _, _ = bridge.Unlock([]dbus.ObjectPath{})
		}
	})

	b.Run("Lock", func(b *testing.B) {
		for range b.N {
			_, _, _ = bridge.Lock([]dbus.ObjectPath{})
		}
	})
}

func TestBridge_SearchCollections(t *testing.T) {
	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}
	bridge, _ := NewBridge(cfg, mockClient)
	bridge.authManager.SetEnabled(false)

	// Create test collections
	collection1 := NewCollection(bridge, "test-1", "Test Collection 1")
	collection2 := NewCollection(bridge, "test-2", "Test Collection 2")
	collection3 := NewCollection(bridge, "test-3", "Another Collection")

	bridge.collections["test-1"] = collection1
	bridge.collections["test-2"] = collection2
	bridge.collections["test-3"] = collection3

	// Search with specific label
	matches, err := bridge.SearchCollections(map[string]string{
		"org.freedesktop.Secret.Collection.Label": "Test Collection 1",
	})
	assert.Nil(t, err)
	assert.Len(t, matches, 1)
	assert.Equal(t, collection1.Path(), matches[0])

	// Search with no attributes (should return all)
	matches, err = bridge.SearchCollections(map[string]string{})
	assert.Nil(t, err)
	assert.Len(t, matches, 3)
}

func TestBridge_GetSession(t *testing.T) {
	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}
	bridge, _ := NewBridge(cfg, mockClient)

	// Get a session that doesn't exist
	_, _, err := bridge.GetSession("/org/freedesktop/secrets/session/nonexistent")
	assert.NotNil(t, err)
}

func TestBridge_ChangeLock(t *testing.T) {
	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}
	bridge, _ := NewBridge(cfg, mockClient)
	bridge.authManager.SetEnabled(false)

	// Test ChangeLock with empty list - should succeed with empty results
	locked, prompt, err := bridge.ChangeLock([]dbus.ObjectPath{})
	assert.Nil(t, err)
	assert.Empty(t, locked)
	assert.Equal(t, dbus.ObjectPath("/"), prompt)
}

func TestBridge_GetServiceInfo(t *testing.T) {
	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}
	bridge, _ := NewBridge(cfg, mockClient)

	version, features, err := bridge.GetServiceInfo()
	assert.Nil(t, err)
	assert.NotEmpty(t, version)
	assert.NotNil(t, features)
}

func TestBridge_GetServiceProperties(t *testing.T) {
	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}
	bridge, _ := NewBridge(cfg, mockClient)

	props := bridge.GetServiceProperties()
	assert.NotNil(t, props)
	assert.Contains(t, props, "Locked")
	assert.Contains(t, props, "AuthenticationEnabled")
	assert.Contains(t, props, "AuthenticationAttempts")
}

func TestPropertyChangeNotifier(t *testing.T) {
	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}
	bridge, _ := NewBridge(cfg, mockClient)

	notifier := NewPropertyChangeNotifier(bridge)
	assert.NotNil(t, notifier)

	// These methods should not panic
	notifier.NotifyCollectionCreated("/org/freedesktop/secrets/collection/test")
	notifier.NotifyCollectionDeleted("/org/freedesktop/secrets/collection/test")
	notifier.NotifyCollectionChanged("/org/freedesktop/secrets/collection/test")
	notifier.NotifyItemCreated(
		"/org/freedesktop/secrets/collection/test",
		"/org/freedesktop/secrets/collection/test/item",
	)
	notifier.NotifyItemDeleted(
		"/org/freedesktop/secrets/collection/test",
		"/org/freedesktop/secrets/collection/test/item",
	)
	notifier.NotifyItemChanged(
		"/org/freedesktop/secrets/collection/test/item",
	)
}
