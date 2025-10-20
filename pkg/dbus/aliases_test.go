package dbus

import (
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/hazayan/knox/pkg/config"
	"github.com/stretchr/testify/assert"
)

func setupBridgeForAliasTests(t *testing.T) *Bridge {
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
	bridge.authManager.SetEnabled(false)
	return bridge
}

func TestStandardAliasManager_GetAllAliases(t *testing.T) {
	bridge := setupBridgeForAliasTests(t)

	// Manually initialize standard aliases (since we can't call Start() without D-Bus)
	bridge.aliasManager.standardAliases = map[string]string{
		"default": "default",
		"session": "session",
	}

	// Create test collection
	collection := NewCollection(bridge, "test-collection", "Test Collection")
	bridge.collections["test-collection"] = collection

	// Set a custom alias through public API
	err := bridge.SetAlias("custom", collection.Path())
	assert.Nil(t, err)

	// Get all aliases through the aliasManager (internal access for testing)
	allAliases := bridge.aliasManager.GetAllAliases()
	assert.NotNil(t, allAliases)
	assert.Contains(t, allAliases, "custom")
}

func TestStandardAliasManager_IsStandardAlias(t *testing.T) {
	bridge := setupBridgeForAliasTests(t)

	// Manually initialize standard aliases
	bridge.aliasManager.standardAliases = map[string]string{
		"default": "default",
		"session": "session",
	}

	// Test standard aliases
	assert.True(t, bridge.aliasManager.IsStandardAlias("default"))
	assert.True(t, bridge.aliasManager.IsStandardAlias("session"))

	// Test non-standard alias
	assert.False(t, bridge.aliasManager.IsStandardAlias("custom"))
	assert.False(t, bridge.aliasManager.IsStandardAlias("nonexistent"))
}

func TestStandardAliasManager_GetStandardAliases(t *testing.T) {
	bridge := setupBridgeForAliasTests(t)

	// Manually initialize standard aliases
	bridge.aliasManager.standardAliases = map[string]string{
		"default": "default",
		"session": "session",
	}

	standardAliases := bridge.aliasManager.GetStandardAliases()
	assert.NotNil(t, standardAliases)
	assert.Contains(t, standardAliases, "default")
	assert.Contains(t, standardAliases, "session")
	assert.NotContains(t, standardAliases, "custom")
}

func TestBridge_SetAlias_ErrorPaths(t *testing.T) {
	bridge := setupBridgeForAliasTests(t)

	// Test invalid alias names
	err := bridge.SetAlias("invalid/alias", "/org/freedesktop/secrets/collection/test")
	assert.NotNil(t, err)

	err = bridge.SetAlias("", "/org/freedesktop/secrets/collection/test")
	assert.NotNil(t, err)

	// Test with non-existent collection
	err = bridge.SetAlias("test", "/org/freedesktop/secrets/collection/nonexistent")
	assert.NotNil(t, err)
}

func TestValidateAliasName(t *testing.T) {
	tests := []struct {
		name    string
		alias   string
		isValid bool
	}{
		{"valid lowercase", "myalias", true},
		{"valid with numbers", "alias123", true},
		{"valid with underscore", "my_alias", true},
		{"valid with dash", "my-alias", true},
		{"empty string", "", false},
		{"with slash", "my/alias", false},
		{"with space", "my alias", false},
		{"with dot", "my.alias", false},
		{"starts with number", "123alias", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAliasName(tt.alias)
			if tt.isValid {
				assert.Nil(t, err)
			} else {
				assert.NotNil(t, err)
			}
		})
	}
}

func TestGetDefaultCollectionLabel(t *testing.T) {
	// Test default collection
	label := getDefaultCollectionLabel("default")
	assert.Equal(t, "Default", label)

	// Test session collection
	label = getDefaultCollectionLabel("session")
	assert.Equal(t, "Session", label)

	// Test unknown collection - it capitalizes the first letter
	label = getDefaultCollectionLabel("unknown")
	assert.Equal(t, "Unknown", label)
}

func TestSignalManager_EmitSignals(t *testing.T) {
	bridge := setupBridgeForAliasTests(t)

	// Create test collection
	collection := NewCollection(bridge, "test-collection", "Test Collection")
	bridge.collections["test-collection"] = collection

	// Create test item
	item := NewItem(collection, "test-item", "Test Item", map[string]string{"attr": "value"})

	// All these should not panic even without D-Bus connection
	t.Run("EmitCollectionAdded", func(_ *testing.T) {
		bridge.signalManager.EmitCollectionAdded(collection.Path())
	})

	t.Run("EmitCollectionDeleted", func(_ *testing.T) {
		bridge.signalManager.EmitCollectionDeleted(collection.Path())
	})

	t.Run("EmitCollectionChanged", func(_ *testing.T) {
		bridge.signalManager.EmitCollectionChanged(collection.Path())
	})

	t.Run("EmitItemChanged", func(_ *testing.T) {
		bridge.signalManager.EmitItemChanged(item.Path())
	})

	t.Run("EmitItemAdded", func(_ *testing.T) {
		bridge.signalManager.EmitItemAdded(collection.Path(), item.Path())
	})

	t.Run("EmitItemDeleted", func(_ *testing.T) {
		bridge.signalManager.EmitItemDeleted(collection.Path(), item.Path())
	})
}

func TestStandardAliasManager_emitAliasChanged(t *testing.T) {
	bridge := setupBridgeForAliasTests(t)

	collection := NewCollection(bridge, "test-collection", "Test Collection")
	bridge.collections["test-collection"] = collection

	// Should not panic even without D-Bus connection
	bridge.aliasManager.emitAliasChanged("test", collection.Path())
}

func TestIsValidAliasChar(t *testing.T) {
	tests := []struct {
		name    string
		char    rune
		isValid bool
	}{
		{"lowercase letter", 'a', true},
		{"uppercase letter", 'A', true},
		{"digit", '5', true},
		{"underscore", '_', true},
		{"dash", '-', true},
		{"slash", '/', false},
		{"space", ' ', false},
		{"dot", '.', false},
		{"at sign", '@', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidAliasChar(tt.char)
			assert.Equal(t, tt.isValid, result)
		})
	}
}

func TestBridge_SetAlias_Success(t *testing.T) {
	bridge := setupBridgeForAliasTests(t)

	// Create test collection
	collection := NewCollection(bridge, "test-collection", "Test Collection")
	bridge.collections["test-collection"] = collection

	// Set alias should succeed
	err := bridge.SetAlias("myalias", collection.Path())
	assert.Nil(t, err)

	// Read it back
	path, err := bridge.ReadAlias("myalias")
	assert.Nil(t, err)
	assert.Equal(t, collection.Path(), path)
}

func TestBridge_ReadAlias_Nonexistent(t *testing.T) {
	bridge := setupBridgeForAliasTests(t)

	// Reading non-existent alias should return root path
	path, err := bridge.ReadAlias("nonexistent")
	assert.Nil(t, err)
	assert.Equal(t, dbus.ObjectPath("/"), path)
}
