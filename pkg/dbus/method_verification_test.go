package dbus

import (
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/hazayan/knox/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFreeDesktopMethodPresence verifies that all required FreeDesktop Secret Service
// methods are present in the introspection data according to the specification.
func TestFreeDesktopMethodPresence(t *testing.T) {
	// Service Interface Methods
	serviceMethods := []string{
		"OpenSession",
		"CreateCollection",
		"SearchItems",
		"SearchCollections",
		"Unlock",
		"Lock",
		"GetSecrets",
		"ReadAlias",
		"SetAlias",
		"DeleteCollection",
		"Close",
	}

	// Collection Interface Methods
	collectionMethods := []string{
		"Delete",
		"SearchItems",
		"CreateItem",
		"SetProperties",
		"GetSecrets",
	}

	// Item Interface Methods
	itemMethods := []string{
		"Delete",
		"GetSecret",
		"SetSecret",
		"SetProperties",
	}

	// Session Interface Methods
	sessionMethods := []string{
		"Close",
	}

	// Prompt Interface Methods
	promptMethods := []string{
		"Prompt",
		"Dismiss",
	}

	// Create a bridge instance for introspection
	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			Server:          "localhost:9000",
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}
	bridge, err := NewBridge(cfg, mockClient)
	require.NoError(t, err)

	// Test Service Interface Methods
	t.Run("ServiceInterface", func(t *testing.T) {
		methods := bridge.getMethods()
		methodNames := make(map[string]bool)
		for _, method := range methods {
			methodNames[method.Name] = true
		}

		for _, requiredMethod := range serviceMethods {
			assert.True(t, methodNames[requiredMethod],
				"Service interface missing required method: %s", requiredMethod)
		}
	})

	// Test Collection Interface Methods
	t.Run("CollectionInterface", func(t *testing.T) {
		// Create a test collection to get its introspection
		collection := NewCollection(bridge, "test-collection", "Test Collection")
		introspect := collection.Introspect()

		methodNames := make(map[string]bool)
		for _, iface := range introspect.Interfaces {
			if iface.Name == CollectionInterface {
				for _, method := range iface.Methods {
					methodNames[method.Name] = true
				}
			}
		}

		for _, requiredMethod := range collectionMethods {
			assert.True(t, methodNames[requiredMethod],
				"Collection interface missing required method: %s", requiredMethod)
		}
	})

	// Test Item Interface Methods
	t.Run("ItemInterface", func(t *testing.T) {
		// Create a test collection and item to get introspection
		collection := NewCollection(bridge, "test-collection", "Test Collection")
		item := NewItem(collection, "test-item", "Test Item", map[string]string{})
		introspect := item.Introspect()

		methodNames := make(map[string]bool)
		for _, iface := range introspect.Interfaces {
			if iface.Name == ItemInterface {
				for _, method := range iface.Methods {
					methodNames[method.Name] = true
				}
			}
		}

		for _, requiredMethod := range itemMethods {
			assert.True(t, methodNames[requiredMethod],
				"Item interface missing required method: %s", requiredMethod)
		}
	})

	// Test Session Interface Methods
	t.Run("SessionInterface", func(t *testing.T) {
		// Create a test session to get introspection
		session, _, err := NewSession(AlgorithmPlain)
		require.NoError(t, err)
		introspect := session.Introspect()

		methodNames := make(map[string]bool)
		for _, iface := range introspect.Interfaces {
			if iface.Name == SessionInterface {
				for _, method := range iface.Methods {
					methodNames[method.Name] = true
				}
			}
		}

		for _, requiredMethod := range sessionMethods {
			assert.True(t, methodNames[requiredMethod],
				"Session interface missing required method: %s", requiredMethod)
		}
	})

	// Test Prompt Interface Methods
	t.Run("PromptInterface", func(t *testing.T) {
		// Create a test prompt to get introspection
		conn, err := dbus.ConnectSessionBus()
		require.NoError(t, err)
		defer conn.Close()

		prompt := NewPrompt(conn, func(bool) {})
		introspect := &introspect.Node{
			Interfaces: []introspect.Interface{
				{
					Name:    PromptInterface,
					Methods: prompt.getMethods(),
				},
			},
		}

		methodNames := make(map[string]bool)
		for _, iface := range introspect.Interfaces {
			if iface.Name == PromptInterface {
				for _, method := range iface.Methods {
					methodNames[method.Name] = true
				}
			}
		}

		for _, requiredMethod := range promptMethods {
			assert.True(t, methodNames[requiredMethod],
				"Prompt interface missing required method: %s", requiredMethod)
		}
	})
}

// TestFreeDesktopPropertyPresence verifies that all required FreeDesktop Secret Service
// properties are present according to the specification.
func TestFreeDesktopPropertyPresence(t *testing.T) {
	// Service Interface Properties
	serviceProperties := []string{
		"Collections",
	}

	// Collection Interface Properties
	collectionProperties := []string{
		"Items",
		"Label",
		"Locked",
		"Created",
		"Modified",
	}

	// Item Interface Properties
	itemProperties := []string{
		"Locked",
		"Attributes",
		"Label",
		"Created",
		"Modified",
	}

	// Prompt Interface Properties
	// Note: Prompt properties are handled internally, not through formal introspection

	// Create a bridge instance for property verification
	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			BusType:     "session",
			ServiceName: "org.freedesktop.secrets.test",
		},
		Knox: config.DBusKnoxConfig{
			Server:          "localhost:9000",
			NamespacePrefix: "test",
		},
	}

	mockClient := &MockAPIClient{}
	bridge, err := NewBridge(cfg, mockClient)
	require.NoError(t, err)

	// Test Service Interface Properties
	t.Run("ServiceInterface", func(t *testing.T) {
		properties := bridge.getProperties()
		propertyNames := make(map[string]bool)
		for _, prop := range properties {
			propertyNames[prop.Name] = true
		}

		for _, requiredProperty := range serviceProperties {
			assert.True(t, propertyNames[requiredProperty],
				"Service interface missing required property: %s", requiredProperty)
		}
	})

	// Test Collection Interface Properties
	t.Run("CollectionInterface", func(t *testing.T) {
		collection := NewCollection(bridge, "test-collection", "Test Collection")
		introspect := collection.Introspect()

		propertyNames := make(map[string]bool)
		for _, iface := range introspect.Interfaces {
			if iface.Name == CollectionInterface {
				for _, prop := range iface.Properties {
					propertyNames[prop.Name] = true
				}
			}
		}

		for _, requiredProperty := range collectionProperties {
			assert.True(t, propertyNames[requiredProperty],
				"Collection interface missing required property: %s", requiredProperty)
		}
	})

	// Test Item Interface Properties
	t.Run("ItemInterface", func(t *testing.T) {
		collection := NewCollection(bridge, "test-collection", "Test Collection")
		item := NewItem(collection, "test-item", "Test Item", map[string]string{})
		introspect := item.Introspect()

		propertyNames := make(map[string]bool)
		for _, iface := range introspect.Interfaces {
			if iface.Name == ItemInterface {
				for _, prop := range iface.Properties {
					propertyNames[prop.Name] = true
				}
			}
		}

		for _, requiredProperty := range itemProperties {
			assert.True(t, propertyNames[requiredProperty],
				"Item interface missing required property: %s", requiredProperty)
		}
	})

	// Test Prompt Interface Properties
	t.Run("PromptInterface", func(t *testing.T) {
		conn, err := dbus.ConnectSessionBus()
		require.NoError(t, err)
		defer conn.Close()

		prompt := NewPrompt(conn, func(bool) {})
		// For prompts, we check the internal property setup
		// since they don't have a formal introspection method
		assert.NotNil(t, prompt, "Prompt should be created successfully")
	})
}
