package dbus

import (
	"errors"
	"fmt"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
	"github.com/hazayan/knox/client"
	"github.com/hazayan/knox/pkg/config"
)

// Bridge represents the D-Bus to Knox bridge.
type Bridge struct {
	conn        *dbus.Conn
	config      *config.DBusConfig
	knoxClient  client.APIClient
	sessionMgr  *SessionManager
	collections map[string]*Collection
	mu          sync.RWMutex
	props       *prop.Properties
}

// NewBridge creates a new D-Bus to Knox bridge.
func NewBridge(cfg *config.DBusConfig, knoxClient client.APIClient) (*Bridge, error) {
	return &Bridge{
		config:      cfg,
		knoxClient:  knoxClient,
		sessionMgr:  NewSessionManager(),
		collections: make(map[string]*Collection),
	}, nil
}

// Start starts the D-Bus bridge.
func (b *Bridge) Start() error {
	var err error

	// Connect to D-Bus
	if b.config.DBus.BusType == "system" {
		b.conn, err = dbus.ConnectSystemBus()
	} else {
		b.conn, err = dbus.ConnectSessionBus()
	}
	if err != nil {
		return fmt.Errorf("failed to connect to D-Bus: %w", err)
	}

	// Request service name
	reply, err := b.conn.RequestName(b.config.DBus.ServiceName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return fmt.Errorf("failed to request name: %w", err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		return errors.New("name already taken")
	}

	// Create properties
	b.props = prop.New(b.conn, ServicePath, map[string]map[string]*prop.Prop{
		ServiceInterface: {
			"Collections": {
				Value:    []dbus.ObjectPath{},
				Writable: false,
				Emit:     prop.EmitTrue,
				Callback: nil,
			},
		},
	})

	// Export service
	if err := b.conn.Export(b, ServicePath, ServiceInterface); err != nil {
		return fmt.Errorf("failed to export service: %w", err)
	}

	// Export introspection
	node := introspect.Node{
		Name: ServicePath,
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			prop.IntrospectData,
			{
				Name:       ServiceInterface,
				Methods:    b.getMethods(),
				Properties: b.getProperties(),
			},
		},
	}
	if err := b.conn.Export(introspect.NewIntrospectable(&node), ServicePath, "org.freedesktop.DBus.Introspectable"); err != nil {
		return fmt.Errorf("failed to export introspection: %w", err)
	}

	// Create default collections
	if err := b.createDefaultCollections(); err != nil {
		return fmt.Errorf("failed to create default collections: %w", err)
	}

	return nil
}

// Stop stops the D-Bus bridge.
func (b *Bridge) Stop() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Close all sessions
	b.sessionMgr.CloseAll(b.conn)

	// Unexport all collections
	for _, collection := range b.collections {
		collection.Unexport(b.conn)
	}

	// Unexport service
	b.conn.Export(nil, ServicePath, ServiceInterface)

	// Close connection
	if err := b.conn.Close(); err != nil {
		return err
	}

	return nil
}

// createDefaultCollections creates the default and session collections.
func (b *Bridge) createDefaultCollections() error {
	// Create default collection
	defaultColl := NewCollection(b, DefaultCollection, "Default")
	if err := defaultColl.Export(b.conn); err != nil {
		return fmt.Errorf("failed to export default collection: %w", err)
	}

	b.mu.Lock()
	b.collections[DefaultCollection] = defaultColl
	b.mu.Unlock()

	// Create session collection (temporary, in-memory only)
	sessionColl := NewCollection(b, SessionCollection, "Session")
	if err := sessionColl.Export(b.conn); err != nil {
		return fmt.Errorf("failed to export session collection: %w", err)
	}

	b.mu.Lock()
	b.collections[SessionCollection] = sessionColl
	b.mu.Unlock()

	// Update Collections property
	b.updateCollectionsProperty()

	return nil
}

// D-Bus methods

// OpenSession opens a new session.
func (b *Bridge) OpenSession(algorithm string, input dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	// Parse algorithm
	var algo EncryptionAlgorithm
	switch algorithm {
	case "plain":
		algo = AlgorithmPlain
	case "dh-ietf1024-sha256-aes128-cbc-pkcs7":
		algo = AlgorithmDHAES
	default:
		return dbus.MakeVariant(""), "/", dbus.MakeFailedError(fmt.Errorf("unsupported algorithm: %s", algorithm))
	}

	// Create session
	session, output, err := b.sessionMgr.CreateSession(b.conn, algo)
	if err != nil {
		return dbus.MakeVariant(""), "/", dbus.MakeFailedError(err)
	}

	// For DH-AES, we need to process the client's public key from input
	if algo == AlgorithmDHAES {
		// Extract client's public key from input variant
		var clientPublicKey []byte
		if inputBytes, ok := input.Value().([]byte); ok {
			clientPublicKey = inputBytes
		} else {
			// Try to extract from variant
			clientPublicKey, err = decodeDBusPublicKey([]byte(input.String()))
			if err != nil {
				session.Close()
				return dbus.MakeVariant(""), "/", dbus.MakeFailedError(fmt.Errorf("invalid client public key: %w", err))
			}
		}

		// Complete the DH key exchange
		if err := session.CompleteKeyExchange(clientPublicKey); err != nil {
			session.Close()
			return dbus.MakeVariant(""), "/", dbus.MakeFailedError(fmt.Errorf("DH key exchange failed: %w", err))
		}
	}

	return dbus.MakeVariant(output), session.Path(), nil
}

// CreateCollection creates a new collection.
func (b *Bridge) CreateCollection(properties map[string]dbus.Variant, alias string) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	// Extract label with validation
	label := "Unnamed"
	if labelVar, ok := properties["org.freedesktop.Secret.Collection.Label"]; ok {
		if labelStr, ok := labelVar.Value().(string); ok {
			if err := validateLabel(labelStr); err != nil {
				return "/", "/", dbus.MakeFailedError(fmt.Errorf("invalid label: %w", err))
			}
			label = labelStr
		}
	}

	// Generate collection name
	name := sanitizeID(label)

	// Validate the sanitized name
	if err := validateCollectionName(name); err != nil {
		return "/", "/", dbus.MakeFailedError(fmt.Errorf("invalid collection name: %w", err))
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Check if collection exists
	if _, ok := b.collections[name]; ok {
		return "/", "/", dbus.MakeFailedError(errors.New("collection already exists"))
	}

	// Create collection
	collection := NewCollection(b, name, label)
	if err := collection.Export(b.conn); err != nil {
		return "/", "/", dbus.MakeFailedError(err)
	}

	b.collections[name] = collection

	// Update Collections property
	b.updateCollectionsProperty()

	// Handle alias if specified (with validation)
	if alias != "" {
		if err := validateCollectionName(alias); err != nil {
			// Log but don't fail - just ignore invalid alias
			return collection.Path(), "/", nil
		}
		// TODO: Implement alias support
	}

	// No prompt needed
	return collection.Path(), "/", nil
}

// SearchItems searches all collections for items matching the given attributes.
func (b *Bridge) SearchItems(attributes map[string]string) ([]dbus.ObjectPath, []dbus.ObjectPath, *dbus.Error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var unlocked []dbus.ObjectPath
	var locked []dbus.ObjectPath // Always empty in our implementation

	for _, collection := range b.collections {
		items, err := collection.SearchItems(attributes)
		if err != nil {
			continue
		}
		unlocked = append(unlocked, items...)
	}

	return unlocked, locked, nil
}

// Unlock unlocks objects (no-op in our implementation).
func (b *Bridge) Unlock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	// We don't support locking, so just return the objects as unlocked
	return objects, "/", nil
}

// Lock locks objects (no-op in our implementation).
func (b *Bridge) Lock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	// We don't support locking
	return []dbus.ObjectPath{}, "/", nil
}

// GetSecrets retrieves secrets for multiple items.
func (b *Bridge) GetSecrets(items []dbus.ObjectPath, sessionPath dbus.ObjectPath) (map[dbus.ObjectPath]Secret, *dbus.Error) {
	secrets := make(map[dbus.ObjectPath]Secret)

	// Get session
	session, err := b.sessionMgr.GetSession(sessionPath)
	if err != nil {
		return nil, dbus.MakeFailedError(err)
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	// Find each item and get its secret
	for _, itemPath := range items {
		// Parse item path to find collection and item
		pathStr := string(itemPath)
		if !hasPrefix(pathStr, CollectionPrefix) {
			continue
		}

		// Extract collection name and item ID
		remainder := pathStr[len(CollectionPrefix):]
		parts := splitPath(remainder)
		if len(parts) != 2 {
			continue
		}

		collectionName := parts[0]
		// itemID := parts[1]

		// Find collection
		collection, ok := b.collections[collectionName]
		if !ok {
			continue
		}

		// Find item in collection
		collection.mu.RLock()
		var item *Item
		for _, it := range collection.items {
			if it.Path() == itemPath {
				item = it
				break
			}
		}
		collection.mu.RUnlock()

		if item == nil {
			continue
		}

		// Get secret
		secret, err := item.GetSecret(session.Path())
		if err == nil {
			secrets[itemPath] = secret
		}
	}

	return secrets, nil
}

// ReadAlias resolves an alias to a collection.
func (b *Bridge) ReadAlias(name string) (dbus.ObjectPath, *dbus.Error) {
	b.mu.RLock()
	defer b.mu.Unlock()

	// Map aliases to collections
	switch name {
	case DefaultCollection:
		if coll, ok := b.collections[DefaultCollection]; ok {
			return coll.Path(), nil
		}
	case SessionCollection:
		if coll, ok := b.collections[SessionCollection]; ok {
			return coll.Path(), nil
		}
	}

	return "/", nil
}

// SetAlias sets an alias for a collection.
func (b *Bridge) SetAlias(name string, collection dbus.ObjectPath) *dbus.Error {
	// TODO: Implement alias support
	return nil
}

// Helper methods

func (b *Bridge) getMethods() []introspect.Method {
	return []introspect.Method{
		{
			Name: "OpenSession",
			Args: []introspect.Arg{
				{Name: "algorithm", Type: "s", Direction: "in"},
				{Name: "input", Type: "v", Direction: "in"},
				{Name: "output", Type: "v", Direction: "out"},
				{Name: "result", Type: "o", Direction: "out"},
			},
		},
		{
			Name: "CreateCollection",
			Args: []introspect.Arg{
				{Name: "properties", Type: "a{sv}", Direction: "in"},
				{Name: "alias", Type: "s", Direction: "in"},
				{Name: "collection", Type: "o", Direction: "out"},
				{Name: "prompt", Type: "o", Direction: "out"},
			},
		},
		{
			Name: "SearchItems",
			Args: []introspect.Arg{
				{Name: "attributes", Type: "a{ss}", Direction: "in"},
				{Name: "unlocked", Type: "ao", Direction: "out"},
				{Name: "locked", Type: "ao", Direction: "out"},
			},
		},
		{
			Name: "Unlock",
			Args: []introspect.Arg{
				{Name: "objects", Type: "ao", Direction: "in"},
				{Name: "unlocked", Type: "ao", Direction: "out"},
				{Name: "prompt", Type: "o", Direction: "out"},
			},
		},
		{
			Name: "Lock",
			Args: []introspect.Arg{
				{Name: "objects", Type: "ao", Direction: "in"},
				{Name: "locked", Type: "ao", Direction: "out"},
				{Name: "prompt", Type: "o", Direction: "out"},
			},
		},
		{
			Name: "GetSecrets",
			Args: []introspect.Arg{
				{Name: "items", Type: "ao", Direction: "in"},
				{Name: "session", Type: "o", Direction: "in"},
				{Name: "secrets", Type: "a{o(oayays)}", Direction: "out"},
			},
		},
		{
			Name: "ReadAlias",
			Args: []introspect.Arg{
				{Name: "name", Type: "s", Direction: "in"},
				{Name: "collection", Type: "o", Direction: "out"},
			},
		},
		{
			Name: "SetAlias",
			Args: []introspect.Arg{
				{Name: "name", Type: "s", Direction: "in"},
				{Name: "collection", Type: "o", Direction: "in"},
			},
		},
	}
}

func (b *Bridge) getProperties() []introspect.Property {
	return []introspect.Property{
		{Name: "Collections", Type: "ao", Access: "read"},
	}
}

func (b *Bridge) updateCollectionsProperty() {
	var paths []dbus.ObjectPath
	for _, collection := range b.collections {
		paths = append(paths, collection.Path())
	}
	b.props.SetMust(ServiceInterface, "Collections", paths)
}

// Helper functions

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func splitPath(path string) []string {
	var parts []string
	start := 0
	for i := range len(path) {
		if path[i] == '/' {
			if i > start {
				parts = append(parts, path[start:i])
			}
			start = i + 1
		}
	}
	if start < len(path) {
		parts = append(parts, path[start:])
	}
	return parts
}
