package dbus

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
	"github.com/hazayan/knox/client"
	"github.com/hazayan/knox/pkg/config"
	"github.com/hazayan/knox/pkg/observability/metrics"
)

// Bridge represents the D-Bus to Knox bridge.
type Bridge struct {
	conn          *dbus.Conn
	config        *config.DBusConfig
	knoxClient    client.APIClient
	sessionMgr    *SessionManager
	authManager   *AuthManager
	authHandler   *AuthPromptHandler
	aliasManager  *StandardAliasManager
	signalManager *SignalManager
	propertyMgr   *PropertyManager
	collections   map[string]*Collection
	aliases       map[string]dbus.ObjectPath
	mu            sync.RWMutex
	props         *prop.Properties
}

// NewBridge creates a new D-Bus to Knox bridge.
func NewBridge(cfg *config.DBusConfig, knoxClient client.APIClient) (*Bridge, error) {
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}
	if knoxClient == nil {
		return nil, errors.New("knoxClient cannot be nil")
	}
	if cfg.DBus.BusType == "" {
		return nil, errors.New("bus type cannot be empty")
	}
	if cfg.DBus.ServiceName == "" {
		return nil, errors.New("service name cannot be empty")
	}

	bridge := &Bridge{
		config:      cfg,
		knoxClient:  knoxClient,
		sessionMgr:  NewSessionManager(),
		authManager: NewAuthManager(),
		collections: make(map[string]*Collection),
		aliases:     make(map[string]dbus.ObjectPath),
	}
	bridge.authHandler = NewAuthPromptHandler(bridge.authManager)
	bridge.aliasManager = NewStandardAliasManager(bridge)
	bridge.signalManager = NewSignalManager(bridge)
	bridge.propertyMgr = NewPropertyManager(bridge)
	return bridge, nil
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
	b.props, _ = prop.Export(b.conn, ServicePath, map[string]map[string]*prop.Prop{
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

	// Create mapped collections from prefix mappings
	if err := b.createMappedCollections(); err != nil {
		return fmt.Errorf("failed to create mapped collections: %w", err)
	}

	// Initialize alias manager with standard aliases
	if err := b.aliasManager.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize alias manager: %w", err)
	}

	return nil
}

// Stop stops the D-Bus bridge.
func (b *Bridge) Stop() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// If connection was never established, nothing to clean up
	if b.conn == nil {
		return nil
	}

	// Close all sessions
	b.sessionMgr.CloseAll(b.conn)

	// Clear authentication data
	if b.authManager != nil {
		b.authManager.Lock()
	}

	// Unexport all collections
	for _, collection := range b.collections {
		collection.Unexport(b.conn)
	}

	// Unexport service
	if err := b.conn.Export(nil, ServicePath, ServiceInterface); err != nil {
		// Log error but don't return - this is best effort cleanup
		log.Printf("failed to unexport service: %v", err)
	}

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

// createMappedCollections creates collections based on prefix mappings configuration.
func (b *Bridge) createMappedCollections() error {
	if b.config.Knox.PrefixMappings == nil {
		return nil // No mappings configured
	}

	for knoxPrefix, dbusCollectionName := range b.config.Knox.PrefixMappings {
		if dbusCollectionName == "" {
			continue // Skip empty collection names
		}

		// Check if collection already exists
		b.mu.Lock()
		_, exists := b.collections[dbusCollectionName]
		b.mu.Unlock()
		if exists {
			continue // Collection already created
		}

		// Create collection with custom prefix mapping
		// Use knoxPrefix directly as the custom prefix
		collection := NewCollection(b, dbusCollectionName, dbusCollectionName, knoxPrefix)
		if err := collection.Export(b.conn); err != nil {
			return fmt.Errorf("failed to export mapped collection %s (prefix %s): %w",
				dbusCollectionName, knoxPrefix, err)
		}

		b.mu.Lock()
		b.collections[dbusCollectionName] = collection
		b.mu.Unlock()
	}

	// Update Collections property
	b.updateCollectionsProperty()

	return nil
}

// D-Bus methods

// OpenSession opens a new session.
func (b *Bridge) OpenSession(algorithm string, input dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RecordDBusOperation("OpenSession", "success", duration)
	}()
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
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RecordDBusOperation("CreateCollection", "success", duration)
	}()

	// Check if authentication is required
	if b.authHandler.IsAuthenticationRequired("CreateCollection") {
		prompt := b.createAuthenticationPrompt("CreateCollection", func(_ bool) {
			// Retry the operation after authentication
			// This would need to be handled differently in a real implementation
		})
		return "/", prompt.Path(), nil
	}

	b.authManager.UpdateActivity()
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
		if err := b.aliasManager.SetAlias(alias, collection.Path()); err != nil {
			// Log but don't fail - just ignore invalid alias
			return collection.Path(), "/", nil
		}
	}

	// Notify about collection creation
	if b.signalManager != nil {
		b.signalManager.EmitCollectionAdded(collection.Path())
	}

	// Check if authentication is required for collection creation
	// For now, we don't require authentication so return "/" (root path)
	// In a production implementation, this would check the auth manager state
	if b.authManager != nil && b.authManager.IsLocked() {
		// Authentication required - create a prompt
		prompt := NewPrompt(b.conn, func(_ bool) {
			// Callback executed when prompt completes - no action needed for auto-approval
		}, WithPromptMessage(fmt.Sprintf("Create new collection '%s'?", label)))
		if err := prompt.Export(); err != nil {
			return collection.Path(), "/", dbus.MakeFailedError(fmt.Errorf("failed to create prompt: %w", err))
		}
		return collection.Path(), prompt.Path(), nil
	}

	// No authentication required - return root path
	return collection.Path(), "/", nil
}

// SearchItems searches all collections for items matching the given attributes.
func (b *Bridge) SearchItems(attributes map[string]string) ([]dbus.ObjectPath, []dbus.ObjectPath, *dbus.Error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RecordDBusOperation("SearchItems", "success", duration)
	}()
	b.mu.RLock()
	defer b.mu.RUnlock()

	var unlocked []dbus.ObjectPath
	var locked []dbus.ObjectPath

	for _, collection := range b.collections {
		items, err := collection.SearchItems(attributes)
		if err != nil {
			continue
		}

		// Separate locked and unlocked items
		for _, itemPath := range items {
			// Find the item to check its locked state
			pathStr := string(itemPath)
			if hasPrefix(pathStr, CollectionPrefix) {
				remainder := pathStr[len(CollectionPrefix):]
				parts := splitPath(remainder)
				if len(parts) == 2 {
					collectionName := parts[0]
					if coll, ok := b.collections[collectionName]; ok {
						coll.mu.RLock()
						for _, item := range coll.items {
							if item.Path() == itemPath {
								if item.IsLocked() {
									locked = append(locked, itemPath)
								} else {
									unlocked = append(unlocked, itemPath)
								}
								break
							}
						}
						coll.mu.RUnlock()
					}
				}
			}
		}
	}

	return unlocked, locked, nil
}

// SearchCollections searches for collections matching the given attributes.
func (b *Bridge) SearchCollections(attributes map[string]string) ([]dbus.ObjectPath, *dbus.Error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RecordDBusOperation("SearchCollections", "success", duration)
	}()
	b.mu.RLock()
	defer b.mu.RUnlock()

	var matches []dbus.ObjectPath

	for _, collection := range b.collections {
		// Check if collection matches the attributes
		// Currently, we only support searching by label
		if label, ok := attributes["org.freedesktop.Secret.Collection.Label"]; ok {
			if collection.label == label {
				matches = append(matches, collection.Path())
			}
		} else {
			// If no specific attributes are provided, return all collections
			matches = append(matches, collection.Path())
		}
	}

	return matches, nil
}

// processLockUnlock is a helper function that handles the common logic for Lock and Unlock operations.
func (b *Bridge) processLockUnlock(objects []dbus.ObjectPath, operation string, action func(any)) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RecordDBusOperation(operation, "success", duration)
	}()

	processed := b.processObjects(objects, action)

	// Check if authentication is required for this operation
	// For now, we don't require authentication for Lock/Unlock operations
	// so we return "/" (root path) to indicate no prompt is needed
	// In a production implementation, this would check the auth manager state
	if b.authManager != nil && b.authManager.IsLocked() {
		// Authentication required - create a prompt
		prompt := NewPrompt(b.conn, func(_ bool) {
			// Callback executed when prompt completes
		}, WithPromptMessage(fmt.Sprintf("%s %d object(s)?", operation, len(objects))))
		if err := prompt.Export(); err != nil {
			return processed, "/", dbus.MakeFailedError(fmt.Errorf("failed to create prompt: %w", err))
		}
		return processed, prompt.Path(), nil
	}

	// No authentication required - return root path
	return processed, "/", nil
}

// Unlock unlocks objects.
func (b *Bridge) Unlock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	return b.processLockUnlock(objects, "Unlock", func(obj any) {
		switch v := obj.(type) {
		case *Collection:
			v.Unlock()
		case *Item:
			v.Unlock()
		}
	})
}

// Lock locks objects.
func (b *Bridge) Lock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	return b.processLockUnlock(objects, "Lock", func(obj any) {
		switch v := obj.(type) {
		case *Collection:
			v.Lock()
		case *Item:
			v.Lock()
		}
	})
}

// GetSecrets retrieves secrets for multiple items.
func (b *Bridge) GetSecrets(items []dbus.ObjectPath, sessionPath dbus.ObjectPath) (map[dbus.ObjectPath]Secret, *dbus.Error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RecordDBusOperation("GetSecrets", "success", duration)
	}()

	// Check if authentication is required
	if b.authHandler.IsAuthenticationRequired("GetSecrets") {
		// Return empty result when locked - clients should handle this appropriately
		return make(map[dbus.ObjectPath]Secret), nil
	}

	b.authManager.UpdateActivity()
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

		// Check if item is locked
		if item.IsLocked() {
			continue // Skip locked items
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
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RecordDBusOperation("ReadAlias", "success", duration)
	}()

	b.authManager.UpdateActivity()
	// Use alias manager to resolve aliases
	if path, err := b.aliasManager.ReadAlias(name); err == nil {
		return path, nil
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if path, ok := b.aliases[name]; ok {
		return path, nil
	}

	// Map standard aliases to collections
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
func (b *Bridge) SetAlias(name string, collectionPath dbus.ObjectPath) *dbus.Error {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RecordDBusOperation("SetAlias", "success", duration)
	}()

	// Check if authentication is required
	if b.authHandler.IsAuthenticationRequired("SetAlias") {
		return dbus.MakeFailedError(errors.New("authentication required to set alias"))
	}

	b.authManager.UpdateActivity()
	if err := validateCollectionName(name); err != nil {
		return dbus.MakeFailedError(fmt.Errorf("invalid alias name: %w", err))
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Find the collection by path
	var targetCollection *Collection
	for _, coll := range b.collections {
		if coll.Path() == collectionPath {
			targetCollection = coll
			break
		}
	}

	if targetCollection == nil {
		return dbus.MakeFailedError(errors.New("collection not found"))
	}

	// Update alias
	if err := b.aliasManager.SetAlias(name, collectionPath); err != nil {
		return dbus.MakeFailedError(fmt.Errorf("failed to set alias: %w", err))
	}

	return nil
}

// DeleteCollection deletes a collection.
func (b *Bridge) DeleteCollection(collectionPath dbus.ObjectPath) *dbus.Error {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RecordDBusOperation("DeleteCollection", "success", duration)
	}()

	// Check if authentication is required
	if b.authHandler.IsAuthenticationRequired("DeleteCollection") {
		return dbus.MakeFailedError(errors.New("authentication required to delete collection"))
	}

	b.authManager.UpdateActivity()

	b.mu.Lock()
	defer b.mu.Unlock()

	// Find the collection by path
	var targetCollection *Collection
	var collectionName string
	for name, coll := range b.collections {
		if coll.Path() == collectionPath {
			targetCollection = coll
			collectionName = name
			break
		}
	}

	if targetCollection == nil {
		return dbus.MakeFailedError(errors.New("collection not found"))
	}

	// Cannot delete default collection
	if collectionName == DefaultCollection {
		return dbus.MakeFailedError(errors.New("cannot delete default collection"))
	}

	// Delete the collection
	if err := targetCollection.DeleteAllItems(); err != nil {
		return dbus.MakeFailedError(fmt.Errorf("failed to delete collection items: %w", err))
	}

	// Unexport the collection
	targetCollection.Unexport(b.conn)

	// Remove from collections map
	delete(b.collections, collectionName)

	// Remove any aliases pointing to this collection
	// Collect aliases to remove first to avoid holding lock during RemoveAlias
	var aliasesToRemove []string
	for alias, path := range b.aliases {
		if path == collectionPath {
			aliasesToRemove = append(aliasesToRemove, alias)
		}
	}
	b.mu.Unlock() // Release lock before calling RemoveAlias to avoid deadlock

	// Remove aliases without holding the bridge lock
	for _, alias := range aliasesToRemove {
		_ = b.aliasManager.RemoveAlias(alias)
	}

	b.mu.Lock() // Reacquire lock for remaining operations

	// Notify about collection deletion
	b.signalManager.EmitCollectionDeleted(collectionPath)

	// Update collections property
	b.updateCollectionsProperty()

	return nil
}

// GetSession returns session information.
func (b *Bridge) GetSession(sessionPath dbus.ObjectPath) (EncryptionAlgorithm, []byte, *dbus.Error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RecordDBusOperation("GetSession", "success", duration)
	}()

	b.authManager.UpdateActivity()

	session, err := b.sessionMgr.GetSession(sessionPath)
	if err != nil {
		return "", nil, dbus.MakeFailedError(err)
	}

	var output []byte
	switch session.algorithm {
	case AlgorithmDHAES:
		output = encodeDBusPublicKey(session.dh.GetPublicKey())
	}

	return session.algorithm, output, nil
}

// ChangeLock changes the lock state of objects.
func (b *Bridge) ChangeLock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RecordDBusOperation("ChangeLock", "success", duration)
	}()

	// Check if authentication is required
	if b.authHandler.IsAuthenticationRequired("ChangeLock") {
		prompt := b.createAuthenticationPrompt("ChangeLock", func(_ bool) {
			// Callback for authentication result
		})
		return []dbus.ObjectPath{}, prompt.Path(), nil
	}

	b.authManager.UpdateActivity()

	var processed []dbus.ObjectPath
	var lockedObjects []dbus.ObjectPath

	// Process each object
	for _, objPath := range objects {
		obj, err := b.findObjectByPath(objPath)
		if err != nil {
			continue
		}

		switch v := obj.(type) {
		case *Collection:
			if v.IsLocked() {
				v.Unlock()
				processed = append(processed, objPath)
			} else {
				v.Lock()
				lockedObjects = append(lockedObjects, objPath)
			}
		case *Item:
			if v.IsLocked() {
				v.Unlock()
				processed = append(processed, objPath)
			} else {
				v.Lock()
				lockedObjects = append(lockedObjects, objPath)
			}
		}
	}

	// Create prompt for locked objects
	if len(lockedObjects) > 0 {
		prompt := NewPrompt(b.conn, func(approved bool) {
			if approved {
				// Unlock the objects
				for _, objPath := range lockedObjects {
					obj, err := b.findObjectByPath(objPath)
					if err != nil {
						continue
					}
					switch v := obj.(type) {
					case *Collection:
						v.Unlock()
					case *Item:
						v.Unlock()
					}
				}
			}
		}, WithPromptMessage(fmt.Sprintf("Unlock %d object(s)?", len(lockedObjects))))
		if err := prompt.Export(); err != nil {
			return processed, "/", dbus.MakeFailedError(fmt.Errorf("failed to create prompt: %w", err))
		}
		return processed, prompt.Path(), nil
	}

	return processed, "/", nil
}

// GetServiceInfo returns service information and capabilities.
func (b *Bridge) GetServiceInfo() (string, []string, *dbus.Error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RecordDBusOperation("GetServiceInfo", "success", duration)
	}()

	b.authManager.UpdateActivity()

	// Service vendor and version
	vendor := "Knox Secret Service Bridge"

	// Supported capabilities
	capabilities := []string{
		"service",    // Basic service functionality
		"collection", // Collection management
		"item",       // Item management
		"session",    // Session encryption
		"lock",       // Locking support
		"prompt",     // User prompts
	}

	return vendor, capabilities, nil
}

// GetProperty gets a service property.
func (b *Bridge) GetProperty(interfaceName, propertyName string) (dbus.Variant, *dbus.Error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RecordDBusOperation("GetProperty", "success", duration)
	}()

	b.authManager.UpdateActivity()

	if interfaceName != ServiceInterface {
		return dbus.Variant{}, dbus.MakeFailedError(errors.New("interface not found"))
	}

	switch propertyName {
	case "Collections":
		var paths []dbus.ObjectPath
		b.mu.RLock()
		for _, coll := range b.collections {
			paths = append(paths, coll.Path())
		}
		b.mu.RUnlock()
		return dbus.MakeVariant(paths), nil

	case "Locked":
		_, locked, _ := b.authManager.GetStatus()
		return dbus.MakeVariant(locked), nil

	default:
		return dbus.Variant{}, dbus.MakeFailedError(errors.New("property not found"))
	}
}

// SetProperty sets a service property.
func (b *Bridge) SetProperty(interfaceName, propertyName string, value dbus.Variant) *dbus.Error {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RecordDBusOperation("SetProperty", "success", duration)
	}()

	// Check if authentication is required
	if b.authHandler.IsAuthenticationRequired("SetProperty") {
		return dbus.MakeFailedError(errors.New("authentication required to set property"))
	}

	b.authManager.UpdateActivity()

	if interfaceName != ServiceInterface {
		return dbus.MakeFailedError(errors.New("interface not found"))
	}

	// Currently only support setting certain properties
	switch propertyName {
	case "AutoLockTimeout":
		if timeout, ok := value.Value().(uint32); ok {
			b.authManager.SetAutoLockTimeout(time.Duration(timeout) * time.Second)
			return nil
		}
		return dbus.MakeFailedError(errors.New("invalid timeout value"))

	default:
		return dbus.MakeFailedError(errors.New("property not writable"))
	}
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
		{
			Name: "DeleteCollection",
			Args: []introspect.Arg{
				{Name: "collection", Type: "o", Direction: "in"},
			},
		},
		{
			Name: "SearchCollections",
			Args: []introspect.Arg{
				{Name: "attributes", Type: "a{ss}", Direction: "in"},
				{Name: "collections", Type: "ao", Direction: "out"},
			},
		},
		{
			Name: "Close",
			Args: []introspect.Arg{},
		},
	}
}

func (b *Bridge) getProperties() []introspect.Property {
	return []introspect.Property{
		{Name: "Collections", Type: "ao", Access: "read"},
	}
}

func (b *Bridge) updateCollectionsProperty() {
	// Skip if props is nil (e.g., in tests)
	if b.props == nil {
		return
	}

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

// Close closes the service and releases all resources.
func (b *Bridge) Close() *dbus.Error {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RecordDBusOperation("Close", "success", duration)
	}()

	// Stop the bridge
	if err := b.Stop(); err != nil {
		return dbus.MakeFailedError(fmt.Errorf("failed to close service: %w", err))
	}

	return nil
}

// createAuthenticationPrompt creates a prompt for authentication.
func (b *Bridge) createAuthenticationPrompt(operation string, callback func(bool)) *Prompt {
	message := b.authHandler.GetAuthenticationPromptMessage(operation)
	prompt := NewPrompt(b.conn, func(approved bool) {
		if approved {
			// Show unlock prompt
			unlockPrompt := NewPrompt(b.conn, func(unlockApproved bool) {
				if unlockApproved {
					// Try to authenticate
					if success, err := b.authHandler.HandleUnlockPrompt(""); success && err == nil {
						callback(true)
						return
					}
				}
				callback(false)
			}, WithPromptMessage("Please unlock the secret service"))
			_ = unlockPrompt.Export()
		} else {
			callback(false)
		}
	}, WithPromptMessage(message))
	_ = prompt.Export()
	return prompt
}

// findObjectByPath finds an object by its D-Bus path.
func (b *Bridge) findObjectByPath(path dbus.ObjectPath) (any, error) {
	pathStr := string(path)

	// Check for collections
	if strings.HasPrefix(pathStr, CollectionPrefix) {
		b.mu.RLock()
		defer b.mu.RUnlock()

		for _, coll := range b.collections {
			if coll.Path() == path {
				return coll, nil
			}
		}

		// Check for items within collections
		for _, coll := range b.collections {
			coll.mu.RLock()
			for _, item := range coll.items {
				if item.Path() == path {
					coll.mu.RUnlock()
					return item, nil
				}
			}
			coll.mu.RUnlock()
		}
	}

	// Check for sessions
	if strings.HasPrefix(pathStr, SessionPrefix) {
		return b.sessionMgr.GetSession(path)
	}

	return nil, errors.New("object not found")
}

// GetServiceProperties returns additional service properties including lock status.
func (b *Bridge) GetServiceProperties() map[string]dbus.Variant {
	enabled, locked, attempts := b.authManager.GetStatus()
	return map[string]dbus.Variant{
		"Locked":                 dbus.MakeVariant(locked),
		"AuthenticationEnabled":  dbus.MakeVariant(enabled),
		"AuthenticationAttempts": dbus.MakeVariant(attempts),
	}
}

// PropertyManager manages service properties and signals.
type PropertyManager struct {
	bridge *Bridge
}

// NewPropertyManager creates a new property manager.
func NewPropertyManager(bridge *Bridge) *PropertyManager {
	return &PropertyManager{
		bridge: bridge,
	}
}

// EmitPropertiesChanged emits a properties changed signal.
func (pm *PropertyManager) EmitPropertiesChanged(interfaceName string, changedProperties map[string]dbus.Variant, invalidatedProperties []string) {
	if pm.bridge.conn == nil {
		return
	}

	err := pm.bridge.conn.Emit(
		ServicePath,
		"org.freedesktop.DBus.Properties.PropertiesChanged",
		interfaceName,
		changedProperties,
		invalidatedProperties,
	)
	_ = err // Signals are best effort - ignore errors
}

func (b *Bridge) processObjects(objects []dbus.ObjectPath, action func(any)) []dbus.ObjectPath {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var processed []dbus.ObjectPath

	for _, objPath := range objects {
		// Parse object path to determine type
		pathStr := string(objPath)
		if hasPrefix(pathStr, CollectionPrefix) {
			// Check if it's a collection or an item
			remainder := pathStr[len(CollectionPrefix):]
			parts := splitPath(remainder)

			if len(parts) == 1 {
				// It's a collection
				collectionName := parts[0]
				if collection, ok := b.collections[collectionName]; ok {
					action(collection)
					processed = append(processed, objPath)
				}
			} else if len(parts) == 2 {
				// It's an item - extract collection and item
				collectionName := parts[0]
				itemID := parts[1]
				if collection, ok := b.collections[collectionName]; ok {
					collection.mu.RLock()
					itemPath := makeItemPath(collectionName, itemID)
					if item, ok := collection.items[string(itemPath)]; ok {
						action(item)
						processed = append(processed, objPath)
					}
					collection.mu.RUnlock()
				}
			}
		}
	}

	return processed
}
