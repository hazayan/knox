// Package dbus implements the FreeDesktop Secret Service API.
// Spec: https://specifications.freedesktop.org/secret-service-spec/latest/
package dbus

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

// StandardAliasManager manages standard aliases according to the FreeDesktop specification.
type StandardAliasManager struct {
	mu              sync.RWMutex
	aliases         map[string]dbus.ObjectPath
	standardAliases map[string]string // alias -> collection name mapping
	bridge          *Bridge
}

// NewStandardAliasManager creates a new standard alias manager.
func NewStandardAliasManager(bridge *Bridge) *StandardAliasManager {
	am := &StandardAliasManager{
		aliases:         make(map[string]dbus.ObjectPath),
		standardAliases: make(map[string]string),
		bridge:          bridge,
	}

	return am
}

// Initialize sets up standard aliases and exports collections after bridge start.
func (am *StandardAliasManager) Initialize() error {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Standard aliases from the FreeDesktop Secret Service specification
	standardAliases := map[string]string{
		"default": DefaultCollection, // Default collection for general secrets
		"session": SessionCollection, // Session-specific secrets
		"login":   "login",           // Login credentials (passwords, etc.)
		"wallet":  "wallet",          // General wallet storage
	}

	am.standardAliases = standardAliases

	// Create and export default collections
	for alias, collectionName := range standardAliases {
		// Check if collection exists
		am.bridge.mu.RLock()
		_, exists := am.bridge.collections[collectionName]
		am.bridge.mu.RUnlock()

		if !exists {
			// Create and export the collection
			collection := NewCollection(am.bridge, collectionName, getDefaultCollectionLabel(collectionName))
			if err := collection.Export(am.bridge.conn); err != nil {
				return fmt.Errorf("failed to export collection %s: %w", collectionName, err)
			}
			am.bridge.mu.Lock()
			am.bridge.collections[collectionName] = collection
			am.bridge.mu.Unlock()
		}

		// Set the alias
		am.bridge.mu.RLock()
		if collection, ok := am.bridge.collections[collectionName]; ok {
			am.aliases[alias] = collection.Path()
		}
		am.bridge.mu.RUnlock()
	}

	return nil
}

// ReadAlias resolves an alias to a collection path.
func (am *StandardAliasManager) ReadAlias(name string) (dbus.ObjectPath, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	// Check standard aliases first
	if path, ok := am.aliases[name]; ok {
		return path, nil
	}

	// Check custom aliases
	am.bridge.mu.RLock()
	defer am.bridge.mu.RUnlock()
	if path, ok := am.bridge.aliases[name]; ok {
		return path, nil
	}

	return "/", errors.New("alias not found")
}

// SetAlias sets an alias to point to a collection.
func (am *StandardAliasManager) SetAlias(name string, collectionPath dbus.ObjectPath) error {
	if err := validateAliasName(name); err != nil {
		return fmt.Errorf("invalid alias name: %w", err)
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	// Check if this is a standard alias
	if _, isStandard := am.standardAliases[name]; isStandard {
		// For standard aliases, update our internal mapping
		am.aliases[name] = collectionPath
	} else {
		// For custom aliases, update the bridge's alias map
		// Note: Bridge lock is already held by the caller (Bridge.SetAlias)
		am.bridge.aliases[name] = collectionPath
	}

	// Emit alias changed signal
	am.emitAliasChanged(name, collectionPath)

	return nil
}

// RemoveAlias removes an alias.
func (am *StandardAliasManager) RemoveAlias(name string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Check if this is a standard alias
	if _, isStandard := am.standardAliases[name]; isStandard {
		// For standard aliases, reset to default collection
		if collectionName, ok := am.standardAliases[name]; ok {
			am.bridge.mu.RLock()
			if collection, ok := am.bridge.collections[collectionName]; ok {
				am.aliases[name] = collection.Path()
			}
			am.bridge.mu.RUnlock()
		}
	} else {
		// For custom aliases, remove from bridge
		am.bridge.mu.Lock()
		delete(am.bridge.aliases, name)
		am.bridge.mu.Unlock()
	}

	// Emit alias changed signal (with empty path to indicate removal for custom aliases)
	if _, isStandard := am.standardAliases[name]; !isStandard {
		am.emitAliasChanged(name, "/")
	}

	return nil
}

// GetAllAliases returns all aliases and their target paths.
func (am *StandardAliasManager) GetAllAliases() map[string]dbus.ObjectPath {
	am.mu.RLock()
	defer am.mu.RUnlock()

	allAliases := make(map[string]dbus.ObjectPath)

	// Add standard aliases
	for alias, path := range am.aliases {
		allAliases[alias] = path
	}

	// Add custom aliases
	am.bridge.mu.RLock()
	for alias, path := range am.bridge.aliases {
		allAliases[alias] = path
	}
	am.bridge.mu.RUnlock()

	return allAliases
}

// IsStandardAlias checks if an alias name is a standard alias.
func (am *StandardAliasManager) IsStandardAlias(name string) bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	_, exists := am.standardAliases[name]
	return exists
}

// GetStandardAliases returns the list of standard alias names.
func (am *StandardAliasManager) GetStandardAliases() []string {
	am.mu.RLock()
	defer am.mu.RUnlock()

	aliases := make([]string, 0, len(am.standardAliases))
	for alias := range am.standardAliases {
		aliases = append(aliases, alias)
	}
	return aliases
}

// emitAliasChanged emits a D-Bus signal when an alias changes.
func (am *StandardAliasManager) emitAliasChanged(alias string, collectionPath dbus.ObjectPath) {
	if am.bridge.conn == nil {
		return
	}

	// Emit the signal on the service interface
	err := am.bridge.conn.Emit(
		ServicePath,
		"org.freedesktop.Secret.Service.AliasChanged",
		alias,
		collectionPath,
	)
	if err != nil {
		// Log but don't fail - signals are best effort
		log.Printf("failed to emit AliasChanged signal: %v", err)
	}
}

// SignalManager manages D-Bus property change signals.
type SignalManager struct {
	bridge *Bridge
}

// NewSignalManager creates a new signal manager.
func NewSignalManager(bridge *Bridge) *SignalManager {
	return &SignalManager{
		bridge: bridge,
	}
}

// EmitCollectionAdded emits a signal when a collection is added.
func (sm *SignalManager) EmitCollectionAdded(collectionPath dbus.ObjectPath) {
	if sm.bridge.conn == nil {
		return
	}

	err := sm.bridge.conn.Emit(
		ServicePath,
		"org.freedesktop.Secret.Service.CollectionCreated",
		collectionPath,
	)
	if err != nil {
		// Log but don't fail
		log.Printf("failed to emit CollectionCreated signal: %v", err)
	}
}

// EmitCollectionDeleted emits a signal when a collection is deleted.
func (sm *SignalManager) EmitCollectionDeleted(collectionPath dbus.ObjectPath) {
	if sm.bridge.conn == nil {
		return
	}

	err := sm.bridge.conn.Emit(
		ServicePath,
		"org.freedesktop.Secret.Service.CollectionDeleted",
		collectionPath,
	)
	if err != nil {
		// Log but don't fail
		log.Printf("failed to emit CollectionDeleted signal: %v", err)
	}
}

// EmitCollectionChanged emits a signal when a collection changes.
func (sm *SignalManager) EmitCollectionChanged(collectionPath dbus.ObjectPath) {
	if sm.bridge.conn == nil {
		return
	}

	err := sm.bridge.conn.Emit(
		collectionPath,
		"org.freedesktop.DBus.Properties.PropertiesChanged",
		CollectionInterface,
		map[string]dbus.Variant{
			"Modified": dbus.MakeVariant(uint64(time.Now().Unix())),
		},
		[]string{},
	)
	if err != nil {
		// Log but don't fail
		log.Printf("failed to emit CollectionChanged signal: %v", err)
	}
}

// EmitItemChanged emits a signal when an item changes.
func (sm *SignalManager) EmitItemChanged(itemPath dbus.ObjectPath) {
	if sm.bridge.conn == nil {
		return
	}

	err := sm.bridge.conn.Emit(
		itemPath,
		"org.freedesktop.DBus.Properties.PropertiesChanged",
		ItemInterface,
		map[string]dbus.Variant{
			"Modified": dbus.MakeVariant(uint64(time.Now().Unix())),
		},
		[]string{},
	)
	if err != nil {
		// Log but don't fail
		log.Printf("failed to emit ItemChanged signal: %v", err)
	}
}

// EmitItemAdded emits a signal when an item is added to a collection.
func (sm *SignalManager) EmitItemAdded(collectionPath, _ dbus.ObjectPath) {
	if sm.bridge.conn == nil {
		return
	}

	// Update collection's Items property and emit change
	sm.bridge.mu.RLock()
	for _, collection := range sm.bridge.collections {
		if collection.Path() == collectionPath {
			collection.mu.Lock()
			collection.updateItemsProperty()
			collection.mu.Unlock()
			break
		}
	}
	sm.bridge.mu.RUnlock()

	// Emit collection changed signal
	sm.EmitCollectionChanged(collectionPath)
}

// EmitItemDeleted emits a signal when an item is deleted from a collection.
func (sm *SignalManager) EmitItemDeleted(collectionPath, _ dbus.ObjectPath) {
	if sm.bridge.conn == nil {
		return
	}

	// Update collection's Items property and emit change
	sm.bridge.mu.RLock()
	for _, collection := range sm.bridge.collections {
		if collection.Path() == collectionPath {
			collection.mu.Lock()
			collection.updateItemsProperty()
			collection.mu.Unlock()
			break
		}
	}
	sm.bridge.mu.RUnlock()

	// Emit collection changed signal
	sm.EmitCollectionChanged(collectionPath)
}

// Helper functions

// validateAliasName validates an alias name.
func validateAliasName(name string) error {
	if name == "" {
		return errors.New("alias name cannot be empty")
	}

	// Alias names should be simple identifiers
	for _, char := range name {
		if !isValidAliasChar(char) {
			return fmt.Errorf("alias name contains invalid character: %c", char)
		}
	}

	return nil
}

// isValidAliasChar checks if a character is valid for an alias name.
func isValidAliasChar(char rune) bool {
	return (char >= 'a' && char <= 'z') ||
		(char >= 'A' && char <= 'Z') ||
		(char >= '0' && char <= '9') ||
		char == '-' || char == '_'
}

// getDefaultCollectionLabel returns the default label for a collection name.
func getDefaultCollectionLabel(name string) string {
	labels := map[string]string{
		DefaultCollection: "Default",
		SessionCollection: "Session",
		"login":           "Login",
		"wallet":          "Wallet",
	}

	if label, ok := labels[name]; ok {
		return label
	}

	// Capitalize the first letter for custom collections
	if len(name) > 0 {
		return string(name[0]-32) + name[1:]
	}
	return name
}

// PropertyChangeNotifier provides a convenient way to notify property changes.
type PropertyChangeNotifier struct {
	signalManager *SignalManager
}

// NewPropertyChangeNotifier creates a new property change notifier.
func NewPropertyChangeNotifier(bridge *Bridge) *PropertyChangeNotifier {
	return &PropertyChangeNotifier{
		signalManager: NewSignalManager(bridge),
	}
}

// NotifyCollectionCreated notifies that a collection was created.
func (pcn *PropertyChangeNotifier) NotifyCollectionCreated(collectionPath dbus.ObjectPath) {
	pcn.signalManager.EmitCollectionAdded(collectionPath)
}

// NotifyCollectionDeleted notifies that a collection was deleted.
func (pcn *PropertyChangeNotifier) NotifyCollectionDeleted(collectionPath dbus.ObjectPath) {
	pcn.signalManager.EmitCollectionDeleted(collectionPath)
}

// NotifyCollectionChanged notifies that a collection was modified.
func (pcn *PropertyChangeNotifier) NotifyCollectionChanged(collectionPath dbus.ObjectPath) {
	pcn.signalManager.EmitCollectionChanged(collectionPath)
}

// NotifyItemCreated notifies that an item was created.
func (pcn *PropertyChangeNotifier) NotifyItemCreated(collectionPath, itemPath dbus.ObjectPath) {
	pcn.signalManager.EmitItemAdded(collectionPath, itemPath)
}

// NotifyItemDeleted notifies that an item was deleted.
func (pcn *PropertyChangeNotifier) NotifyItemDeleted(collectionPath, itemPath dbus.ObjectPath) {
	pcn.signalManager.EmitItemDeleted(collectionPath, itemPath)
}

// NotifyItemChanged notifies that an item was modified.
func (pcn *PropertyChangeNotifier) NotifyItemChanged(itemPath dbus.ObjectPath) {
	pcn.signalManager.EmitItemChanged(itemPath)
}
