// Package dbus implements the FreeDesktop Secret Service API.
// Spec: https://specifications.freedesktop.org/secret-service-spec/latest/
package dbus

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
	"github.com/hazayan/knox/pkg/observability/metrics"
	"github.com/hazayan/knox/pkg/types"
)

// Collection represents a collection of secret items.
type Collection struct {
	name     string
	path     dbus.ObjectPath
	prefix   string // Knox key prefix for this collection
	label    string
	bridge   *Bridge
	items    map[string]*Item
	mu       sync.RWMutex
	props    *prop.Properties
	created  int64 // Creation timestamp (Unix seconds)
	modified int64 // Last modification timestamp (Unix seconds)
	locked   bool  // Whether the collection is locked
}

// NewCollection creates a new collection.
func NewCollection(bridge *Bridge, name, label string, customPrefix ...string) *Collection {
	now := time.Now().Unix()
	prefix := ""
	if len(customPrefix) > 0 && customPrefix[0] != "" {
		// Use custom prefix directly (e.g., "service:auth")
		// Strip trailing colon if present to avoid double colons
		knoxPrefix := strings.TrimSuffix(customPrefix[0], ":")
		prefix = knoxPrefix + ":"
	} else {
		// Use default pattern: namespace:collection:
		prefix = bridge.config.Knox.NamespacePrefix + ":" + name + ":"
	}
	return &Collection{
		name:     name,
		path:     makeCollectionPath(name),
		prefix:   prefix,
		label:    label,
		bridge:   bridge,
		items:    make(map[string]*Item),
		created:  now,
		modified: now,
		locked:   false,
	}
}

// Path returns the D-Bus object path for this collection.
func (c *Collection) Path() dbus.ObjectPath {
	return c.path
}

// makeKeyID creates a Knox key ID for an item.
func (c *Collection) makeKeyID(itemID string) string {
	return c.prefix + itemID
}

// Export exports the collection to D-Bus.
func (c *Collection) Export(conn *dbus.Conn) error {
	var err error

	// Create properties
	c.props, err = prop.Export(conn, c.Path(), map[string]map[string]*prop.Prop{
		CollectionInterface: {
			"Items": {
				Value:    []dbus.ObjectPath{},
				Writable: false,
				Emit:     prop.EmitTrue,
				Callback: nil,
			},
			"Label": {
				Value:    c.label,
				Writable: true,
				Emit:     prop.EmitTrue,
				Callback: c.onLabelChanged,
			},
			"Locked": {
				Value:    false,
				Writable: false,
				Emit:     prop.EmitTrue,
				Callback: nil,
			},
			"Created": {
				Value:    uint64(0),
				Writable: false,
				Emit:     prop.EmitTrue,
				Callback: nil,
			},
			"Modified": {
				Value:    uint64(0),
				Writable: false,
				Emit:     prop.EmitTrue,
				Callback: nil,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to export properties: %w", err)
	}

	// Export the collection
	if err := conn.Export(c, c.path, CollectionInterface); err != nil {
		return err
	}

	// Export introspection
	introspectNode := c.Introspect()
	introspectNode.Name = string(c.path)
	// Ensure prop.IntrospectData is included
	hasPropIntrospect := false
	for _, iface := range introspectNode.Interfaces {
		if iface.Name == "org.freedesktop.DBus.Properties" {
			hasPropIntrospect = true
			break
		}
	}
	if !hasPropIntrospect {
		introspectNode.Interfaces = append([]introspect.Interface{prop.IntrospectData}, introspectNode.Interfaces...)
	}
	if err := conn.Export(introspect.NewIntrospectable(introspectNode), c.path, "org.freedesktop.DBus.Introspectable"); err != nil {
		return fmt.Errorf("failed to export introspection: %w", err)
	}

	// Load items from Knox
	if err := c.loadItems(conn); err != nil {
		return fmt.Errorf("failed to load items: %w", err)
	}

	return nil
}

// Unexport removes the collection from D-Bus.
func (c *Collection) Unexport(conn *dbus.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Skip if connection is nil (e.g., in tests)
	if conn == nil {
		return
	}

	// Unexport all items
	for _, item := range c.items {
		item.Unexport(conn)
	}

	if err := conn.Export(nil, c.path, CollectionInterface); err != nil {
		// Log error but don't return - this is best effort cleanup
		log.Printf("failed to export collection: %v", err)
	}
}

// loadItems loads items from Knox.
func (c *Collection) loadItems(conn *dbus.Conn) error {
	// List all keys with this collection's prefix
	keys, err := c.bridge.knoxClient.GetKeys(map[string]string{})
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}

	var itemPaths []dbus.ObjectPath

	for _, keyID := range keys {
		// Check if key belongs to this collection
		if !strings.HasPrefix(keyID, c.prefix) {
			continue
		}

		// Get the full key
		key, err := c.bridge.knoxClient.GetKey(keyID)
		if err != nil {
			continue // Skip keys we can't read
		}

		// Create item
		item := createItemFromKnoxKey(c, key)

		// Export item
		if err := item.Export(conn, c.props); err != nil {
			continue
		}

		// Add to collection
		c.mu.Lock()
		itemID := keyID[len(c.prefix):]
		c.items[itemID] = item
		itemPaths = append(itemPaths, item.Path())
		c.mu.Unlock()
	}

	// Update Items property
	c.props.SetMust(CollectionInterface, "Items", itemPaths)

	return nil
}

// Property callbacks.
func (c *Collection) onLabelChanged(change *prop.Change) *dbus.Error {
	c.mu.Lock()
	defer c.mu.Unlock()

	label, ok := change.Value.(string)
	if !ok {
		return dbus.MakeFailedError(errors.New("invalid label type"))
	}

	c.label = label
	return nil
}

// D-Bus methods

// Delete deletes the collection.
func (c *Collection) Delete() (dbus.ObjectPath, *dbus.Error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RecordDBusCollection("Delete")
		metrics.RecordDBusOperation("CollectionDelete", "success", duration)
	}()
	c.mu.Lock()
	defer c.mu.Unlock()

	// Delete all items
	if err := c.DeleteAllItems(); err != nil {
		return "/", dbus.MakeFailedError(fmt.Errorf("failed to delete collection items: %w", err))
	}

	// No prompt needed
	return "/", nil
}

// DeleteAllItems deletes all items in the collection.
func (c *Collection) DeleteAllItems() error {
	for _, item := range c.items {
		if err := c.bridge.knoxClient.DeleteKey(item.keyID); err != nil {
			return fmt.Errorf("failed to delete key %s: %w", item.keyID, err)
		}
	}
	return nil
}

// SearchItems searches for items matching the given attributes.
func (c *Collection) SearchItems(attributes map[string]string) ([]dbus.ObjectPath, error) {
	metrics.RecordDBusCollection("SearchItems")
	c.mu.RLock()
	defer c.mu.RUnlock()

	var matches []dbus.ObjectPath

	for _, item := range c.items {
		if item.MatchesAttributes(attributes) {
			matches = append(matches, item.Path())
		}
	}

	return matches, nil
}

// Lock locks the collection and all its items.
func (c *Collection) Lock() {
	metrics.RecordDBusCollection("Lock")
	c.mu.Lock()
	defer c.mu.Unlock()

	c.locked = true
	c.props.SetMust(CollectionInterface, "Locked", true)

	// Lock all items in the collection
	for _, item := range c.items {
		item.Lock()
	}
}

// Unlock unlocks the collection and all its items.
func (c *Collection) Unlock() {
	metrics.RecordDBusCollection("Unlock")
	c.mu.Lock()
	defer c.mu.Unlock()

	c.locked = false
	c.props.SetMust(CollectionInterface, "Locked", false)

	// Unlock all items in the collection
	for _, item := range c.items {
		item.Unlock()
	}
}

// IsLocked returns whether the collection is locked.
func (c *Collection) IsLocked() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.locked
}

// CreateItem creates a new item in the collection.
func (c *Collection) CreateItem(properties map[string]dbus.Variant, secret Secret, replace bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RecordDBusCollection("CreateItem")
		metrics.RecordDBusOperation("CollectionCreateItem", "success", duration)
	}()
	// Extract properties
	label := ""
	if labelVar, ok := properties["org.freedesktop.Secret.Item.Label"]; ok {
		label = labelVar.Value().(string)
	}

	attributes := make(map[string]string)
	if attrsVar, ok := properties["org.freedesktop.Secret.Item.Attributes"]; ok {
		attributes = attrsVar.Value().(map[string]string)
	}

	// Generate item ID from label or attributes
	itemID := generateItemID(label, attributes)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if item exists
	if existing, ok := c.items[itemID]; ok {
		if !replace {
			return "/", "/", dbus.MakeFailedError(errors.New("item already exists"))
		}
		// Delete existing item
		if err := c.bridge.knoxClient.DeleteKey(existing.keyID); err != nil {
			return "/", "/", dbus.MakeFailedError(fmt.Errorf("failed to delete key %s: %w", existing.keyID, err))
		}
	}

	// Create new item
	item := NewItem(c, itemID, label, attributes)

	// Get session and decrypt secret
	session, err := c.bridge.sessionMgr.GetSession(secret.Session)
	if err != nil {
		return "/", "/", dbus.MakeFailedError(err)
	}

	data, err := session.Decrypt(secret.Parameters, secret.Value)
	if err != nil {
		return "/", "/", dbus.MakeFailedError(err)
	}

	// Create default ACL (grant admin access to creator)
	// For D-Bus bridge, use a system principal
	acl := types.ACL{
		{
			Type:       types.User,
			ID:         "dbus-user",
			AccessType: types.Admin,
		},
	}

	// Save to Knox
	ctx := context.Background()
	if err := saveItemToKnox(ctx, item, data, acl); err != nil {
		return "/", "/", dbus.MakeFailedError(err)
	}

	// Export item to D-Bus
	if err := item.Export(c.bridge.conn, c.props); err != nil {
		return "/", "/", dbus.MakeFailedError(err)
	}

	// Add to collection
	c.items[itemID] = item

	// Update Items property
	c.updateItemsProperty()

	// Emit signal for item creation
	if c.bridge.signalManager != nil {
		c.bridge.signalManager.EmitItemAdded(c.Path(), item.Path())
	}

	// No prompt needed
	return item.Path(), "/", nil
}

// SetProperties sets properties on the collection.
func (c *Collection) SetProperties(properties map[string]dbus.Variant) *dbus.Error {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RecordDBusCollection("SetProperties")
		metrics.RecordDBusOperation("CollectionSetProperties", "success", duration)
	}()
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update label if provided
	if labelVar, ok := properties["org.freedesktop.Secret.Collection.Label"]; ok {
		if label, ok := labelVar.Value().(string); ok {
			if err := validateLabel(label); err != nil {
				return dbus.MakeFailedError(fmt.Errorf("invalid label: %w", err))
			}
			c.label = label
			c.props.SetMust(CollectionInterface, "Label", label)
			c.modified = time.Now().Unix()
		}
	}

	return nil
}

// GetSecrets retrieves secrets for multiple items in this collection.
func (c *Collection) GetSecrets(items []dbus.ObjectPath, sessionPath dbus.ObjectPath) (map[dbus.ObjectPath]Secret, *dbus.Error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RecordDBusCollection("GetSecrets")
		metrics.RecordDBusOperation("CollectionGetSecrets", "success", duration)
	}()
	secrets := make(map[dbus.ObjectPath]Secret)

	// Get session
	session, err := c.bridge.sessionMgr.GetSession(sessionPath)
	if err != nil {
		return nil, dbus.MakeFailedError(err)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	// Find each item and get its secret
	for _, itemPath := range items {
		// Parse item path to find item ID
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

		// Verify this is the correct collection
		if parts[0] != c.name {
			continue
		}

		itemID := parts[1]

		// Find item in collection
		item, ok := c.items[itemID]
		if !ok {
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

// Introspect returns XML introspection data.
func (c *Collection) Introspect() *introspect.Node {
	return &introspect.Node{
		Interfaces: []introspect.Interface{
			{
				Name: CollectionInterface,
				Methods: []introspect.Method{
					{
						Name: "Delete",
						Args: []introspect.Arg{
							{Name: "prompt", Type: "o", Direction: "out"},
						},
					},
					{
						Name: "SearchItems",
						Args: []introspect.Arg{
							{Name: "attributes", Type: "a{ss}", Direction: "in"},
							{Name: "results", Type: "ao", Direction: "out"},
						},
					},
					{
						Name: "CreateItem",
						Args: []introspect.Arg{
							{Name: "properties", Type: "a{sv}", Direction: "in"},
							{Name: "secret", Type: "(oayays)", Direction: "in"},
							{Name: "replace", Type: "b", Direction: "in"},
							{Name: "item", Type: "o", Direction: "out"},
							{Name: "prompt", Type: "o", Direction: "out"},
						},
					},
					{
						Name: "SetProperties",
						Args: []introspect.Arg{
							{Name: "properties", Type: "a{sv}", Direction: "in"},
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
				},
				Properties: []introspect.Property{
					{Name: "Items", Type: "ao", Access: "read"},
					{Name: "Label", Type: "s", Access: "readwrite"},
					{Name: "Locked", Type: "b", Access: "read"},
					{Name: "Created", Type: "t", Access: "read"},
					{Name: "Modified", Type: "t", Access: "read"},
				},
			},
			introspect.IntrospectData,
		},
	}
}

// Helper methods

// removeItem removes an item from the collection.
func (c *Collection) removeItem(item *Item) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Extract item ID from key ID
	itemID := item.keyID[len(c.prefix):]

	// Remove from map
	delete(c.items, itemID)

	// Unexport from D-Bus (if bridge and connection are available)
	if c.bridge != nil && c.bridge.conn != nil {
		item.Unexport(c.bridge.conn)
	}

	// Update Items property
	c.updateItemsProperty()
}

// updateItemsProperty updates the Items property.
func (c *Collection) updateItemsProperty() {
	var paths []dbus.ObjectPath
	for _, item := range c.items {
		paths = append(paths, item.Path())
	}
	if c.props != nil {
		c.props.SetMust(CollectionInterface, "Items", paths)
	}
}

// generateItemID generates a unique item ID.
func generateItemID(label string, attributes map[string]string) string {
	// Use label if available
	if label != "" {
		return sanitizeID(label)
	}

	// Try to generate from attributes
	if username, ok := attributes["username"]; ok {
		if domain, ok := attributes["domain"]; ok {
			return sanitizeID(username + "_" + domain)
		}
		return sanitizeID(username)
	}

	// Fall back to random ID
	id := generateID()
	return id
}

// sanitizeID sanitizes a string for use as an item ID.
func sanitizeID(s string) string {
	// Replace invalid characters with underscores
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, " ", "_")
	return s
}
