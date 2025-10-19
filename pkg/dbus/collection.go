package dbus

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
	"github.com/hazayan/knox/pkg/types"
)

// Collection represents a collection of secret items.
type Collection struct {
	name   string
	path   dbus.ObjectPath
	prefix string // Knox key prefix for this collection
	label  string
	bridge *Bridge
	items  map[string]*Item
	mu     sync.RWMutex
	props  *prop.Properties
}

// NewCollection creates a new collection.
func NewCollection(bridge *Bridge, name, label string) *Collection {
	return &Collection{
		name:   name,
		path:   makeCollectionPath(name),
		prefix: bridge.config.Knox.NamespacePrefix + ":" + name + ":",
		label:  label,
		bridge: bridge,
		items:  make(map[string]*Item),
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
	// Create properties handler
	c.props = prop.New(conn, c.path, map[string]map[string]*prop.Prop{
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
				Value:    uint64(0), // TODO: Track creation time
				Writable: false,
				Emit:     prop.EmitFalse,
				Callback: nil,
			},
			"Modified": {
				Value:    uint64(0), // TODO: Track modification time
				Writable: false,
				Emit:     prop.EmitFalse,
				Callback: nil,
			},
		},
	})

	// Export the collection
	if err := conn.Export(c, c.path, CollectionInterface); err != nil {
		return err
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

	// Unexport all items
	for _, item := range c.items {
		item.Unexport(conn)
	}

	conn.Export(nil, c.path, CollectionInterface)
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
		item, err := createItemFromKnoxKey(c, key)
		if err != nil {
			continue
		}

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
	c.mu.Lock()
	defer c.mu.Unlock()

	// Delete all items
	for _, item := range c.items {
		c.bridge.knoxClient.DeleteKey(item.keyID)
	}

	// No prompt needed
	return "/", nil
}

// SearchItems searches for items matching the given attributes.
func (c *Collection) SearchItems(attributes map[string]string) ([]dbus.ObjectPath, *dbus.Error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var results []dbus.ObjectPath

	for _, item := range c.items {
		if item.MatchAttributes(attributes) {
			results = append(results, item.Path())
		}
	}

	return results, nil
}

// CreateItem creates a new item in the collection.
func (c *Collection) CreateItem(properties map[string]dbus.Variant, secret Secret, replace bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
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
		c.bridge.knoxClient.DeleteKey(existing.keyID)
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
	// TODO: Get actual user principal
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

	// No prompt needed
	return item.Path(), "/", nil
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

	// Unexport from D-Bus
	item.Unexport(c.bridge.conn)

	// Update Items property
	c.updateItemsProperty()
}

// updateItemsProperty updates the Items property.
func (c *Collection) updateItemsProperty() {
	var paths []dbus.ObjectPath
	for _, item := range c.items {
		paths = append(paths, item.Path())
	}
	c.props.SetMust(CollectionInterface, "Items", paths)
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
	id, _ := generateID()
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
