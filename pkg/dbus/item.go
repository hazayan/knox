package dbus

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
	"github.com/hazayan/knox/pkg/observability/metrics"
	"github.com/hazayan/knox/pkg/types"
)

// Item represents a secret item in a collection.
type Item struct {
	path       dbus.ObjectPath
	collection *Collection
	keyID      string
	label      string
	attributes map[string]string
	created    int64
	modified   int64
	locked     bool
	mu         sync.RWMutex
}

// NewItem creates a new item.
func NewItem(collection *Collection, itemID, label string, attributes map[string]string) *Item {
	now := time.Now().Unix()

	return &Item{
		path:       makeItemPath(collection.name, itemID),
		collection: collection,
		keyID:      collection.makeKeyID(itemID),
		label:      label,
		attributes: attributes,
		created:    now,
		modified:   now,
		locked:     false,
	}
}

// Path returns the D-Bus object path for this item.
func (i *Item) Path() dbus.ObjectPath {
	return i.path
}

// Export exports the item to D-Bus.
func (i *Item) Export(conn *dbus.Conn, _ *prop.Properties) error {
	return conn.Export(i, i.path, ItemInterface)
}

// Unexport removes the item from D-Bus.
func (i *Item) Unexport(conn *dbus.Conn) {
	if err := conn.Export(nil, i.path, ItemInterface); err != nil {
		// Log error but don't return - this is best effort cleanup
		log.Printf("failed to unexport item: %v", err)
	}
}

// D-Bus methods

// Delete deletes the item.
func (i *Item) Delete() (dbus.ObjectPath, *dbus.Error) {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RecordDBusItem("Delete")
		metrics.RecordDBusOperation("ItemDelete", "success", duration)
	}()
	// Delete from Knox
	client := i.collection.bridge.knoxClient
	if err := client.DeleteKey(i.keyID); err != nil {
		return "/", dbus.MakeFailedError(err)
	}

	// Remove from collection
	i.collection.removeItem(i)

	// Emit signal for item deletion
	i.collection.bridge.signalManager.EmitItemDeleted(i.collection.Path(), i.Path())

	// No prompt needed, return root path
	return "/", nil
}

// GetSecret retrieves the secret value.
func (i *Item) GetSecret(sessionPath dbus.ObjectPath) (Secret, *dbus.Error) {
	// Get session
	session, err := i.collection.bridge.sessionMgr.GetSession(sessionPath)
	if err != nil {
		return Secret{}, dbus.MakeFailedError(err)
	}

	// Get secret from Knox
	client := i.collection.bridge.knoxClient
	key, err := client.GetKey(i.keyID)
	if err != nil {
		return Secret{}, dbus.MakeFailedError(err)
	}

	// Get primary version
	primary := key.VersionList.GetPrimary()
	if primary == nil {
		return Secret{}, dbus.MakeFailedError(errors.New("no primary version"))
	}

	// Extract the actual secret from the stored data (which may include metadata)
	_, secretData, err := ExtractMetadataFromKeyData(primary.Data)
	if err != nil {
		return Secret{}, dbus.MakeFailedError(fmt.Errorf("failed to extract secret: %w", err))
	}

	// Encrypt the secret
	params, value, err := session.Encrypt(secretData)
	if err != nil {
		return Secret{}, dbus.MakeFailedError(err)
	}

	return Secret{
		Session:     sessionPath,
		Parameters:  params,
		Value:       value,
		ContentType: "text/plain",
	}, nil
}

// SetSecret sets the secret value.
func (i *Item) SetSecret(secret Secret) *dbus.Error {
	// Get session
	session, err := i.collection.bridge.sessionMgr.GetSession(secret.Session)
	if err != nil {
		return dbus.MakeFailedError(err)
	}

	// Decrypt the secret
	data, err := session.Decrypt(secret.Parameters, secret.Value)
	if err != nil {
		return dbus.MakeFailedError(err)
	}

	// Add new version to Knox
	client := i.collection.bridge.knoxClient
	if _, err := client.AddVersion(i.keyID, data); err != nil {
		return dbus.MakeFailedError(err)
	}

	i.mu.Lock()
	i.modified = time.Now().Unix()
	i.mu.Unlock()

	// Emit signal for item modification
	i.collection.bridge.signalManager.EmitItemChanged(i.Path())

	return nil
}

// Introspect returns XML introspection data.
func (i *Item) Introspect() *introspect.Node {
	return &introspect.Node{
		Interfaces: []introspect.Interface{
			{
				Name: ItemInterface,
				Methods: []introspect.Method{
					{
						Name: "Delete",
						Args: []introspect.Arg{
							{Name: "prompt", Type: "o", Direction: "out"},
						},
					},
					{
						Name: "GetSecret",
						Args: []introspect.Arg{
							{Name: "session", Type: "o", Direction: "in"},
							{Name: "secret", Type: "(oayays)", Direction: "out"},
						},
					},
					{
						Name: "SetSecret",
						Args: []introspect.Arg{
							{Name: "secret", Type: "(oayays)", Direction: "in"},
						},
					},
					{
						Name: "SetProperties",
						Args: []introspect.Arg{
							{Name: "properties", Type: "a{sv}", Direction: "in"},
						},
					},
				},
				Properties: []introspect.Property{
					{Name: "Locked", Type: "b", Access: "read"},
					{Name: "Attributes", Type: "a{ss}", Access: "readwrite"},
					{Name: "Label", Type: "s", Access: "readwrite"},
					{Name: "Created", Type: "t", Access: "read"},
					{Name: "Modified", Type: "t", Access: "read"},
				},
			},
			introspect.IntrospectData,
		},
	}
}

// SetProperties sets properties on the item.
func (i *Item) SetProperties(properties map[string]dbus.Variant) *dbus.Error {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RecordDBusItem("SetProperties")
		metrics.RecordDBusOperation("ItemSetProperties", "success", duration)
	}()
	i.mu.Lock()
	defer i.mu.Unlock()

	// Update label if provided
	if labelVar, ok := properties["org.freedesktop.Secret.Item.Label"]; ok {
		if label, ok := labelVar.Value().(string); ok {
			if err := validateLabel(label); err != nil {
				return dbus.MakeFailedError(fmt.Errorf("invalid label: %w", err))
			}
			i.label = label
		}
	}

	// Update attributes if provided
	if attrsVar, ok := properties["org.freedesktop.Secret.Item.Attributes"]; ok {
		if attrs, ok := attrsVar.Value().(map[string]string); ok {
			i.attributes = attrs
		}
	}

	i.modified = time.Now().Unix()

	return nil
}

// Lock locks the item.
func (i *Item) Lock() {
	metrics.RecordDBusItem("Lock")
	i.mu.Lock()
	defer i.mu.Unlock()
	i.locked = true
}

// Unlock unlocks the item.
func (i *Item) Unlock() {
	metrics.RecordDBusItem("Unlock")
	i.mu.Lock()
	defer i.mu.Unlock()
	i.locked = false
}

// IsLocked returns whether the item is locked.
func (i *Item) IsLocked() bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.locked
}

// Helper methods

// MatchesAttributes checks if the item matches the given attributes.
func (i *Item) MatchesAttributes(attributes map[string]string) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()

	for key, value := range attributes {
		if itemValue, ok := i.attributes[key]; !ok || itemValue != value {
			return false
		}
	}
	return true
}

// GetLabel returns the item's label.
func (i *Item) GetLabel() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.label
}

// GetAttributes returns the item's attributes.
func (i *Item) GetAttributes() map[string]string {
	i.mu.RLock()
	defer i.mu.RUnlock()

	// Return a copy
	attrs := make(map[string]string)
	for k, v := range i.attributes {
		attrs[k] = v
	}
	return attrs
}

// createItemFromKnoxKey creates an item from a Knox key.
func createItemFromKnoxKey(collection *Collection, key *types.Key) *Item {
	// Extract item ID from key ID (remove collection prefix)
	itemID := key.ID[len(collection.prefix):]

	// Extract metadata from key data
	var label string
	var attributes map[string]string
	var created int64

	if len(key.VersionList) > 0 {
		// Get the primary version data
		primaryData := key.VersionList.GetPrimary().Data

		// Try to extract metadata
		metadata, _, err := ExtractMetadataFromKeyData(primaryData)
		if err == nil && metadata != nil {
			// Use metadata if available
			label = metadata.Label
			attributes = metadata.Attributes
			created = metadata.Created
		} else {
			// Fallback to legacy format
			label = itemID
			attributes = make(map[string]string)
			created = key.VersionList[0].CreationTime / 1e9 // Convert from nanoseconds
		}
	} else {
		// No versions available
		label = itemID
		attributes = make(map[string]string)
		created = 0
	}

	item := NewItem(collection, itemID, label, attributes)
	item.created = created

	return item
}

// saveItemToKnox saves an item to Knox as a new key.
func saveItemToKnox(_ context.Context, item *Item, data []byte, acl types.ACL) error {
	client := item.collection.bridge.knoxClient

	// Create metadata for the item
	metadata := NewItemMetadata(item.label)
	metadata.Attributes = item.attributes
	metadata.Created = item.created
	metadata.Modified = item.modified

	// Combine metadata with secret data
	combinedData, err := CombineMetadataWithSecret(metadata, data)
	if err != nil {
		return fmt.Errorf("failed to combine metadata with secret: %w", err)
	}

	// Create the key in Knox
	_, err = client.CreateKey(item.keyID, combinedData, acl)
	if err != nil {
		return fmt.Errorf("failed to create Knox key: %w", err)
	}

	return nil
}
