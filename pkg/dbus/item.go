package dbus

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
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
	}
}

// Path returns the D-Bus object path for this item.
func (i *Item) Path() dbus.ObjectPath {
	return i.path
}

// Export exports the item to D-Bus.
func (i *Item) Export(conn *dbus.Conn, props *prop.Properties) error {
	return conn.Export(i, i.path, ItemInterface)
}

// Unexport removes the item from D-Bus.
func (i *Item) Unexport(conn *dbus.Conn) {
	conn.Export(nil, i.path, ItemInterface)
}

// Property change callbacks.
func (i *Item) onLabelChanged(c *prop.Change) *dbus.Error {
	i.mu.Lock()
	defer i.mu.Unlock()

	label, ok := c.Value.(string)
	if !ok {
		return dbus.MakeFailedError(errors.New("invalid label type"))
	}

	i.label = label
	i.modified = time.Now().Unix()

	// TODO: Update Knox key metadata

	return nil
}

func (i *Item) onAttributesChanged(c *prop.Change) *dbus.Error {
	i.mu.Lock()
	defer i.mu.Unlock()

	attrs, ok := c.Value.(map[string]string)
	if !ok {
		return dbus.MakeFailedError(errors.New("invalid attributes type"))
	}

	i.attributes = attrs
	i.modified = time.Now().Unix()

	// TODO: Update Knox key metadata

	return nil
}

// D-Bus methods

// Delete deletes the item.
func (i *Item) Delete() (dbus.ObjectPath, *dbus.Error) {
	// Delete from Knox
	client := i.collection.bridge.knoxClient
	if err := client.DeleteKey(i.keyID); err != nil {
		return "/", dbus.MakeFailedError(err)
	}

	// Remove from collection
	i.collection.removeItem(i)

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

	// Encrypt the secret
	params, value, err := session.Encrypt(primary.Data)
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

// Helper methods

// MatchAttributes checks if the item matches the given attributes.
func (i *Item) MatchAttributes(attrs map[string]string) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()

	for key, value := range attrs {
		if i.attributes[key] != value {
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
func createItemFromKnoxKey(collection *Collection, key *types.Key) (*Item, error) {
	// Extract item ID from key ID (remove collection prefix)
	itemID := key.ID[len(collection.prefix):]

	// TODO: Extract label and attributes from key metadata
	// For now, use key ID as label and empty attributes
	label := itemID
	attributes := make(map[string]string)

	// Get creation time from first version
	var created int64
	if len(key.VersionList) > 0 {
		created = key.VersionList[0].CreationTime / 1e9 // Convert from nanoseconds
	} else {
		created = time.Now().Unix()
	}

	item := NewItem(collection, itemID, label, attributes)
	item.created = created

	return item, nil
}

// saveItemToKnox saves an item to Knox as a new key.
func saveItemToKnox(ctx context.Context, item *Item, data []byte, acl types.ACL) error {
	client := item.collection.bridge.knoxClient

	// Create the key in Knox
	_, err := client.CreateKey(item.keyID, data, acl)
	if err != nil {
		return fmt.Errorf("failed to create Knox key: %w", err)
	}

	// TODO: Store label and attributes as metadata

	return nil
}
