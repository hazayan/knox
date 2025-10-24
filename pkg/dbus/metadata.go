// Package dbus provides D-Bus to Knox bridge implementation.
package dbus

import (
	"encoding/json"
	"time"
)

// ItemMetadata represents metadata for D-Bus secret items.
type ItemMetadata struct {
	Label      string            `json:"label"`      // Human-readable label for the item
	Attributes map[string]string `json:"attributes"` // Searchable attributes
	Created    int64             `json:"created"`    // Creation timestamp (Unix seconds)
	Modified   int64             `json:"modified"`   // Last modification timestamp (Unix seconds)
	Type       string            `json:"type"`       // Item type (e.g., "password", "certificate")
	AppID      string            `json:"app_id"`     // Application that created the item
}

// NewItemMetadata creates new metadata with default values.
func NewItemMetadata(label string) *ItemMetadata {
	now := time.Now().Unix()
	return &ItemMetadata{
		Label:      label,
		Attributes: make(map[string]string),
		Created:    now,
		Modified:   now,
		Type:       "password", // Default type
		AppID:      "knox-dbus",
	}
}

// Marshal serializes metadata to JSON bytes.
func (m *ItemMetadata) Marshal() ([]byte, error) {
	return json.Marshal(m)
}

// Unmarshal deserializes metadata from JSON bytes.
func (m *ItemMetadata) Unmarshal(data []byte) error {
	return json.Unmarshal(data, m)
}

// UpdateModified updates the modification timestamp to current time.
func (m *ItemMetadata) UpdateModified() {
	m.Modified = time.Now().Unix()
}

// SetAttribute sets an attribute and updates modification time.
func (m *ItemMetadata) SetAttribute(key, value string) {
	m.Attributes[key] = value
	m.UpdateModified()
}

// RemoveAttribute removes an attribute and updates modification time.
func (m *ItemMetadata) RemoveAttribute(key string) {
	delete(m.Attributes, key)
	m.UpdateModified()
}

// HasAttribute checks if an attribute exists.
func (m *ItemMetadata) HasAttribute(key string) bool {
	_, exists := m.Attributes[key]
	return exists
}

// GetAttribute returns an attribute value.
func (m *ItemMetadata) GetAttribute(key string) string {
	return m.Attributes[key]
}

// Metadata constants.
const (
	// MetadataKey is the key used to store metadata in Knox key data.
	MetadataKey = "dbus_metadata"

	// Default attributes for common use cases.
	AttributeService = "service"
	AttributeUser    = "user"
	AttributeURL     = "url"
	AttributeApp     = "application"
)

// ExtractMetadataFromKeyData extracts metadata from key data.
// Knox stores the actual secret data along with metadata in a structured format.
func ExtractMetadataFromKeyData(keyData []byte) (*ItemMetadata, []byte, error) {
	var data struct {
		Metadata *ItemMetadata `json:"metadata"`
		Secret   []byte        `json:"secret"`
	}

	if err := json.Unmarshal(keyData, &data); err != nil {
		// If unmarshaling fails, assume it's legacy format (just the secret)
		return nil, keyData, nil
	}

	return data.Metadata, data.Secret, nil
}

// CombineMetadataWithSecret combines metadata and secret into a single byte array.
func CombineMetadataWithSecret(metadata *ItemMetadata, secret []byte) ([]byte, error) {
	data := struct {
		Metadata *ItemMetadata `json:"metadata"`
		Secret   []byte        `json:"secret"`
	}{
		Metadata: metadata,
		Secret:   secret,
	}

	return json.Marshal(data)
}

// CreateDefaultAttributes creates default attributes from common patterns.
func CreateDefaultAttributes(label string) map[string]string {
	attrs := make(map[string]string)

	// Try to extract common patterns from label
	switch {
	case len(label) > 0:
		attrs[AttributeApp] = "unknown" // Will be updated by actual application
		// Additional attribute extraction can be added here based on label patterns
	}

	return attrs
}
