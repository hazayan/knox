package crypto

import (
	"encoding/json"
	"fmt"
)

// CryptoMetadata contains information about how data was encrypted.
type CryptoMetadata struct {
	Algorithm    string `json:"algorithm"`     // e.g., "AES-256-GCM"
	EncryptedDEK string `json:"encrypted_dek"` // Base64-encoded encrypted data encryption key
	Version      int    `json:"version"`       // Metadata format version
}

// Marshal serializes the metadata to JSON.
func (m *CryptoMetadata) Marshal() ([]byte, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal crypto metadata: %w", err)
	}
	return data, nil
}

// UnmarshalCryptoMetadata deserializes metadata from JSON.
func UnmarshalCryptoMetadata(data []byte) (*CryptoMetadata, error) {
	var metadata CryptoMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal crypto metadata: %w", err)
	}

	// Validate required fields
	if metadata.Algorithm == "" {
		return nil, fmt.Errorf("missing algorithm in metadata")
	}
	if metadata.EncryptedDEK == "" {
		return nil, fmt.Errorf("missing encrypted DEK in metadata")
	}
	if metadata.Version == 0 {
		return nil, fmt.Errorf("missing version in metadata")
	}

	return &metadata, nil
}
