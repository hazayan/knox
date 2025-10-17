// Package storage provides encrypted storage backends for Knox.
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pinterest/knox"
	"github.com/pinterest/knox/pkg/observability/logging"
	"github.com/pinterest/knox/server/keydb"
)

// EncryptedBackend wraps a Backend to store encrypted keydb.DBKey instead of plaintext knox.Key.
// This is the correct implementation for Knox - storage backends should only ever see encrypted data.
type EncryptedBackend struct {
	backend Backend
}

// NewEncryptedBackend wraps a backend to store encrypted DBKeys.
func NewEncryptedBackend(backend Backend) *EncryptedBackend {
	return &EncryptedBackend{
		backend: backend,
	}
}

// Get retrieves an encrypted DBKey from storage.
func (e *EncryptedBackend) Get(keyID string) (*keydb.DBKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Backend stores knox.Key, but we'll serialize DBKey to its Data field
	wrapper, err := e.backend.GetKey(ctx, keyID)
	if err != nil {
		if err == ErrKeyNotFound {
			return nil, nil // Knox convention: nil for not found
		}
		return nil, fmt.Errorf("backend get failed: %w", err)
	}

	// Deserialize the DBKey from the wrapper's Data field
	var dbKey keydb.DBKey
	if err := json.Unmarshal(wrapper.VersionList[0].Data, &dbKey); err != nil {
		return nil, fmt.Errorf("failed to deserialize DBKey: %w", err)
	}

	return &dbKey, nil
}

// GetAll retrieves all encrypted DBKeys from storage.
func (e *EncryptedBackend) GetAll() ([]keydb.DBKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	keyIDs, err := e.backend.ListKeys(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("backend list failed: %w", err)
	}

	dbKeys := make([]keydb.DBKey, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		dbKey, err := e.Get(keyID)
		if err != nil {
			logging.Errorf("Failed to get key %s: %v", keyID, err)
			continue
		}
		if dbKey != nil {
			dbKeys = append(dbKeys, *dbKey)
		}
	}

	return dbKeys, nil
}

// Update stores an encrypted DBKey in storage.
func (e *EncryptedBackend) Update(dbKey *keydb.DBKey) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Serialize the encrypted DBKey
	data, err := json.Marshal(dbKey)
	if err != nil {
		return fmt.Errorf("failed to serialize DBKey: %w", err)
	}

	// Wrap in a knox.Key for backend storage
	// The backend will store this serialized encrypted DBKey
	wrapper := &knox.Key{
		ID:  dbKey.ID,
		ACL: dbKey.ACL,
		VersionList: knox.KeyVersionList{
			{
				ID:   1,
				Data: data, // Encrypted DBKey serialized here
			},
		},
	}

	if err := e.backend.PutKey(ctx, wrapper); err != nil {
		return fmt.Errorf("backend put failed: %w", err)
	}

	return nil
}

// Add stores new encrypted DBKeys.
func (e *EncryptedBackend) Add(keys ...*keydb.DBKey) error {
	for _, dbKey := range keys {
		// Check if exists
		existing, err := e.Get(dbKey.ID)
		if err != nil {
			return fmt.Errorf("failed to check existence: %w", err)
		}
		if existing != nil {
			return fmt.Errorf("key already exists: %s", dbKey.ID)
		}

		if err := e.Update(dbKey); err != nil {
			return fmt.Errorf("failed to add key: %w", err)
		}
	}

	return nil
}

// Remove deletes a key from storage.
func (e *EncryptedBackend) Remove(keyID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := e.backend.DeleteKey(ctx, keyID)
	if err == ErrKeyNotFound {
		return nil // Not an error
	}
	return err
}

// Verify interface compliance
var _ keydb.DB = (*EncryptedBackend)(nil)
