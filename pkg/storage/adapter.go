// Package storage provides a storage backend adapter that connects
// our storage.Backend interface to Knox's keydb.DB interface.
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/hazayan/knox/pkg/types"
	"github.com/hazayan/knox/server/keydb"
)

// DBAdapter adapts storage.Backend to keydb.DB interface.
// It stores ENCRYPTED keydb.DBKey data in the backend by serializing it
// into a wrapper types.Key structure. The backend never sees plaintext secrets.
//
// SECURITY: All data stored in backend is encrypted. The serialized DBKey
// contains encrypted EncData fields from the cryptor.
type DBAdapter struct {
	backend Backend
	mu      sync.RWMutex
	cache   map[string]*cachedKey // Optional in-memory cache
}

// cachedKey represents a cached key with TTL.
type cachedKey struct {
	key       *keydb.DBKey
	expiresAt time.Time
}

// NewDBAdapter creates a new storage backend adapter.
// The adapter stores encrypted DBKey data - the backend never sees plaintext.
func NewDBAdapter(backend Backend, cryptor keydb.Cryptor) keydb.DB {
	return &DBAdapter{
		backend: backend,
		cache:   make(map[string]*cachedKey),
	}
}

// Get retrieves an encrypted DBKey from storage.
// The data is stored as a serialized DBKey (which contains encrypted EncData).
func (a *DBAdapter) Get(keyID string) (*keydb.DBKey, error) {
	// Check cache first
	if dbKey := a.getCached(keyID); dbKey != nil {
		return dbKey, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Retrieve wrapper from backend
	// The wrapper's VersionList[0].Data contains serialized encrypted DBKey
	wrapper, err := a.backend.GetKey(ctx, keyID)
	if err != nil {
		if err == ErrKeyNotFound {
			return nil, nil // Knox convention: nil for not found
		}
		return nil, fmt.Errorf("backend get failed: %w", err)
	}

	// Deserialize the encrypted DBKey from the wrapper
	if len(wrapper.VersionList) == 0 {
		return nil, fmt.Errorf("invalid stored key: no versions")
	}

	var dbKey keydb.DBKey
	if err := json.Unmarshal(wrapper.VersionList[0].Data, &dbKey); err != nil {
		return nil, fmt.Errorf("failed to deserialize DBKey: %w", err)
	}

	// Cache the encrypted result
	a.setCached(keyID, &dbKey)

	return &dbKey, nil
}

// GetAll retrieves all encrypted keys from storage.
func (a *DBAdapter) GetAll() ([]keydb.DBKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// List all key IDs
	keyIDs, err := a.backend.ListKeys(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("backend list failed: %w", err)
	}

	// Retrieve each key
	dbKeys := make([]keydb.DBKey, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		dbKey, err := a.Get(keyID)
		if err != nil {
			// Log error and continue with other keys
			fmt.Printf("WARNING: Failed to get key %s: %v\n", keyID, err)
			continue
		}
		if dbKey != nil {
			dbKeys = append(dbKeys, *dbKey)
		}
	}

	return dbKeys, nil
}

// Update stores an encrypted DBKey in storage.
// The DBKey is serialized (containing encrypted EncData) and stored in the backend.
func (a *DBAdapter) Update(dbKey *keydb.DBKey) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Serialize the encrypted DBKey
	data, err := json.Marshal(dbKey)
	if err != nil {
		return fmt.Errorf("failed to serialize DBKey: %w", err)
	}

	// Wrap in types.Key for backend storage
	// The encrypted DBKey bytes are stored in the Data field
	wrapper := &types.Key{
		ID:  dbKey.ID,
		ACL: dbKey.ACL,
		VersionList: types.KeyVersionList{
			{ID: 1, Data: data}, // Encrypted DBKey serialized here
		},
	}

	// Store using backend
	if err := a.backend.PutKey(ctx, wrapper); err != nil {
		return fmt.Errorf("backend update failed: %w", err)
	}

	// Invalidate cache
	a.invalidateCached(dbKey.ID)

	return nil
}

// Add adds new encrypted keys to storage.
// Each DBKey is serialized (containing encrypted EncData) and stored in the backend.
func (a *DBAdapter) Add(keys ...*keydb.DBKey) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, dbKey := range keys {
		// Check if key already exists
		_, err := a.backend.GetKey(ctx, dbKey.ID)
		if err == nil {
			return fmt.Errorf("key already exists: %s", dbKey.ID)
		}
		if err != ErrKeyNotFound {
			return fmt.Errorf("backend check failed: %w", err)
		}

		// Serialize the encrypted DBKey
		data, err := json.Marshal(dbKey)
		if err != nil {
			return fmt.Errorf("failed to serialize DBKey: %w", err)
		}

		// Wrap in types.Key for backend storage
		wrapper := &types.Key{
			ID:  dbKey.ID,
			ACL: dbKey.ACL,
			VersionList: types.KeyVersionList{
				{ID: 1, Data: data}, // Encrypted DBKey serialized here
			},
		}

		// Store using backend
		if err := a.backend.PutKey(ctx, wrapper); err != nil {
			return fmt.Errorf("backend add failed: %w", err)
		}

		// Cache the encrypted version
		a.setCached(dbKey.ID, dbKey)
	}

	return nil
}

// Remove deletes a key from storage.
func (a *DBAdapter) Remove(keyID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := a.backend.DeleteKey(ctx, keyID)
	if err == ErrKeyNotFound {
		// Key not found is not an error for delete
		return nil
	}
	if err != nil {
		return fmt.Errorf("backend delete failed: %w", err)
	}

	// Invalidate cache
	a.invalidateCached(keyID)

	return nil
}

// Cache management methods

func (a *DBAdapter) getCached(keyID string) *keydb.DBKey {
	a.mu.RLock()
	defer a.mu.RUnlock()

	cached, ok := a.cache[keyID]
	if !ok {
		return nil
	}

	// Check if expired
	if time.Now().After(cached.expiresAt) {
		return nil
	}

	return cached.key
}

func (a *DBAdapter) setCached(keyID string, dbKey *keydb.DBKey) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Cache for 5 minutes
	a.cache[keyID] = &cachedKey{
		key:       dbKey,
		expiresAt: time.Now().Add(5 * time.Minute),
	}

	// Cleanup old cache entries periodically
	if len(a.cache) > 1000 {
		a.cleanupCacheLocked()
	}
}

func (a *DBAdapter) invalidateCached(keyID string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	delete(a.cache, keyID)
}

func (a *DBAdapter) cleanupCacheLocked() {
	now := time.Now()
	for keyID, cached := range a.cache {
		if now.After(cached.expiresAt) {
			delete(a.cache, keyID)
		}
	}
}

// Verify interface compliance at compile time
var _ keydb.DB = (*DBAdapter)(nil)
