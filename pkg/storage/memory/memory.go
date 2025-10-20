// Package memory provides an in-memory storage backend for Knox.
// This backend is primarily intended for testing and development.
// All data is lost when the process terminates.
package memory

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	"github.com/hazayan/knox/pkg/storage"
	"github.com/hazayan/knox/pkg/types"
)

func init() {
	storage.RegisterBackend("memory", func(_ storage.Config) (storage.Backend, error) {
		return New(), nil
	})
}

// Backend implements storage.Backend using an in-memory map.
type Backend struct {
	mu   sync.RWMutex
	data map[string]*types.Key

	// Metrics
	opCounts map[string]int64
}

// New creates a new in-memory storage backend.
func New() *Backend {
	return &Backend{
		data:     make(map[string]*types.Key),
		opCounts: make(map[string]int64),
	}
}

// NewBackend creates a new in-memory storage backend.
// Deprecated: Use New() instead.
func NewBackend() *Backend {
	return New()
}

// GetKey retrieves a key by ID.
func (b *Backend) GetKey(_ context.Context, keyID string) (*types.Key, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	b.opCounts["get"]++

	key, exists := b.data[keyID]
	if !exists {
		return nil, storage.ErrKeyNotFound
	}

	// Return a deep copy to prevent external modifications
	return b.copyKey(key), nil
}

// PutKey stores or updates a key.
func (b *Backend) PutKey(_ context.Context, key *types.Key) error {
	if err := key.Validate(); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.opCounts["put"]++

	// Store a deep copy to prevent external modifications
	b.data[key.ID] = b.copyKey(key)
	return nil
}

// DeleteKey removes a key by ID.
func (b *Backend) DeleteKey(_ context.Context, keyID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.opCounts["delete"]++

	if _, exists := b.data[keyID]; !exists {
		return storage.ErrKeyNotFound
	}

	delete(b.data, keyID)
	return nil
}

// ListKeys returns all keys with the given prefix.
func (b *Backend) ListKeys(_ context.Context, prefix string) ([]string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	b.opCounts["list"]++

	var keys []string
	for keyID := range b.data {
		if prefix == "" || strings.HasPrefix(keyID, prefix) {
			keys = append(keys, keyID)
		}
	}

	return keys, nil
}

// UpdateKey atomically updates a key using the provided update function.
func (b *Backend) UpdateKey(_ context.Context, keyID string, updateFn func(*types.Key) (*types.Key, error)) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.opCounts["update"]++

	// Get current key (or nil if it doesn't exist)
	var currentKey *types.Key
	if key, exists := b.data[keyID]; exists {
		currentKey = b.copyKey(key)
	}

	// Apply the update function
	newKey, err := updateFn(currentKey)
	if err != nil {
		return err
	}

	// Validate the new key
	if newKey != nil {
		if err := newKey.Validate(); err != nil {
			return err
		}

		// Ensure the key ID hasn't changed
		if newKey.ID != keyID {
			return types.ErrInvalidKeyID
		}

		// Store the updated key
		b.data[keyID] = b.copyKey(newKey)
	} else {
		// If updateFn returned nil, delete the key
		delete(b.data, keyID)
	}

	return nil
}

// Ping checks if the backend is healthy.
func (b *Backend) Ping(_ context.Context) error {
	// Memory backend is always healthy
	return nil
}

// Close releases any resources held by the backend.
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Clear the data
	b.data = make(map[string]*types.Key)
	b.opCounts = make(map[string]int64)
	return nil
}

// Stats returns metrics about the backend's state.
func (b *Backend) Stats(_ context.Context) (*storage.Stats, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Calculate approximate storage size
	var totalSize int64
	for _, key := range b.data {
		// Rough estimate: JSON size of the key
		if data, err := json.Marshal(key); err == nil {
			totalSize += int64(len(data))
		}
	}

	// Copy operation counts
	opCounts := make(map[string]int64)
	for op, count := range b.opCounts {
		opCounts[op] = count
	}

	return &storage.Stats{
		TotalKeys:       int64(len(b.data)),
		StorageSize:     totalSize,
		OperationCounts: opCounts,
		BackendSpecific: map[string]any{
			"backend": "memory",
		},
	}, nil
}

// copyKey creates a deep copy of a key.
func (b *Backend) copyKey(key *types.Key) *types.Key {
	if key == nil {
		return nil
	}

	// Deep copy via JSON marshal/unmarshal
	// This is simple but not the most efficient; could be optimized later
	data, err := json.Marshal(key)
	if err != nil {
		// Should never happen for valid Knox keys
		panic("failed to marshal key: " + err.Error())
	}

	var keyCopy types.Key
	if err := json.Unmarshal(data, &keyCopy); err != nil {
		// Should never happen for valid Knox keys
		panic("failed to unmarshal key: " + err.Error())
	}

	return &keyCopy
}

// Verify that Backend implements the required interfaces at compile time.
var (
	_ storage.Backend       = (*Backend)(nil)
	_ storage.StatsProvider = (*Backend)(nil)
)
