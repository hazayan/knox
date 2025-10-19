// Package storage provides an abstraction layer for Knox key storage backends.
package storage

import (
	"context"
	"errors"

	"github.com/hazayan/knox/pkg/types"
)

var (
	// ErrKeyNotFound is returned when a key does not exist in storage.
	ErrKeyNotFound = errors.New("key not found")

	// ErrKeyExists is returned when attempting to create a key that already exists.
	ErrKeyExists = errors.New("key already exists")

	// ErrTransactionNotSupported is returned when a backend doesn't support transactions.
	ErrTransactionNotSupported = errors.New("transactions not supported by this backend")

	// ErrStorageUnavailable is returned when the storage backend is unavailable.
	ErrStorageUnavailable = errors.New("storage backend unavailable")
)

// Backend defines the interface that all Knox storage backends must implement.
// Implementations must be safe for concurrent use by multiple goroutines.
type Backend interface {
	// GetKey retrieves a key by its ID. Returns ErrKeyNotFound if the key doesn't exist.
	GetKey(ctx context.Context, keyID string) (*types.Key, error)

	// PutKey stores or updates a key. The key must be valid (key.Validate() == nil).
	PutKey(ctx context.Context, key *types.Key) error

	// DeleteKey removes a key by its ID. Returns ErrKeyNotFound if the key doesn't exist.
	DeleteKey(ctx context.Context, keyID string) error

	// ListKeys returns all key IDs that match the given prefix.
	// If prefix is empty, returns all keys.
	// Results may be returned in any order.
	ListKeys(ctx context.Context, prefix string) ([]string, error)

	// UpdateKey atomically updates a key using the provided update function.
	// The update function receives the current key state and returns the new state.
	// If the key doesn't exist, the update function receives nil.
	// If the update function returns an error, the update is aborted.
	// This provides optimistic concurrency control.
	UpdateKey(ctx context.Context, keyID string, updateFn func(*types.Key) (*types.Key, error)) error

	// Ping checks if the storage backend is healthy and reachable.
	Ping(ctx context.Context) error

	// Close releases any resources held by the backend.
	Close() error
}

// TransactionalBackend extends Backend with transaction support.
// Not all backends need to implement this - it's optional for backends
// that can provide stronger consistency guarantees.
type TransactionalBackend interface {
	Backend

	// BeginTx starts a new transaction. All operations within the transaction
	// are isolated until Commit is called.
	BeginTx(ctx context.Context) (Transaction, error)
}

// Transaction represents an isolated set of storage operations.
// All methods must be called from the same goroutine that created the transaction.
type Transaction interface {
	// GetKey retrieves a key within the transaction context.
	GetKey(ctx context.Context, keyID string) (*types.Key, error)

	// PutKey stores or updates a key within the transaction context.
	PutKey(ctx context.Context, key *types.Key) error

	// DeleteKey removes a key within the transaction context.
	DeleteKey(ctx context.Context, keyID string) error

	// Commit applies all operations in the transaction atomically.
	// After Commit, the transaction cannot be used again.
	Commit() error

	// Rollback aborts all operations in the transaction.
	// After Rollback, the transaction cannot be used again.
	Rollback() error
}

// Config holds configuration for initializing a storage backend.
type Config struct {
	// Backend specifies which storage implementation to use.
	// Valid values: "memory", "filesystem", "postgres", "etcd"
	Backend string

	// Filesystem backend configuration
	FilesystemDir string

	// PostgreSQL backend configuration
	PostgresConnectionString string
	PostgresMaxConnections   int

	// etcd backend configuration
	EtcdEndpoints []string
	EtcdPrefix    string

	// Common configuration
	ReadOnly bool // If true, all write operations will fail
}

// BackendFactory is a function that creates a new backend instance.
type BackendFactory func(cfg Config) (Backend, error)

// Registry of available backend factories.
var backendRegistry = make(map[string]BackendFactory)

// RegisterBackend registers a new backend factory.
// This should be called by backend packages in their init() functions.
func RegisterBackend(name string, factory BackendFactory) {
	backendRegistry[name] = factory
}

// NewBackend creates a new storage backend based on the provided configuration.
func NewBackend(cfg Config) (Backend, error) {
	factory, exists := backendRegistry[cfg.Backend]
	if !exists {
		return nil, errors.New("unknown storage backend: " + cfg.Backend)
	}
	return factory(cfg)
}

// Stats provides metrics about the storage backend's performance and state.
type Stats struct {
	// TotalKeys is the approximate number of keys stored
	TotalKeys int64

	// StorageSize is the approximate size of stored data in bytes
	StorageSize int64

	// OperationCounts tracks the number of each operation type
	OperationCounts map[string]int64

	// Backend-specific metrics
	BackendSpecific map[string]interface{}
}

// StatsProvider is an optional interface that backends can implement
// to expose metrics about their internal state.
type StatsProvider interface {
	Stats(ctx context.Context) (*Stats, error)
}
