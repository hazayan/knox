// Package filesystem provides a filesystem-based storage backend for Knox.
// Keys are stored as JSON files in a directory structure.
// This backend is compatible with Knox's existing file cache format.
package filesystem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/hazayan/knox/pkg/types"
	"github.com/hazayan/knox/pkg/storage"
)

func init() {
	storage.RegisterBackend("filesystem", func(cfg storage.Config) (storage.Backend, error) {
		if cfg.FilesystemDir == "" {
			return nil, errors.New("filesystem backend requires FilesystemDir")
		}
		return New(cfg.FilesystemDir)
	})
}

// Backend implements storage.Backend using the filesystem.
type Backend struct {
	baseDir string

	// File locking to ensure safe concurrent access
	locks   map[string]*sync.RWMutex
	locksMu sync.Mutex

	// Metrics
	opCounts sync.Map // map[string]*int64
}

// New creates a new filesystem storage backend.
// The baseDir directory will be created if it doesn't exist.
func New(baseDir string) (*Backend, error) {
	// Ensure the directory exists
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	// Verify we can write to the directory
	testFile := filepath.Join(baseDir, ".knox-test")
	if err := os.WriteFile(testFile, []byte("test"), 0600); err != nil {
		return nil, fmt.Errorf("storage directory is not writable: %w", err)
	}
	os.Remove(testFile)

	return &Backend{
		baseDir: baseDir,
		locks:   make(map[string]*sync.RWMutex),
	}, nil
}

// GetKey retrieves a key by ID.
func (b *Backend) GetKey(ctx context.Context, keyID string) (*types.Key, error) {
	b.incrementOp("get")

	lock := b.getLock(keyID)
	lock.RLock()
	defer lock.RUnlock()

	path := b.keyPath(keyID)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, storage.ErrKeyNotFound
		}
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	var key types.Key
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key: %w", err)
	}

	// Store the file path in the key for compatibility with existing code
	key.Path = path

	return &key, nil
}

// PutKey stores or updates a key.
func (b *Backend) PutKey(ctx context.Context, key *types.Key) error {
	if err := key.Validate(); err != nil {
		return err
	}

	b.incrementOp("put")

	lock := b.getLock(key.ID)
	lock.Lock()
	defer lock.Unlock()

	path := b.keyPath(key.ID)

	// Marshal the key to JSON
	data, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	// Write atomically using a temporary file + rename
	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	if err := os.Rename(tempPath, path); err != nil {
		os.Remove(tempPath) // Clean up temp file
		return fmt.Errorf("failed to rename key file: %w", err)
	}

	return nil
}

// DeleteKey removes a key by ID.
func (b *Backend) DeleteKey(ctx context.Context, keyID string) error {
	b.incrementOp("delete")

	lock := b.getLock(keyID)
	lock.Lock()
	defer lock.Unlock()

	path := b.keyPath(keyID)

	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return storage.ErrKeyNotFound
		}
		return fmt.Errorf("failed to delete key file: %w", err)
	}

	return nil
}

// ListKeys returns all key IDs matching the given prefix.
func (b *Backend) ListKeys(ctx context.Context, prefix string) ([]string, error) {
	b.incrementOp("list")

	var keys []string

	err := filepath.Walk(b.baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and temp files
		if info.IsDir() || strings.HasSuffix(path, ".tmp") {
			return nil
		}

		// Extract the key ID from the file path
		relPath, err := filepath.Rel(b.baseDir, path)
		if err != nil {
			return err
		}

		// Use the relative path as the key ID
		keyID := relPath

		// Apply prefix filter
		if prefix == "" || strings.HasPrefix(keyID, prefix) {
			keys = append(keys, keyID)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	return keys, nil
}

// UpdateKey atomically updates a key using the provided update function.
func (b *Backend) UpdateKey(ctx context.Context, keyID string, updateFn func(*types.Key) (*types.Key, error)) error {
	b.incrementOp("update")

	lock := b.getLock(keyID)
	lock.Lock()
	defer lock.Unlock()

	// Get current key (or nil if it doesn't exist)
	var currentKey *types.Key
	path := b.keyPath(keyID)
	data, err := os.ReadFile(path)
	if err == nil {
		var key types.Key
		if err := json.Unmarshal(data, &key); err != nil {
			return fmt.Errorf("failed to unmarshal existing key: %w", err)
		}
		currentKey = &key
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read existing key: %w", err)
	}

	// Apply the update function
	newKey, err := updateFn(currentKey)
	if err != nil {
		return err
	}

	// Handle the result
	if newKey != nil {
		// Validate the new key
		if err := newKey.Validate(); err != nil {
			return err
		}

		// Ensure the key ID hasn't changed
		if newKey.ID != keyID {
			return types.ErrInvalidKeyID
		}

		// Write the updated key
		data, err := json.MarshalIndent(newKey, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal updated key: %w", err)
		}

		tempPath := path + ".tmp"
		if err := os.WriteFile(tempPath, data, 0600); err != nil {
			return fmt.Errorf("failed to write updated key: %w", err)
		}

		if err := os.Rename(tempPath, path); err != nil {
			os.Remove(tempPath)
			return fmt.Errorf("failed to rename updated key: %w", err)
		}
	} else {
		// Delete the key
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to delete key: %w", err)
		}
	}

	return nil
}

// Ping checks if the backend is healthy.
func (b *Backend) Ping(ctx context.Context) error {
	// Check if the base directory is accessible
	if _, err := os.Stat(b.baseDir); err != nil {
		return storage.ErrStorageUnavailable
	}

	// Try to write a test file
	testPath := filepath.Join(b.baseDir, ".knox-health")
	if err := os.WriteFile(testPath, []byte("health-check"), 0600); err != nil {
		return storage.ErrStorageUnavailable
	}
	os.Remove(testPath)

	return nil
}

// Close releases any resources held by the backend.
func (b *Backend) Close() error {
	// No resources to release for filesystem backend
	return nil
}

// Stats returns metrics about the backend's state.
func (b *Backend) Stats(ctx context.Context) (*storage.Stats, error) {
	var totalKeys int64
	var totalSize int64

	err := filepath.Walk(b.baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && !strings.HasSuffix(path, ".tmp") {
			totalKeys++
			totalSize += info.Size()
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to calculate stats: %w", err)
	}

	// Collect operation counts
	opCounts := make(map[string]int64)
	b.opCounts.Range(func(key, value interface{}) bool {
		opCounts[key.(string)] = atomic.LoadInt64(value.(*int64))
		return true
	})

	return &storage.Stats{
		TotalKeys:       totalKeys,
		StorageSize:     totalSize,
		OperationCounts: opCounts,
		BackendSpecific: map[string]interface{}{
			"backend":  "filesystem",
			"base_dir": b.baseDir,
		},
	}, nil
}

// keyPath returns the filesystem path for a given key ID.
// It validates the key ID to prevent path traversal attacks.
func (b *Backend) keyPath(keyID string) string {
	// Sanitize the key ID to prevent path traversal
	// Replace potentially dangerous characters
	safeKeyID := sanitizeKeyID(keyID)

	// Build the full path
	fullPath := filepath.Join(b.baseDir, safeKeyID)

	// Clean the path to resolve any .. or . components
	fullPath = filepath.Clean(fullPath)

	// Verify the path is still within baseDir (prevent escaping)
	if !strings.HasPrefix(fullPath, filepath.Clean(b.baseDir)+string(filepath.Separator)) &&
		fullPath != filepath.Clean(b.baseDir) {
		// Path escape attempt detected - use hash of keyID as filename
		// This ensures we can still store the key, but safely
		return filepath.Join(b.baseDir, hashKeyID(keyID))
	}

	return fullPath
}

// sanitizeKeyID removes or replaces dangerous characters in key IDs.
func sanitizeKeyID(keyID string) string {
	// Replace path separators with underscores
	safe := strings.ReplaceAll(keyID, string(filepath.Separator), "_")
	safe = strings.ReplaceAll(safe, "/", "_")
	safe = strings.ReplaceAll(safe, "\\", "_")

	// Remove null bytes
	safe = strings.ReplaceAll(safe, "\x00", "")

	// Remove parent directory references
	safe = strings.ReplaceAll(safe, "..", "_")

	// Limit length to prevent filesystem issues
	if len(safe) > 255 {
		safe = safe[:255]
	}

	return safe
}

// hashKeyID creates a safe filename from a key ID using SHA256.
func hashKeyID(keyID string) string {
	h := sha256.Sum256([]byte(keyID))
	return hex.EncodeToString(h[:])
}

// getLock returns a mutex for the given key ID.
func (b *Backend) getLock(keyID string) *sync.RWMutex {
	b.locksMu.Lock()
	defer b.locksMu.Unlock()

	if lock, exists := b.locks[keyID]; exists {
		return lock
	}

	lock := &sync.RWMutex{}
	b.locks[keyID] = lock
	return lock
}

// incrementOp increments the counter for a given operation type.
func (b *Backend) incrementOp(op string) {
	val, _ := b.opCounts.LoadOrStore(op, new(int64))
	atomic.AddInt64(val.(*int64), 1)
}

// Verify that Backend implements the required interfaces at compile time.
var _ storage.Backend = (*Backend)(nil)
var _ storage.StatsProvider = (*Backend)(nil)
