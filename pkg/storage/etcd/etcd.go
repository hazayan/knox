// Package etcd provides an etcd-based storage backend for Knox.
// This backend is suitable for distributed deployments requiring high availability,
// strong consistency, and coordination across multiple instances.
package etcd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hazayan/knox/pkg/storage"
	"github.com/hazayan/knox/pkg/types"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
)

func init() {
	storage.RegisterBackend("etcd", func(cfg storage.Config) (storage.Backend, error) {
		if len(cfg.EtcdEndpoints) == 0 {
			return nil, errors.New("etcd backend requires EtcdEndpoints")
		}
		return New(cfg.EtcdEndpoints, cfg.EtcdPrefix, cfg.ReadOnly)
	})
}

// Backend implements storage.Backend using etcd with support for transactions.
type Backend struct {
	client   *clientv3.Client
	prefix   string
	readOnly bool

	// Metrics
	opCounts map[string]*int64

	// Session for distributed locks
	session *concurrency.Session
}

// New creates a new etcd storage backend with production-ready configuration.
// endpoints: list of etcd endpoints (e.g., ["http://etcd1:2379", "http://etcd2:2379"])
// prefix: base path for all keys (e.g., "/knox/keys")
// readOnly: if true, all write operations will fail.
func New(endpoints []string, prefix string, readOnly bool) (*Backend, error) {
	if prefix == "" {
		prefix = "/knox"
	}
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}

	// Production-ready etcd client configuration
	config := clientv3.Config{
		Endpoints:            endpoints,
		DialTimeout:          5 * time.Second,
		DialKeepAliveTime:    30 * time.Second,
		DialKeepAliveTimeout: 10 * time.Second,
		AutoSyncInterval:     30 * time.Second,
		RejectOldCluster:     true, // Prevent connecting to outdated clusters
	}

	client, err := clientv3.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create etcd client: %w", err)
	}

	// Create session for distributed locks
	session, err := concurrency.NewSession(client, concurrency.WithTTL(30))
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to create etcd session: %w", err)
	}

	// Initialize operation counters
	opCounts := make(map[string]*int64)
	for _, op := range []string{"get", "put", "delete", "list", "update", "ping"} {
		var count int64
		opCounts[op] = &count
	}

	backend := &Backend{
		client:   client,
		prefix:   prefix,
		readOnly: readOnly,
		opCounts: opCounts,
		session:  session,
	}

	// Verify connectivity and permissions
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := backend.Ping(ctx); err != nil {
		backend.Close()
		return nil, fmt.Errorf("etcd connectivity test failed: %w", err)
	}

	return backend, nil
}

// buildKeyPath constructs the full etcd key path for a given key ID.
func (b *Backend) buildKeyPath(keyID string) string {
	return path.Join(b.prefix, "keys", keyID)
}

// buildLockPath constructs the path for distributed locks.
func (b *Backend) buildLockPath(keyID string) string {
	return path.Join(b.prefix, "locks", keyID)
}

// incrementOpCount safely increments the operation counter.
func (b *Backend) incrementOpCount(op string) {
	if counter, exists := b.opCounts[op]; exists {
		atomic.AddInt64(counter, 1)
	}
}

// GetKey retrieves a key by its ID from etcd.
func (b *Backend) GetKey(ctx context.Context, keyID string) (*types.Key, error) {
	b.incrementOpCount("get")

	if keyID == "" {
		return nil, errors.New("key ID cannot be empty")
	}

	resp, err := b.client.Get(ctx, b.buildKeyPath(keyID))
	if err != nil {
		return nil, fmt.Errorf("etcd get failed: %w", err)
	}

	if len(resp.Kvs) == 0 {
		return nil, storage.ErrKeyNotFound
	}

	var key types.Key
	if err := json.Unmarshal(resp.Kvs[0].Value, &key); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key: %w", err)
	}

	return &key, nil
}

// PutKey stores or updates a key in etcd.
func (b *Backend) PutKey(ctx context.Context, key *types.Key) error {
	b.incrementOpCount("put")

	if b.readOnly {
		return errors.New("backend is read-only")
	}

	if key == nil {
		return errors.New("key cannot be nil")
	}

	if err := key.Validate(); err != nil {
		return fmt.Errorf("invalid key: %w", err)
	}

	// Serialize key to JSON
	data, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	// Use distributed lock to prevent concurrent modifications
	mutex := concurrency.NewMutex(b.session, b.buildLockPath(key.ID))
	if err := mutex.Lock(ctx); err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() {
		if unlockErr := mutex.Unlock(ctx); unlockErr != nil {
			log.Printf("warning: failed to unlock mutex for key %s: %v", key.ID, unlockErr)
		}
	}()

	// Check if key already exists for proper error reporting
	resp, err := b.client.Get(ctx, b.buildKeyPath(key.ID))
	if err != nil {
		return fmt.Errorf("etcd get failed during put: %w", err)
	}

	if len(resp.Kvs) > 0 {
		return storage.ErrKeyExists
	}

	// Put the key with lease to enable automatic cleanup if needed
	_, err = b.client.Put(ctx, b.buildKeyPath(key.ID), string(data))
	if err != nil {
		return fmt.Errorf("etcd put failed: %w", err)
	}

	return nil
}

// DeleteKey removes a key from etcd.
func (b *Backend) DeleteKey(ctx context.Context, keyID string) error {
	b.incrementOpCount("delete")

	if b.readOnly {
		return errors.New("backend is read-only")
	}

	if keyID == "" {
		return errors.New("key ID cannot be empty")
	}

	// Use distributed lock to prevent concurrent modifications
	mutex := concurrency.NewMutex(b.session, b.buildLockPath(keyID))
	if err := mutex.Lock(ctx); err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() {
		if unlockErr := mutex.Unlock(ctx); unlockErr != nil {
			log.Printf("warning: failed to unlock mutex for key %s: %v", keyID, unlockErr)
		}
	}()

	// Check if key exists first
	resp, err := b.client.Get(ctx, b.buildKeyPath(keyID))
	if err != nil {
		return fmt.Errorf("etcd get failed during delete: %w", err)
	}

	if len(resp.Kvs) == 0 {
		return storage.ErrKeyNotFound
	}

	// Delete the key
	_, err = b.client.Delete(ctx, b.buildKeyPath(keyID))
	if err != nil {
		return fmt.Errorf("etcd delete failed: %w", err)
	}

	return nil
}

// ListKeys returns all key IDs that match the given prefix.
func (b *Backend) ListKeys(ctx context.Context, prefix string) ([]string, error) {
	b.incrementOpCount("list")

	searchPath := b.buildKeyPath("")
	if prefix != "" {
		searchPath = b.buildKeyPath(prefix)
	}

	// Use WithPrefix to get all keys under the search path
	resp, err := b.client.Get(ctx, searchPath, clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("etcd list failed: %w", err)
	}

	keys := make([]string, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		// Extract key ID from full path
		fullPath := string(kv.Key)
		keyID := strings.TrimPrefix(fullPath, b.buildKeyPath(""))
		if keyID != "" {
			keys = append(keys, keyID)
		}
	}

	return keys, nil
}

// UpdateKey atomically updates a key using etcd transactions.
func (b *Backend) UpdateKey(ctx context.Context, keyID string, updateFn func(*types.Key) (*types.Key, error)) error {
	b.incrementOpCount("update")

	if b.readOnly {
		return errors.New("backend is read-only")
	}

	if keyID == "" {
		return errors.New("key ID cannot be empty")
	}

	if updateFn == nil {
		return errors.New("update function cannot be nil")
	}

	// Use distributed lock for the entire update operation
	mutex := concurrency.NewMutex(b.session, b.buildLockPath(keyID))
	if err := mutex.Lock(ctx); err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() {
		if unlockErr := mutex.Unlock(ctx); unlockErr != nil {
			log.Printf("warning: failed to unlock mutex for key %s: %v", keyID, unlockErr)
		}
	}()

	// Get current key state
	var currentKey *types.Key
	resp, err := b.client.Get(ctx, b.buildKeyPath(keyID))
	if err != nil {
		return fmt.Errorf("etcd get failed during update: %w", err)
	}

	if len(resp.Kvs) > 0 {
		currentKey = &types.Key{}
		if err := json.Unmarshal(resp.Kvs[0].Value, currentKey); err != nil {
			return fmt.Errorf("failed to unmarshal current key: %w", err)
		}
	}

	// Apply update function
	newKey, err := updateFn(currentKey)
	if err != nil {
		return fmt.Errorf("update function failed: %w", err)
	}

	if newKey == nil {
		// Update function returned nil, meaning delete the key
		if currentKey != nil {
			_, err = b.client.Delete(ctx, b.buildKeyPath(keyID))
			if err != nil {
				return fmt.Errorf("etcd delete failed: %w", err)
			}
		}
		return nil
	}

	// Validate the new key
	if err := newKey.Validate(); err != nil {
		return fmt.Errorf("invalid updated key: %w", err)
	}

	// Ensure key ID consistency
	if newKey.ID != keyID {
		return errors.New("update function changed key ID")
	}

	// Serialize new key
	data, err := json.Marshal(newKey)
	if err != nil {
		return fmt.Errorf("failed to marshal updated key: %w", err)
	}

	// Use transaction for atomic update
	txnResp, err := b.client.Txn(ctx).
		If(clientv3.Compare(clientv3.Version(b.buildKeyPath(keyID)), "=", resp.Kvs[0].Version)).
		Then(clientv3.OpPut(b.buildKeyPath(keyID), string(data))).
		Commit()
	if err != nil {
		return fmt.Errorf("etcd transaction failed: %w", err)
	}

	if !txnResp.Succeeded {
		return errors.New("concurrent modification detected, update aborted")
	}

	return nil
}

// Ping checks etcd connectivity and cluster health.
func (b *Backend) Ping(ctx context.Context) error {
	b.incrementOpCount("ping")

	// Use a short timeout for health checks
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Get cluster member list to verify connectivity
	_, err := b.client.MemberList(pingCtx)
	if err != nil {
		return fmt.Errorf("etcd cluster unreachable: %w", err)
	}

	// Try to read a key to verify read permissions
	_, err = b.client.Get(pingCtx, b.buildKeyPath("healthcheck"), clientv3.WithLimit(1))
	if err != nil {
		return fmt.Errorf("etcd read permission check failed: %w", err)
	}

	// If not read-only, try a write to verify write permissions
	if !b.readOnly {
		lease, err := b.client.Grant(pingCtx, 1) // 1 second TTL
		if err != nil {
			return fmt.Errorf("etcd write permission check failed: %w", err)
		}

		// Clean up the test key immediately
		_, err = b.client.Put(pingCtx, b.buildKeyPath("healthcheck"), "test", clientv3.WithLease(lease.ID))
		if err != nil {
			return fmt.Errorf("etcd write permission check failed: %w", err)
		}
	}

	return nil
}

// Close releases etcd client resources.
func (b *Backend) Close() error {
	if b.session != nil {
		b.session.Close()
	}
	if b.client != nil {
		return b.client.Close()
	}
	return nil
}

// BeginTx starts a new etcd transaction.
func (b *Backend) BeginTx(ctx context.Context) (storage.Transaction, error) {
	return &EtcdTransaction{
		backend: b,
		ctx:     ctx,
	}, nil
}

// EtcdTransaction implements storage.Transaction for etcd.
type EtcdTransaction struct {
	backend *Backend
	ctx     context.Context

	ops []clientv3.Op
}

// GetKey retrieves a key within the transaction context.
func (tx *EtcdTransaction) GetKey(ctx context.Context, keyID string) (*types.Key, error) {
	return tx.backend.GetKey(ctx, keyID)
}

// PutKey stores or updates a key within the transaction context.
func (tx *EtcdTransaction) PutKey(_ context.Context, key *types.Key) error {
	if tx.backend.readOnly {
		return errors.New("backend is read-only")
	}

	if key == nil {
		return errors.New("key cannot be nil")
	}

	if err := key.Validate(); err != nil {
		return fmt.Errorf("invalid key: %w", err)
	}

	data, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	tx.ops = append(tx.ops, clientv3.OpPut(tx.backend.buildKeyPath(key.ID), string(data)))
	return nil
}

// DeleteKey removes a key within the transaction context.
func (tx *EtcdTransaction) DeleteKey(_ context.Context, keyID string) error {
	if tx.backend.readOnly {
		return errors.New("backend is read-only")
	}

	if keyID == "" {
		return errors.New("key ID cannot be empty")
	}

	tx.ops = append(tx.ops, clientv3.OpDelete(tx.backend.buildKeyPath(keyID)))
	return nil
}

// Commit applies all operations in the transaction atomically.
func (tx *EtcdTransaction) Commit() error {
	if len(tx.ops) == 0 {
		return nil
	}

	txn := tx.backend.client.Txn(tx.ctx)
	for _, op := range tx.ops {
		txn = txn.Then(op)
	}

	_, err := txn.Commit()
	if err != nil {
		return fmt.Errorf("etcd transaction commit failed: %w", err)
	}

	return nil
}

// Rollback aborts the transaction.
func (tx *EtcdTransaction) Rollback() error {
	// etcd transactions are automatically rolled back if not committed
	tx.ops = nil
	return nil
}

// Stats returns metrics about the etcd backend.
func (b *Backend) Stats(ctx context.Context) (*storage.Stats, error) {
	// Get total key count
	keys, err := b.ListKeys(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to list keys for stats: %w", err)
	}

	// Get cluster status for backend-specific metrics
	memberList, err := b.client.MemberList(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster status: %w", err)
	}

	backendSpecific := map[string]any{
		"cluster_size":  len(memberList.Members),
		"endpoints":     b.client.Endpoints(),
		"session_alive": b.session != nil,
	}

	// Collect operation counts
	opCounts := make(map[string]int64)
	for op, counter := range b.opCounts {
		opCounts[op] = atomic.LoadInt64(counter)
	}

	return &storage.Stats{
		TotalKeys:       int64(len(keys)),
		StorageSize:     0, // etcd doesn't provide easy size metrics
		OperationCounts: opCounts,
		BackendSpecific: backendSpecific,
	}, nil
}
