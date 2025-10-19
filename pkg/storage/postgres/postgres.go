// Package postgres provides a PostgreSQL-based storage backend for Knox.
// This backend is suitable for production use with high availability requirements.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/hazayan/knox/pkg/storage"
	"github.com/hazayan/knox/pkg/types"
	_ "github.com/lib/pq" // PostgreSQL driver
)

func init() {
	storage.RegisterBackend("postgres", func(cfg storage.Config) (storage.Backend, error) {
		if cfg.PostgresConnectionString == "" {
			return nil, errors.New("postgres backend requires PostgresConnectionString")
		}
		return New(cfg.PostgresConnectionString, cfg.PostgresMaxConnections)
	})
}

// Backend implements storage.Backend using PostgreSQL.
type Backend struct {
	db *sql.DB

	// Metrics
	opCounts map[string]*int64
}

// New creates a new PostgreSQL storage backend.
// The connection string should be in the format:
// "postgres://user:password@host:port/database?sslmode=require"
func New(connectionString string, maxConnections int) (*Backend, error) {
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool with production-ready settings
	if maxConnections <= 0 {
		maxConnections = 25 // Default: conservative for production
	}

	// Max open connections: total connections to database
	db.SetMaxOpenConns(maxConnections)

	// Max idle connections: keep half as idle for quick reuse
	db.SetMaxIdleConns(maxConnections / 2)

	// Max connection lifetime: rotate connections every hour to prevent stale connections
	db.SetConnMaxLifetime(1 * time.Hour)

	// Max connection idle time: close idle connections after 10 minutes
	db.SetConnMaxIdleTime(10 * time.Minute)

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	b := &Backend{
		db: db,
		opCounts: map[string]*int64{
			"get":    new(int64),
			"put":    new(int64),
			"delete": new(int64),
			"list":   new(int64),
			"update": new(int64),
		},
	}

	// Initialize schema
	if err := b.initSchema(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return b, nil
}

// initSchema creates the necessary tables if they don't exist.
func (b *Backend) initSchema(ctx context.Context) error {
	schema := `
	CREATE TABLE IF NOT EXISTS knox_keys (
		key_id TEXT PRIMARY KEY,
		key_data JSONB NOT NULL,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_knox_keys_key_id_prefix ON knox_keys USING btree (key_id text_pattern_ops);
	CREATE INDEX IF NOT EXISTS idx_knox_keys_updated_at ON knox_keys (updated_at);
	`

	_, err := b.db.ExecContext(ctx, schema)
	return err
}

// GetKey retrieves a key by ID.
func (b *Backend) GetKey(ctx context.Context, keyID string) (*types.Key, error) {
	atomic.AddInt64(b.opCounts["get"], 1)

	var keyData []byte
	err := b.db.QueryRowContext(ctx,
		"SELECT key_data FROM knox_keys WHERE key_id = $1",
		keyID,
	).Scan(&keyData)

	if err == sql.ErrNoRows {
		return nil, storage.ErrKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query key: %w", err)
	}

	var key types.Key
	if err := json.Unmarshal(keyData, &key); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key: %w", err)
	}

	return &key, nil
}

// PutKey stores or updates a key.
func (b *Backend) PutKey(ctx context.Context, key *types.Key) error {
	if err := key.Validate(); err != nil {
		return err
	}

	atomic.AddInt64(b.opCounts["put"], 1)

	keyData, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	_, err = b.db.ExecContext(ctx,
		`INSERT INTO knox_keys (key_id, key_data, updated_at)
		 VALUES ($1, $2, NOW())
		 ON CONFLICT (key_id)
		 DO UPDATE SET key_data = $2, updated_at = NOW()`,
		key.ID, keyData,
	)
	if err != nil {
		return fmt.Errorf("failed to upsert key: %w", err)
	}

	return nil
}

// DeleteKey removes a key by ID.
func (b *Backend) DeleteKey(ctx context.Context, keyID string) error {
	atomic.AddInt64(b.opCounts["delete"], 1)

	result, err := b.db.ExecContext(ctx,
		"DELETE FROM knox_keys WHERE key_id = $1",
		keyID,
	)
	if err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return storage.ErrKeyNotFound
	}

	return nil
}

// ListKeys returns all key IDs matching the given prefix.
func (b *Backend) ListKeys(ctx context.Context, prefix string) ([]string, error) {
	atomic.AddInt64(b.opCounts["list"], 1)

	var rows *sql.Rows
	var err error

	if prefix == "" {
		rows, err = b.db.QueryContext(ctx,
			"SELECT key_id FROM knox_keys ORDER BY key_id",
		)
	} else {
		// Use LIKE with text_pattern_ops index for efficient prefix search
		rows, err = b.db.QueryContext(ctx,
			"SELECT key_id FROM knox_keys WHERE key_id LIKE $1 ORDER BY key_id",
			prefix+"%",
		)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to query keys: %w", err)
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var keyID string
		if err := rows.Scan(&keyID); err != nil {
			return nil, fmt.Errorf("failed to scan key ID: %w", err)
		}
		keys = append(keys, keyID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating keys: %w", err)
	}

	return keys, nil
}

// UpdateKey atomically updates a key using the provided update function.
func (b *Backend) UpdateKey(ctx context.Context, keyID string, updateFn func(*types.Key) (*types.Key, error)) error {
	atomic.AddInt64(b.opCounts["update"], 1)

	// Start a transaction
	tx, err := b.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Get current key with row lock
	var keyData []byte
	err = tx.QueryRowContext(ctx,
		"SELECT key_data FROM knox_keys WHERE key_id = $1 FOR UPDATE",
		keyID,
	).Scan(&keyData)

	var currentKey *types.Key
	if err == nil {
		var key types.Key
		if err := json.Unmarshal(keyData, &key); err != nil {
			return fmt.Errorf("failed to unmarshal existing key: %w", err)
		}
		currentKey = &key
	} else if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to query key: %w", err)
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

		// Marshal and store the updated key
		newKeyData, err := json.Marshal(newKey)
		if err != nil {
			return fmt.Errorf("failed to marshal updated key: %w", err)
		}

		_, err = tx.ExecContext(ctx,
			`INSERT INTO knox_keys (key_id, key_data, updated_at)
			 VALUES ($1, $2, NOW())
			 ON CONFLICT (key_id)
			 DO UPDATE SET key_data = $2, updated_at = NOW()`,
			keyID, newKeyData,
		)
		if err != nil {
			return fmt.Errorf("failed to update key: %w", err)
		}
	} else {
		// Delete the key
		_, err = tx.ExecContext(ctx,
			"DELETE FROM knox_keys WHERE key_id = $1",
			keyID,
		)
		if err != nil {
			return fmt.Errorf("failed to delete key: %w", err)
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// Ping checks if the backend is healthy.
func (b *Backend) Ping(ctx context.Context) error {
	if err := b.db.PingContext(ctx); err != nil {
		return storage.ErrStorageUnavailable
	}
	return nil
}

// Close releases any resources held by the backend.
func (b *Backend) Close() error {
	return b.db.Close()
}

// Stats returns metrics about the backend's state.
func (b *Backend) Stats(ctx context.Context) (*storage.Stats, error) {
	var totalKeys int64
	err := b.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM knox_keys",
	).Scan(&totalKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to count keys: %w", err)
	}

	// Get approximate storage size
	var totalSize sql.NullInt64
	err = b.db.QueryRowContext(ctx,
		"SELECT pg_total_relation_size('knox_keys')",
	).Scan(&totalSize)
	if err != nil {
		// Non-fatal, just log and continue
		totalSize.Valid = false
	}

	// Collect operation counts
	opCounts := make(map[string]int64)
	for op, count := range b.opCounts {
		opCounts[op] = atomic.LoadInt64(count)
	}

	// Get database stats
	dbStats := b.db.Stats()

	stats := &storage.Stats{
		TotalKeys:       totalKeys,
		OperationCounts: opCounts,
		BackendSpecific: map[string]interface{}{
			"backend":          "postgres",
			"open_connections": dbStats.OpenConnections,
			"in_use":           dbStats.InUse,
			"idle":             dbStats.Idle,
			"wait_count":       dbStats.WaitCount,
			"wait_duration":    dbStats.WaitDuration.String(),
		},
	}

	if totalSize.Valid {
		stats.StorageSize = totalSize.Int64
	}

	return stats, nil
}

// Transaction represents a PostgreSQL transaction.
type Transaction struct {
	tx        *sql.Tx
	backend   *Backend
	committed bool
}

// BeginTx starts a new transaction.
func (b *Backend) BeginTx(ctx context.Context) (storage.Transaction, error) {
	tx, err := b.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	return &Transaction{
		tx:      tx,
		backend: b,
	}, nil
}

// GetKey retrieves a key within the transaction.
func (t *Transaction) GetKey(ctx context.Context, keyID string) (*types.Key, error) {
	var keyData []byte
	err := t.tx.QueryRowContext(ctx,
		"SELECT key_data FROM knox_keys WHERE key_id = $1 FOR UPDATE",
		keyID,
	).Scan(&keyData)

	if err == sql.ErrNoRows {
		return nil, storage.ErrKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query key: %w", err)
	}

	var key types.Key
	if err := json.Unmarshal(keyData, &key); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key: %w", err)
	}

	return &key, nil
}

// PutKey stores or updates a key within the transaction.
func (t *Transaction) PutKey(ctx context.Context, key *types.Key) error {
	if err := key.Validate(); err != nil {
		return err
	}

	keyData, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	_, err = t.tx.ExecContext(ctx,
		`INSERT INTO knox_keys (key_id, key_data, updated_at)
		 VALUES ($1, $2, NOW())
		 ON CONFLICT (key_id)
		 DO UPDATE SET key_data = $2, updated_at = NOW()`,
		key.ID, keyData,
	)
	if err != nil {
		return fmt.Errorf("failed to upsert key: %w", err)
	}

	return nil
}

// DeleteKey removes a key within the transaction.
func (t *Transaction) DeleteKey(ctx context.Context, keyID string) error {
	result, err := t.tx.ExecContext(ctx,
		"DELETE FROM knox_keys WHERE key_id = $1",
		keyID,
	)
	if err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return storage.ErrKeyNotFound
	}

	return nil
}

// Commit applies all operations in the transaction atomically.
func (t *Transaction) Commit() error {
	if t.commited {
		return errors.New("transaction already committed")
	}
	t.commited = true
	return t.tx.Commit()
}

// Rollback aborts all operations in the transaction.
func (t *Transaction) Rollback() error {
	if t.commited {
		return nil // Already committed, nothing to rollback
	}
	return t.tx.Rollback()
}

// Verify that Backend implements the required interfaces at compile time.
var (
	_ storage.Backend              = (*Backend)(nil)
	_ storage.TransactionalBackend = (*Backend)(nil)
	_ storage.StatsProvider        = (*Backend)(nil)
	_ storage.Transaction          = (*Transaction)(nil)
)
