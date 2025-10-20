package orm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/hazayan/knox/pkg/storage"
	"github.com/hazayan/knox/pkg/types"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Backend implements storage.Backend using GORM for database abstraction.
// This backend is database-agnostic and works with PostgreSQL, MySQL, SQLite, etc.
type Backend struct {
	db *gorm.DB

	// Metrics
	opCounts map[string]*int64
}

// New creates a new GORM-based storage backend.
// The db parameter should be a configured GORM database connection.
func New(db *gorm.DB) (*Backend, error) {
	if db == nil {
		return nil, errors.New("db cannot be nil")
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

	// Auto-migrate the schema
	if err := db.AutoMigrate(&KeyRecord{}); err != nil {
		return nil, fmt.Errorf("failed to migrate schema: %w", err)
	}

	return b, nil
}

// GetKey retrieves a key by ID.
func (b *Backend) GetKey(ctx context.Context, keyID string) (*types.Key, error) {
	atomic.AddInt64(b.opCounts["get"], 1)

	var record KeyRecord
	result := b.db.WithContext(ctx).Where("key_id = ?", keyID).First(&record)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, storage.ErrKeyNotFound
		}
		return nil, fmt.Errorf("failed to query key: %w", result.Error)
	}

	return record.ToKey()
}

// PutKey stores or updates a key.
func (b *Backend) PutKey(ctx context.Context, key *types.Key) error {
	if err := key.Validate(); err != nil {
		return err
	}

	atomic.AddInt64(b.opCounts["put"], 1)

	record, err := NewKeyRecord(key)
	if err != nil {
		return fmt.Errorf("failed to create key record: %w", err)
	}

	// Use GORM's Clauses for upsert (works across all databases)
	result := b.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"key_data", "updated_at"}),
	}).Create(record)

	if result.Error != nil {
		return fmt.Errorf("failed to upsert key: %w", result.Error)
	}

	return nil
}

// DeleteKey removes a key by ID.
func (b *Backend) DeleteKey(ctx context.Context, keyID string) error {
	atomic.AddInt64(b.opCounts["delete"], 1)

	result := b.db.WithContext(ctx).Where("key_id = ?", keyID).Delete(&KeyRecord{})

	if result.Error != nil {
		return fmt.Errorf("failed to delete key: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return storage.ErrKeyNotFound
	}

	return nil
}

// ListKeys returns all key IDs matching the given prefix.
func (b *Backend) ListKeys(ctx context.Context, prefix string) ([]string, error) {
	atomic.AddInt64(b.opCounts["list"], 1)

	var keyIDs []string
	query := b.db.WithContext(ctx).Model(&KeyRecord{}).Order("key_id")

	if prefix != "" {
		// Use LIKE for prefix matching (works across all databases)
		query = query.Where("key_id LIKE ?", prefix+"%")
	}

	result := query.Pluck("key_id", &keyIDs)

	if result.Error != nil {
		return nil, fmt.Errorf("failed to list keys: %w", result.Error)
	}

	return keyIDs, nil
}

// UpdateKey atomically updates a key using the provided update function.
func (b *Backend) UpdateKey(ctx context.Context, keyID string, updateFn func(*types.Key) (*types.Key, error)) error {
	atomic.AddInt64(b.opCounts["update"], 1)

	// Start a transaction with serializable isolation
	return b.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Get current key with row lock
		var record KeyRecord
		result := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("key_id = ?", keyID).
			First(&record)

		var currentKey *types.Key
		if result.Error == nil {
			var err error
			currentKey, err = record.ToKey()
			if err != nil {
				return fmt.Errorf("failed to deserialize key: %w", err)
			}
		} else if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return fmt.Errorf("failed to query key: %w", result.Error)
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

			// Create new record
			newRecord, err := NewKeyRecord(newKey)
			if err != nil {
				return fmt.Errorf("failed to create key record: %w", err)
			}

			// Upsert the updated key
			result := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "key_id"}},
				DoUpdates: clause.AssignmentColumns([]string{"key_data", "updated_at"}),
			}).Create(newRecord)

			if result.Error != nil {
				return fmt.Errorf("failed to update key: %w", result.Error)
			}
		} else {
			// Delete the key
			result := tx.Where("key_id = ?", keyID).Delete(&KeyRecord{})
			if result.Error != nil {
				return fmt.Errorf("failed to delete key: %w", result.Error)
			}
		}

		return nil
	})
}

// Ping checks if the backend is healthy.
func (b *Backend) Ping(ctx context.Context) error {
	sqlDB, err := b.db.DB()
	if err != nil {
		return storage.ErrStorageUnavailable
	}
	if err := sqlDB.PingContext(ctx); err != nil {
		return storage.ErrStorageUnavailable
	}
	return nil
}

// Close releases any resources held by the backend.
func (b *Backend) Close() error {
	sqlDB, err := b.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Stats returns metrics about the backend's state.
func (b *Backend) Stats(ctx context.Context) (*storage.Stats, error) {
	// Count total keys
	var totalKeys int64
	if err := b.db.WithContext(ctx).Model(&KeyRecord{}).Count(&totalKeys).Error; err != nil {
		return nil, fmt.Errorf("failed to count keys: %w", err)
	}

	// Collect operation counts
	opCounts := make(map[string]int64)
	for op, count := range b.opCounts {
		opCounts[op] = atomic.LoadInt64(count)
	}

	// Get GORM stats
	sqlDB, err := b.db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database connection: %w", err)
	}
	dbStats := sqlDB.Stats()

	// Get database dialect name
	dialectName := b.db.Dialector.Name()

	stats := &storage.Stats{
		TotalKeys:       totalKeys,
		OperationCounts: opCounts,
		BackendSpecific: map[string]any{
			"backend":          "orm",
			"dialect":          dialectName,
			"open_connections": dbStats.OpenConnections,
			"in_use":           dbStats.InUse,
			"idle":             dbStats.Idle,
			"wait_count":       dbStats.WaitCount,
			"wait_duration":    dbStats.WaitDuration.String(),
		},
	}

	// Try to get table size (database-specific, may fail)
	var tableSize int64
	switch strings.ToLower(dialectName) {
	case "postgres":
		// PostgreSQL-specific query
		if err := b.db.WithContext(ctx).Raw("SELECT pg_total_relation_size('knox_keys')").Scan(&tableSize).Error; err == nil {
			stats.StorageSize = tableSize
		}
	case "mysql":
		// MySQL-specific query
		var result struct {
			DataLength  int64
			IndexLength int64
		}
		if err := b.db.WithContext(ctx).Raw(`
			SELECT data_length + index_length AS total_size
			FROM information_schema.tables
			WHERE table_schema = DATABASE() AND table_name = 'knox_keys'
		`).Scan(&result).Error; err == nil {
			stats.StorageSize = result.DataLength + result.IndexLength
		}
		// SQLite doesn't have a reliable way to get table size without OS-level queries
	}

	return stats, nil
}

// Transaction represents a GORM transaction.
type Transaction struct {
	tx        *gorm.DB
	backend   *Backend
	committed bool
}

// BeginTx starts a new transaction.
func (b *Backend) BeginTx(ctx context.Context) (storage.Transaction, error) {
	tx := b.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", tx.Error)
	}

	return &Transaction{
		tx:      tx,
		backend: b,
	}, nil
}

// GetKey retrieves a key within the transaction.
func (t *Transaction) GetKey(ctx context.Context, keyID string) (*types.Key, error) {
	var record KeyRecord
	result := t.tx.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("key_id = ?", keyID).
		First(&record)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, storage.ErrKeyNotFound
		}
		return nil, fmt.Errorf("failed to query key: %w", result.Error)
	}

	return record.ToKey()
}

// PutKey stores or updates a key within the transaction.
func (t *Transaction) PutKey(ctx context.Context, key *types.Key) error {
	if err := key.Validate(); err != nil {
		return err
	}

	record, err := NewKeyRecord(key)
	if err != nil {
		return fmt.Errorf("failed to create key record: %w", err)
	}

	result := t.tx.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"key_data", "updated_at"}),
	}).Create(record)

	if result.Error != nil {
		return fmt.Errorf("failed to upsert key: %w", result.Error)
	}

	return nil
}

// DeleteKey removes a key within the transaction.
func (t *Transaction) DeleteKey(ctx context.Context, keyID string) error {
	result := t.tx.WithContext(ctx).Where("key_id = ?", keyID).Delete(&KeyRecord{})

	if result.Error != nil {
		return fmt.Errorf("failed to delete key: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return storage.ErrKeyNotFound
	}

	return nil
}

// Commit applies all operations in the transaction atomically.
func (t *Transaction) Commit() error {
	if t.committed {
		return errors.New("transaction already committed")
	}
	t.committed = true
	return t.tx.Commit().Error
}

// Rollback aborts all operations in the transaction.
func (t *Transaction) Rollback() error {
	if t.committed {
		return nil // Already committed, nothing to rollback
	}
	return t.tx.Rollback().Error
}

// Verify that Backend implements the required interfaces at compile time.
// Verify that Backend implements the required interfaces at compile time.
var (
	_ storage.Backend              = (*Backend)(nil)
	_ storage.TransactionalBackend = (*Backend)(nil)
	_ storage.StatsProvider        = (*Backend)(nil)
	_ storage.Transaction          = (*Transaction)(nil)
)
