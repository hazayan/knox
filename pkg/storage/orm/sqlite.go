package orm

import (
	"fmt"
	"time"

	"github.com/hazayan/knox/pkg/storage"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func init() {
	storage.RegisterBackend("sqlite", NewSQLiteBackend)
}

// NewSQLiteBackend creates a new SQLite-based storage backend using GORM.
func NewSQLiteBackend(cfg storage.Config) (storage.Backend, error) {
	// For SQLite, we'll use FilesystemDir as the database file path
	dbPath := cfg.FilesystemDir
	if dbPath == "" {
		dbPath = "knox.db" // Default SQLite database file
	}

	// Configure GORM
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
		PrepareStmt: true,
	}

	// Open database connection with SQLite dialect
	db, err := gorm.Open(sqlite.Open(dbPath), gormConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to sqlite: %w", err)
	}

	// Configure connection pool (SQLite has different characteristics)
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database instance: %w", err)
	}

	// SQLite works best with limited connections
	sqlDB.SetMaxOpenConns(1)                   // SQLite benefits from single connection
	sqlDB.SetMaxIdleConns(1)                   // Keep connection alive
	sqlDB.SetConnMaxLifetime(0)                // No lifetime limit
	sqlDB.SetConnMaxIdleTime(10 * time.Minute) // Close after idle period

	// Enable WAL mode for better concurrency (SQLite-specific pragma)
	if err := db.Exec("PRAGMA journal_mode=WAL").Error; err != nil {
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	// Create the ORM backend
	return New(db)
}
