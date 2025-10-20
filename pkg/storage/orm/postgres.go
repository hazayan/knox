package orm

import (
	"errors"
	"fmt"
	"time"

	"github.com/hazayan/knox/pkg/storage"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func init() {
	storage.RegisterBackend("postgres", NewPostgresBackend)
}

// NewPostgresBackend creates a new PostgreSQL-based storage backend using GORM.
func NewPostgresBackend(cfg storage.Config) (storage.Backend, error) {
	if cfg.PostgresConnectionString == "" {
		return nil, errors.New("postgres backend requires PostgresConnectionString")
	}

	// Configure GORM
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent), // Use Silent for production
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
		PrepareStmt: true, // Prepare statements for better performance
	}

	// Open database connection with PostgreSQL dialect
	db, err := gorm.Open(postgres.Open(cfg.PostgresConnectionString), gormConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database instance: %w", err)
	}

	maxConnections := cfg.PostgresMaxConnections
	if maxConnections <= 0 {
		maxConnections = 25 // Default: conservative for production
	}

	// Connection pool settings
	sqlDB.SetMaxOpenConns(maxConnections)
	sqlDB.SetMaxIdleConns(maxConnections / 2)
	sqlDB.SetConnMaxLifetime(1 * time.Hour)
	sqlDB.SetConnMaxIdleTime(10 * time.Minute)

	// Create the ORM backend
	return New(db)
}
