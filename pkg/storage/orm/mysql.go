package orm

import (
	"errors"
	"fmt"
	"time"

	"github.com/hazayan/knox/pkg/storage"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func init() {
	storage.RegisterBackend("mysql", NewMySQLBackend)
}

// MySQLConfig extends storage.Config with MySQL-specific options.
type MySQLConfig struct {
	storage.Config
	MySQLConnectionString string
	MySQLMaxConnections   int
}

// NewMySQLBackend creates a new MySQL-based storage backend using GORM.
func NewMySQLBackend(cfg storage.Config) (storage.Backend, error) {
	// For MySQL, we'll expect the connection string in PostgresConnectionString
	// or add a MySQLConnectionString field to storage.Config
	connectionString := cfg.PostgresConnectionString // Reuse for now
	if connectionString == "" {
		return nil, errors.New("mysql backend requires connection string")
	}

	// Configure GORM
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
		PrepareStmt: true,
	}

	// Open database connection with MySQL dialect
	db, err := gorm.Open(mysql.Open(connectionString), gormConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to mysql: %w", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database instance: %w", err)
	}

	maxConnections := cfg.PostgresMaxConnections // Reuse config field
	if maxConnections <= 0 {
		maxConnections = 25
	}

	sqlDB.SetMaxOpenConns(maxConnections)
	sqlDB.SetMaxIdleConns(maxConnections / 2)
	sqlDB.SetConnMaxLifetime(1 * time.Hour)
	sqlDB.SetConnMaxIdleTime(10 * time.Minute)

	// Create the ORM backend
	return New(db)
}
