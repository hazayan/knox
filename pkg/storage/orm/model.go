// Package orm provides a database-agnostic ORM-based storage backend for Knox.
// This package uses GORM to abstract away SQL differences between PostgreSQL, MySQL, SQLite, etc.
package orm

import (
	"encoding/json"
	"time"

	"github.com/hazayan/knox/pkg/types"
)

// KeyRecord represents a Knox key stored in the database.
// This is the ORM model that maps to the knox_keys table.
type KeyRecord struct {
	// KeyID is the unique identifier for this key (primary key)
	KeyID string `gorm:"primaryKey;type:varchar(500);index:idx_key_id_prefix" json:"key_id"`

	// KeyData stores the serialized types.Key as JSON
	// PostgreSQL: jsonb, MySQL: json, SQLite: text
	KeyData []byte `gorm:"type:jsonb;not null" json:"key_data"`

	// CreatedAt is automatically managed by GORM
	CreatedAt time.Time `gorm:"autoCreateTime;index" json:"created_at"`

	// UpdatedAt is automatically managed by GORM
	UpdatedAt time.Time `gorm:"autoUpdateTime;index" json:"updated_at"`
}

// TableName specifies the table name for GORM.
func (KeyRecord) TableName() string {
	return "knox_keys"
}

// ToKey deserializes the KeyData JSON into a types.Key.
func (kr *KeyRecord) ToKey() (*types.Key, error) {
	var key types.Key
	if err := json.Unmarshal(kr.KeyData, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

// FromKey serializes a types.Key into KeyData JSON.
func (kr *KeyRecord) FromKey(key *types.Key) error {
	data, err := json.Marshal(key)
	if err != nil {
		return err
	}
	kr.KeyID = key.ID
	kr.KeyData = data
	return nil
}

// NewKeyRecord creates a new KeyRecord from a types.Key.
func NewKeyRecord(key *types.Key) (*KeyRecord, error) {
	kr := &KeyRecord{}
	if err := kr.FromKey(key); err != nil {
		return nil, err
	}
	return kr, nil
}
