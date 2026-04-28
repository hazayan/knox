// Package keydb provides the database layer for Knox key storage.
// It handles encryption, serialization, and persistence of keys with
// support for multiple database backends and cryptographic providers.
package keydb

import (
	"errors"
	"sync"
	"time"

	"github.com/hazayan/knox/pkg/types"
)

var ErrDBVersion = errors.New("DB version does not match")

// DBKey is a struct for the json serialization of keys in the database.
type DBKey struct {
	ID          string          `json:"id"`
	ACL         types.ACL       `json:"acl"`
	VersionList []EncKeyVersion `json:"versions"`
	VersionHash string          `json:"hash"`
	// The version should be set by the db provider and is not part of the data.
	DBVersion int64 `json:"-"`
}

// Copy provides a deep copy of database keys so that VersionLists can be edited in a copy.
func (k *DBKey) Copy() *DBKey {
	versionList := make([]EncKeyVersion, len(k.VersionList))
	copy(versionList, k.VersionList)
	acl := make([]types.Access, len(k.ACL))
	copy(acl, k.ACL)
	return &DBKey{
		ID:          k.ID,
		ACL:         acl,
		VersionList: versionList,
		VersionHash: k.VersionHash,
		DBVersion:   k.DBVersion,
	}
}

// EncKeyVersion is a struct for encrypting key data.
type EncKeyVersion struct {
	ID             uint64              `json:"id"`
	EncData        []byte              `json:"data"`
	Status         types.VersionStatus `json:"status"`
	CreationTime   int64               `json:"ts"`
	CryptoMetadata []byte              `json:"crypt"`
}

// DB is the underlying database connection that KeyDB uses for all of its operations.
//
// This interface should not contain any business logic and should only deal with formatting
// and database specific logic.
type DB interface {
	// Get returns the key specified by the ID.
	Get(id string) (*DBKey, error)
	// GetAll returns all of the keys in the database.
	GetAll() ([]DBKey, error)

	// Update makes an update to DBKey indexed by its ID.
	// It will fail if the key has been changed since the specified version.
	Update(key *DBKey) error
	// Add adds the key(s) to the DB (it will fail if the key id exists).
	Add(keys ...*DBKey) error
	// Remove permanently removes the key specified by the ID.
	Remove(id string) error
}

// NewTempDB creates a new TempDB with no data.
func NewTempDB() DB {
	return &TempDB{}
}

// TempDB is an in memory DB that does no replication across servers and starts
// out fresh everytime. It is written for testing and simple dev work.
type TempDB struct {
	sync.RWMutex
	keys []DBKey
	err  error
}

// SetError is used to set the error the TempDB for testing purposes.
func (db *TempDB) SetError(err error) {
	db.Lock()
	defer db.Unlock()
	db.err = err
}

// Get gets stored db key from TempDB.
func (db *TempDB) Get(id string) (*DBKey, error) {
	db.RLock()
	defer db.RUnlock()
	if db.err != nil {
		return nil, db.err
	}
	for _, k := range db.keys {
		if k.ID == id {
			return &k, nil
		}
	}
	return nil, types.ErrKeyIDNotFound
}

// GetAll gets all keys from TempDB.
func (db *TempDB) GetAll() ([]DBKey, error) {
	db.RLock()
	defer db.RUnlock()
	if db.err != nil {
		return nil, db.err
	}
	return db.keys, nil
}

// Update looks for an existing key and updates the key in the database.
func (db *TempDB) Update(key *DBKey) error {
	db.Lock()
	defer db.Unlock()
	if db.err != nil {
		return db.err
	}
	for i, dbk := range db.keys {
		if dbk.ID == key.ID {
			if dbk.DBVersion != key.DBVersion {
				return ErrDBVersion
			}
			k := key.Copy()
			k.DBVersion = time.Now().UnixNano()
			db.keys[i] = *k
			return nil
		}
	}
	return types.ErrKeyIDNotFound
}

// Add adds the key(s) to the DB (it will fail if the key id exists).
func (db *TempDB) Add(keys ...*DBKey) error {
	db.Lock()
	defer db.Unlock()
	if db.err != nil {
		return db.err
	}
	for _, key := range keys {
		for _, oldK := range db.keys {
			if oldK.ID == key.ID {
				return types.ErrKeyExists
			}
		}
	}
	for _, key := range keys {
		k := key.Copy()
		k.DBVersion = time.Now().UnixNano()

		db.keys = append(db.keys, *k)
	}
	return nil
}

// Remove will remove the key id from the database.
func (db *TempDB) Remove(id string) error {
	db.Lock()
	defer db.Unlock()
	if db.err != nil {
		return db.err
	}
	for i, k := range db.keys {
		if k.ID == id {
			db.keys = append(db.keys[:i], db.keys[i+1:]...)
			return nil
		}
	}
	return types.ErrKeyIDNotFound
}
