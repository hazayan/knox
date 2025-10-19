package server

import (
	"fmt"

	"github.com/hazayan/knox/pkg/types"
	"github.com/hazayan/knox/server/keydb"
)

// KeyManager is the interface for logic related to managing keys.
type KeyManager interface {
	GetAllKeyIDs() ([]string, error)
	GetUpdatedKeyIDs(map[string]string) ([]string, error)
	GetKey(id string, status types.VersionStatus) (*types.Key, error)
	AddNewKey(*types.Key) error
	DeleteKey(id string) error
	UpdateAccess(string, ...types.Access) error
	AddVersion(string, *types.KeyVersion) error
	UpdateVersion(keyID string, versionID uint64, s types.VersionStatus) error
}

// NewKeyManager builds a struct for interfacing with the keydb.
func NewKeyManager(c keydb.Cryptor, db keydb.DB) KeyManager {
	return &keyManager{c, db}
}

type keyManager struct {
	cryptor keydb.Cryptor
	db      keydb.DB
}

func (m *keyManager) GetAllKeyIDs() ([]string, error) {
	keys, err := m.db.GetAll()
	if err != nil {
		return nil, err
	}
	var output []string
	for _, k := range keys {
		output = append(output, k.ID)
	}
	return output, nil
}

func (m *keyManager) GetUpdatedKeyIDs(versions map[string]string) ([]string, error) {
	keys, err := m.db.GetAll()
	if err != nil {
		return nil, err
	}
	var output []string
	for _, k := range keys {
		if v, ok := versions[k.ID]; ok && k.VersionHash != v {
			output = append(output, k.ID)
		}
	}
	return output, nil
}

func (m *keyManager) GetKey(id string, status types.VersionStatus) (*types.Key, error) {
	encK, err := m.db.Get(id)
	if err != nil {
		return nil, err
	}
	k, err := m.cryptor.Decrypt(encK)
	if err != nil {
		return nil, fmt.Errorf("error decrypting key: %s", err.Error())
	}
	switch status {
	case types.Inactive:
		return k, nil
	case types.Active:
		k.VersionList = k.VersionList.GetActive()
		return k, nil
	case types.Primary:
		k.VersionList = types.KeyVersionList{*k.VersionList.GetPrimary()}
		return k, nil
	default:
		return nil, types.ErrInvalidStatus
	}
}

func (m *keyManager) AddNewKey(k *types.Key) error {
	if err := k.Validate(); err != nil {
		return err
	}
	dbk, err := m.cryptor.Encrypt(k)
	if err != nil {
		return err
	}
	return m.db.Add(dbk)
}

func (m *keyManager) DeleteKey(id string) error {
	return m.db.Remove(id)
}

func (m *keyManager) UpdateAccess(id string, acl ...types.Access) error {
	encK, err := m.db.Get(id)
	if err != nil {
		return err
	}
	newEncK := encK.Copy()
	for _, a := range acl {
		newEncK.ACL = newEncK.ACL.Add(a)
	}
	err = newEncK.ACL.Validate()
	if err != nil {
		return err
	}
	return m.db.Update(newEncK)
}

func (m *keyManager) AddVersion(id string, v *types.KeyVersion) error {
	encK, err := m.db.Get(id)
	if err != nil {
		return err
	}

	k, err := m.cryptor.Decrypt(encK)
	if err != nil {
		return fmt.Errorf("error decrypting key: %s", err.Error())
	}

	k.VersionList = append(k.VersionList, *v)
	k.VersionHash = k.VersionList.Hash()
	err = k.Validate()
	if err != nil {
		return err
	}
	encV, err := m.cryptor.EncryptVersion(k, v)
	if err != nil {
		return err
	}

	newEncK := encK.Copy()
	newEncK.VersionList = append(newEncK.VersionList, *encV)
	newEncK.VersionHash = k.VersionList.Hash()

	return m.db.Update(newEncK)
}

func (m *keyManager) UpdateVersion(keyID string, versionID uint64, s types.VersionStatus) error {
	encK, err := m.db.Get(keyID)
	if err != nil {
		return err
	}
	k, err := m.cryptor.Decrypt(encK)
	if err != nil {
		return fmt.Errorf("error decrypting key: %s", err.Error())
	}
	// Validate the change makes sense
	kvl, err := k.VersionList.Update(versionID, s)
	if err != nil {
		return err
	}
	k.VersionHash = kvl.Hash()
	err = k.Validate()
	if err != nil {
		return err
	}
	newEncK := encK.Copy()
	for j, v := range newEncK.VersionList {
		for _, nv := range kvl {
			if v.ID == nv.ID {
				newEncK.VersionList[j].Status = nv.Status
			}
		}
	}
	newEncK.VersionHash = k.VersionHash
	return m.db.Update(newEncK)
}
