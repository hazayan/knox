package main

import (
	"fmt"

	"github.com/hazayan/knox/pkg/types"
	"github.com/hazayan/knox/server/keydb"
)

func moveKeyData(sDB keydb.DB, sCrypt keydb.Cryptor, dDB keydb.DB, dCrypt keydb.Cryptor) error {
	dbKeys, err := sDB.GetAll()
	if err != nil {
		return err
	}
	newDBKeys := make([]*keydb.DBKey, 0, len(dbKeys))
	for _, dbk := range dbKeys {
		k, err := sCrypt.Decrypt(&dbk)
		if err != nil {
			return err
		}
		newDBK, err := dCrypt.Encrypt(k)
		if err != nil {
			return err
		}
		newDBKeys = append(newDBKeys, newDBK)
	}

	err = dDB.Add(newDBKeys...)
	if err != nil {
		return err
	}
	return nil
}

func generateTestDBWithKeys(crypt keydb.Cryptor) keydb.DB {
	source := keydb.NewTempDB()
	d := []byte("test")
	v1 := types.KeyVersion{ID: 1, Data: d, Status: types.Primary, CreationTime: 10}
	v2 := types.KeyVersion{ID: 2, Data: d, Status: types.Active, CreationTime: 10}
	v3 := types.KeyVersion{ID: 3, Data: d, Status: types.Inactive, CreationTime: 10}
	validKVL := types.KeyVersionList([]types.KeyVersion{v1, v2, v3})

	a1 := types.Access{ID: "testmachine1", AccessType: types.Admin, Type: types.Machine}
	a2 := types.Access{ID: "testuser", AccessType: types.Write, Type: types.User}
	a3 := types.Access{ID: "testmachine", AccessType: types.Read, Type: types.MachinePrefix}
	validACL := types.ACL([]types.Access{a1, a2, a3})

	key := types.Key{ID: "test_key", ACL: validACL, VersionList: validKVL, VersionHash: validKVL.Hash()}
	key2 := types.Key{ID: "test_key2", ACL: validACL, VersionList: validKVL, VersionHash: validKVL.Hash()}

	dbkey, err := crypt.Encrypt(&key)
	if err != nil {
		panic(err)
	}
	dbkey2, err := crypt.Encrypt(&key2)
	if err != nil {
		panic(err)
	}

	source.Add(dbkey, dbkey2)
	return source
}

func main() {
	crypt1 := keydb.NewAESGCMCryptor(0, make([]byte, 16))
	crypt2 := keydb.NewAESGCMCryptor(1, make([]byte, 16))

	source := generateTestDBWithKeys(crypt1)

	dest := keydb.NewTempDB()

	err := moveKeyData(source, crypt1, dest, crypt2)
	if err != nil {
		panic(err)
	}

	fmt.Printf("source: %v, dest: %v", source, dest)
}
