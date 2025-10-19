package server

import (
	"sort"
	"testing"

	"github.com/hazayan/knox/pkg/types"
	"github.com/hazayan/knox/server/auth"
	"github.com/hazayan/knox/server/keydb"
)

func GetMocks() (KeyManager, types.Principal, types.ACL) {
	db := keydb.NewTempDB()
	cryptor := keydb.NewAESGCMCryptor(10, []byte("testtesttesttest"))
	m := NewKeyManager(cryptor, db)
	acl := types.ACL([]types.Access{})
	u := auth.NewUser("test", []string{})
	return m, u, acl
}

func TestGetAllKeyIDs(t *testing.T) {
	m, u, acl := GetMocks()
	keys, err := m.GetAllKeyIDs()
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if len(keys) != 0 {
		t.Fatal("database should have no keys in it")
	}

	key1 := newKey("id1", acl, []byte("data"), u)
	if err := m.AddNewKey(&key1); err != nil {
		t.Fatalf("failed to add key1: %v", err)
	}
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	keys, err = m.GetAllKeyIDs()
	if err != nil {
		t.Fatal(err.Error())
	}
	if len(keys) == 1 {
		if keys[0] != key1.ID {
			t.Fatalf("%s does not match %s", keys[0], key1.ID)
		}
	} else if len(keys) != 0 {
		t.Fatal("Unexpected # of keys in get all keys response")
	}

	key2 := newKey("id2", acl, []byte("data"), u)
	if err := m.AddNewKey(&key2); err != nil {
		t.Fatalf("failed to add key2: %v", err)
	}
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	keys, err = m.GetAllKeyIDs()
	if err != nil {
		t.Fatal(err.Error())
	}
	if len(keys) == 2 {
		switch keys[0] {
		case key1.ID:
			if keys[1] != key2.ID {
				t.Fatalf("%s does not match %s", keys[1], key2.ID)
			}
		case key2.ID:
			if keys[1] != key2.ID {
				t.Fatalf("%s does not match %s", keys[1], key1.ID)
			}
		default:
			t.Fatal("Unexpected key ID returned")
		}
	} else if len(keys) != 1 {
		t.Fatal("Unexpected # of keys in get all keys response")
	}

	err = m.DeleteKey(key1.ID)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	keys, err = m.GetAllKeyIDs()
	if err != nil {
		t.Fatal(err.Error())
	}
	if len(keys) == 1 {
		if keys[0] != key2.ID {
			t.Fatalf("%s does not match %s", keys[0], key2.ID)
		}
	} else if len(keys) != 2 {
		t.Fatal("Unexpected # of keys in get all keys response")
	}
}

func TestGetUpdatedKeyIDs(t *testing.T) {
	m, u, acl := GetMocks()
	keys, err := m.GetUpdatedKeyIDs(map[string]string{})
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if len(keys) != 0 {
		t.Fatal("database should have no keys in it")
	}

	key1 := newKey("id1", acl, []byte("data"), u)
	if err := m.AddNewKey(&key1); err != nil {
		t.Fatalf("failed to add key1: %v", err)
	}
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	keys, err = m.GetUpdatedKeyIDs(map[string]string{key1.ID: "NOT_THE_HASH"})
	if err != nil {
		t.Fatal(err.Error())
	}
	if len(keys) == 1 {
		if keys[0] != key1.ID {
			t.Fatalf("%s does not match %s", keys[0], key1.ID)
		}
	} else if len(keys) != 0 {
		t.Fatal("Unexpected # of keys in get all keys response")
	}

	keys, err = m.GetUpdatedKeyIDs(map[string]string{key1.ID: key1.VersionHash})
	if len(keys) != 0 {
		t.Fatal("database should have no keys in it")
	}

	key2 := newKey("id2", acl, []byte("data"), u)
	if err := m.AddNewKey(&key2); err != nil {
		t.Fatalf("failed to add key2: %v", err)
	}
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	keys, err = m.GetUpdatedKeyIDs(map[string]string{key2.ID: "NOT_THE_HASH"})
	if err != nil {
		t.Fatal(err.Error())
	}
	if len(keys) == 1 {
		if keys[0] != key2.ID {
			t.Fatalf("%s does not match %s", keys[0], key2.ID)
		}
	} else if len(keys) != 0 {
		t.Fatal("Unexpected # of keys in get all keys response")
	}

	keys, _ = m.GetUpdatedKeyIDs(map[string]string{key2.ID: "NOT_THE_HASH", key1.ID: "NOT_THE_HASH"})
	if len(keys) != 2 {
		t.Fatalf("Expect 2 keys not %d", len(keys))
	}
	switch keys[0] {
	case key1.ID:
		if keys[1] != key2.ID {
			t.Fatalf("%s does not match %s", keys[1], key2.ID)
		}
	case key2.ID:
		if keys[1] != key1.ID {
			t.Fatalf("%s does not match %s", keys[1], key1.ID)
		}
	default:
		t.Fatal("Unexpected key ID returned")
	}

	keys, _ = m.GetUpdatedKeyIDs(map[string]string{key2.ID: key2.VersionHash, key1.ID: "NOT_THE_HASH"})
	if len(keys) != 1 {
		t.Fatalf("Expect 1 key not %d", len(keys))
	}
	if keys[0] != key1.ID {
		t.Fatalf("%s does not match %s", keys[0], key1.ID)
	}

	keys, _ = m.GetUpdatedKeyIDs(map[string]string{key2.ID: key2.VersionHash, key1.ID: key1.VersionHash})
	if len(keys) != 0 {
		t.Fatal("expected no keys")
	}
}

func TestAddNewKey(t *testing.T) {
	m, u, acl := GetMocks()
	key1 := newKey("id1", acl, []byte("data"), u)

	_, err := m.GetKey(key1.ID, types.Active)
	if err == nil {
		t.Fatal("Should be an error")
	}

	err = m.AddNewKey(&key1)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	key, err := m.GetKey(key1.ID, types.Active)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if key.ID != key1.ID || key.VersionHash != key1.VersionHash || len(key.VersionList) != len(key1.VersionList) {
		t.Fatal("keys are not equal")
	}

	pKey, err := m.GetKey(key1.ID, types.Primary)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	aKey, err := m.GetKey(key1.ID, types.Active)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if pKey.ID != aKey.ID || pKey.VersionHash != aKey.VersionHash || len(pKey.VersionList) != len(aKey.VersionList) {
		t.Fatal("keys are not equal")
	}

	iKey, err := m.GetKey(key1.ID, types.Inactive)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if pKey.ID != iKey.ID || pKey.VersionHash != iKey.VersionHash || len(pKey.VersionList) != len(iKey.VersionList) {
		t.Fatal("keys are not equal")
	}
	if iKey.ID != aKey.ID || iKey.VersionHash != aKey.VersionHash || len(iKey.VersionList) != len(aKey.VersionList) {
		t.Fatal("keys are not equal")
	}

	err = m.DeleteKey(key1.ID)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	_, err = m.GetKey(key1.ID, types.Active)
	if err == nil {
		t.Fatal("Should be an error")
	}
}

func TestUpdateAccess(t *testing.T) {
	m, u, acl := GetMocks()
	key1 := newKey("id1", acl, []byte("data"), u)
	access := types.Access{Type: types.User, ID: "grootan", AccessType: types.Read}
	access2 := types.Access{Type: types.UserGroup, ID: "group", AccessType: types.Write}
	access3 := types.Access{Type: types.Machine, ID: "machine", AccessType: types.Read}
	err := m.UpdateAccess(key1.ID, access)
	if err == nil {
		t.Fatal("Should be an error")
	}

	err = m.AddNewKey(&key1)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	err = m.UpdateAccess(key1.ID, access)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	err = m.UpdateAccess(key1.ID, access2, access3)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	key, err := m.GetKey(key1.ID, types.Active)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if len(key.ACL) != 4 {
		t.Fatalf("%d acl rules instead of expected 4", len(key.ACL))
	}
	for _, a := range key.ACL {
		switch a.ID {
		case access.ID:
			if access.Type != a.Type {
				t.Fatalf("%d does not equal %d", access.Type, a.Type)
			}
			if access.AccessType != a.AccessType {
				t.Fatalf("%d does not equal %d", access.AccessType, a.AccessType)
			}
		case access2.ID:
			if access2.Type != a.Type {
				t.Fatalf("%d does not equal %d", access2.Type, a.Type)
			}
			if access2.AccessType != a.AccessType {
				t.Fatalf("%d does not equal %d", access2.AccessType, a.AccessType)
			}
		case access3.ID:
			if access3.Type != a.Type {
				t.Fatalf("%d does not equal %d", access3.Type, a.Type)
			}
			if access3.AccessType != a.AccessType {
				t.Fatalf("%d does not equal %d", access3.AccessType, a.AccessType)
			}
		case u.GetID():
			continue
		default:
			t.Fatalf("unknown acl value for key %v", a)
		}
	}
}

func TestAddUpdateVersion(t *testing.T) {
	m, u, acl := GetMocks()
	var key *types.Key
	key1 := newKey("id1", acl, []byte("data"), u)
	kv := newKeyVersion([]byte("data2"), types.Active)
	access := types.Access{Type: types.User, ID: "grootan", AccessType: types.Read}
	err := m.UpdateAccess(key1.ID, access)
	if err == nil {
		t.Fatal("Should be an error")
	}

	err = m.AddNewKey(&key1)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	key, err = m.GetKey(key1.ID, types.Active)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if key.ID != key1.ID || key.VersionHash != key1.VersionHash || len(key.VersionList) != len(key1.VersionList) {
		t.Fatal("keys are not equal")
	}

	err = m.AddVersion(key1.ID, &kv)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	key, err = m.GetKey(key1.ID, types.Active)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if key.ID != key1.ID {
		t.Fatalf("%s does not equal %s", key.ID, key1.ID)
	}
	if len(key.VersionList) != 2 {
		t.Fatalf("%d does not equal %d", len(key.VersionList), 2)
	}
	if key.VersionHash == key1.VersionHash {
		t.Fatalf("%s does equal %s", key.VersionHash, key1.VersionHash)
	}
	sort.Sort(key.VersionList)
	sort.Sort(key1.VersionList)
	for _, kv1 := range key.VersionList {
		if kv1.Status == types.Primary {
			if kv1.ID != key1.VersionList[0].ID || !equalBytes(kv1.Data, key1.VersionList[0].Data) || kv1.Status != key1.VersionList[0].Status || kv1.CreationTime != key1.VersionList[0].CreationTime {
				t.Fatal("primary versions are not equal")
			}
		}
		if kv1.Status == types.Active {
			if kv1.ID != kv.ID || !equalBytes(kv1.Data, kv.Data) || kv1.Status != kv.Status || kv1.CreationTime != kv.CreationTime {
				t.Fatal("active versions are not equal")
			}
		}
		if kv1.Status == types.Inactive {
			t.Fatal("No key versions should be inactive")
		}
	}

	err = m.UpdateVersion(key1.ID, kv.ID, types.Primary)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	key, err = m.GetKey(key1.ID, types.Active)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if key.ID != key1.ID {
		t.Fatalf("%s does not equal %s", key.ID, key1.ID)
	}
	if key.VersionHash == key1.VersionHash {
		t.Fatalf("%s does equal %s", key.VersionHash, key1.VersionHash)
	}
	if len(key.VersionList) != 2 {
		t.Fatalf("%d does not equal %d", len(key.VersionList), 2)
	}
	sort.Sort(key.VersionList)
	kv1 := key.VersionList[0]
	if kv1.Status != types.Primary {
		t.Fatalf("%d does equal %d", kv1.Status, types.Primary)
	}
	if kv1.ID != kv.ID {
		t.Fatalf("%d does equal %d", kv1.ID, kv.ID)
	}
	if string(kv1.Data) != string(kv.Data) {
		t.Fatalf("%s does equal %s", string(kv1.Data), string(kv.Data))
	}
	if kv1.CreationTime != kv.CreationTime {
		t.Fatalf("%d does equal %d", kv1.CreationTime, kv.CreationTime)
	}

	kv1 = key.VersionList[1]
	if kv1.Status != types.Active {
		t.Fatalf("%d does equal %d", kv1.Status, types.Primary)
	}
	if kv1.ID != key1.VersionList[0].ID {
		t.Fatalf("%d does equal %d", kv1.ID, key1.VersionList[0].ID)
	}
	if string(kv1.Data) != string(key1.VersionList[0].Data) {
		t.Fatalf("%s does equal %s", string(kv1.Data), string(key1.VersionList[0].Data))
	}
	if kv1.CreationTime != key1.VersionList[0].CreationTime {
		t.Fatalf("%d does equal %d", kv1.CreationTime, key1.VersionList[0].CreationTime)
	}

	err = m.UpdateVersion(key1.ID, key1.VersionList[0].ID, types.Inactive)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	key, err = m.GetKey(key1.ID, types.Active)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if key.ID != key1.ID {
		t.Fatalf("%s does not equal %s", key.ID, key1.ID)
	}
	if key.VersionHash == key1.VersionHash {
		t.Fatalf("%s does equal %s", key.VersionHash, key1.VersionHash)
	}
	if len(key.VersionList) != 1 {
		t.Fatalf("%d does not equal %d", len(key.VersionList), 1)
	}
	kv1 = key.VersionList[0]
	if kv1.Status != types.Primary {
		t.Fatalf("%d does equal %d", kv1.Status, types.Primary)
	}
	if kv1.ID != kv.ID {
		t.Fatalf("%d does equal %d", kv1.ID, kv.ID)
	}
	if string(kv1.Data) != string(kv.Data) {
		t.Fatalf("%s does equal %s", string(kv1.Data), string(kv.Data))
	}
	if kv1.CreationTime != kv.CreationTime {
		t.Fatalf("%d does equal %d", kv1.CreationTime, kv.CreationTime)
	}
}

// equalBytes compares two byte slices for equality.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestGetInactiveKeyVersions(t *testing.T) {
	m, u, acl := GetMocks()

	keyOrig := newKey("id1", acl, []byte("data"), u)
	kv := newKeyVersion([]byte("data2"), types.Active)

	// Create key and add version so we have two versions
	err := m.AddNewKey(&keyOrig)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	err = m.AddVersion(keyOrig.ID, &kv)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	// Get active versions and deactivate one of them
	key, err := m.GetKey(keyOrig.ID, types.Active)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	kvID0 := key.VersionList[0].ID
	kvID1 := key.VersionList[1].ID

	// Deactivate one of these versions
	err = m.UpdateVersion(keyOrig.ID, kvID1, types.Inactive)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	// Reading active key versions should now list only one version
	key, err = m.GetKey(keyOrig.ID, types.Active)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	if len(key.VersionList) != 1 {
		t.Fatalf("Wanted one key version, got: %d", len(key.VersionList))
	}
	if key.VersionList[0].ID != kvID0 {
		t.Fatal("Inactive key id was listed as ctive")
	}

	// Reading active/inactive key versions should now list both
	key, err = m.GetKey(keyOrig.ID, types.Inactive)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	if len(key.VersionList) != 2 {
		t.Fatal("Wanted two key versions, got: ", len(key.VersionList))
	}
}
