package types_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/hazayan/knox/pkg/types"
)

func TestKeyVersionListHash(t *testing.T) {
	d := []byte("test")
	v1 := types.KeyVersion{1, d, types.Primary, 10}
	v2 := types.KeyVersion{2, d, types.Active, 10}
	v3 := types.KeyVersion{3, d, types.Active, 10}
	versions := []types.KeyVersion{v1, v2, v3}
	statuses := []types.VersionStatus{types.Active, types.Inactive}
	hashes := map[string]string{}
	for i := range versions {
		versions[i].Status = types.Primary
		for _, s1 := range statuses {
			versions[(i+1)%3].Status = s1
			for _, s2 := range statuses {
				versions[(i+2)%3].Status = s2
				h := types.KeyVersionList([]types.KeyVersion{versions[0], versions[1], versions[2]}).Hash()
				text, _ := json.Marshal(versions)
				if _, match := hashes[h]; match {
					t.Error("hashes match: " + string(text) + " == " + hashes[h])
				}
				hashes[h] = string(text)
			}
		}
	}
}

func TestKeyVersionListUpdate(t *testing.T) {
	d := []byte("test")
	v1 := types.KeyVersion{1, d, types.Primary, 10}
	v2 := types.KeyVersion{2, d, types.Active, 10}
	v3 := types.KeyVersion{3, d, types.Inactive, 10}
	kvl := types.KeyVersionList([]types.KeyVersion{v1, v2, v3})
	_, primary2PrimaryErr := kvl.Update(v1.ID, types.Primary)
	if primary2PrimaryErr == nil {
		t.Error("Primary can't go to Primary")
	}
	_, primary2ActiveErr := kvl.Update(v1.ID, types.Active)
	if primary2ActiveErr == nil {
		t.Error("Primary can go to Active")
	}
	_, primary2InactiveErr := kvl.Update(v1.ID, types.Inactive)
	if primary2InactiveErr == nil {
		t.Error("Primary can go to Inactive")
	}
	_, active2ActiveErr := kvl.Update(v2.ID, types.Active)
	if active2ActiveErr == nil {
		t.Error("Active can go to Active")
	}
	_, inActive2InActiveErr := kvl.Update(v3.ID, types.Inactive)
	if inActive2InActiveErr == nil {
		t.Error("InActive can go to Inactive")
	}
	_, inActive2PrimaryErr := kvl.Update(v3.ID, types.Primary)
	if inActive2PrimaryErr == nil {
		t.Error("InActive can go to Primary")
	}
	kvl, inActive2ActiveErr := kvl.Update(v3.ID, types.Active)
	if inActive2ActiveErr != nil {
		t.Error("InActive can't go to Active")
	}
	for _, kv := range kvl {
		if kv.ID == v1.ID && kv.Status != types.Primary {
			t.Error("Wrong type on v1")
		}
		if kv.ID == v2.ID && kv.Status != types.Active {
			t.Error("Wrong type on v2")
		}
		if kv.ID == v3.ID && kv.Status != types.Active {
			t.Error("Wrong type on v3")
		}
	}
	kvl, active2InactiveErr := kvl.Update(v3.ID, types.Inactive)
	if active2InactiveErr != nil {
		t.Error("Active can't go to Inactive")
	}

	kvl, active2PrimaryErr := kvl.Update(v2.ID, types.Primary)
	if active2PrimaryErr != nil {
		t.Error("Active can't go to Primary")
	}
	for _, kv := range kvl {
		if kv.ID == v1.ID && kv.Status != types.Active {
			t.Error("Wrong type on v1")
		}
		if kv.ID == v2.ID && kv.Status != types.Primary {
			t.Error("Wrong type on v2")
		}
		if kv.ID == v3.ID && kv.Status != types.Inactive {
			t.Error("Wrong type on v3")
		}
	}

	_, dneErr := kvl.Update(2387498237, types.Active)
	if !errors.Is(dneErr, types.ErrKeyVersionNotFound) {
		t.Error("Expected version to not exist")
	}
}

func marshalUnmarshal(t *testing.T, in json.Marshaler, out json.Unmarshaler) {
	s, mErr := in.MarshalJSON()
	if mErr != nil {
		t.Error(mErr)
	}
	uErr := out.UnmarshalJSON(s)
	if uErr != nil {
		t.Error(uErr)
	}
}

func TestAccessTypeMarshaling(t *testing.T) {
	for _, in := range []types.AccessType{types.Read, types.Write, types.Admin, types.None} {
		var out types.AccessType
		marshalUnmarshal(t, &in, &out)
		if in != out {
			t.Error("Unmarshaled not same as input ", in, out)
		}
	}
	var invalid types.AccessType = 12938798732 // This is not currently an AccessType
	_, marshalErr := invalid.MarshalJSON()
	if marshalErr == nil {
		t.Error("Marshaled invalid enum")
	}
	unmarshalErr := invalid.UnmarshalJSON([]byte("ThisInputIsNotValid"))
	if unmarshalErr == nil {
		t.Error("Unmarshaled invalid string")
	}
}

func TestPrincipalTypeMarshaling(t *testing.T) {
	for _, in := range []types.PrincipalType{types.User, types.UserGroup, types.Machine, types.MachinePrefix, types.Service, types.ServicePrefix} {
		var out types.PrincipalType
		marshalUnmarshal(t, &in, &out)
		if in != out {
			t.Error("Unmarshaled not same as input ", in, out)
		}
	}
	var invalid types.PrincipalType = 12938798732 // This is not currently an PrincipalType
	_, marshalErr := invalid.MarshalJSON()
	if marshalErr == nil {
		t.Error("Marshaled invalid enum")
	}
	unmarshalErr := invalid.UnmarshalJSON([]byte("ThisInputIsNotValid"))
	if unmarshalErr != nil {
		t.Error("Did not unmarshal invalid string")
	}
	if invalid != -1 {
		t.Error("Unmarshaling invalid Principal type should result in -1")
	}
}

func TestVersionStatusMarshaling(t *testing.T) {
	for _, in := range []types.VersionStatus{types.Primary, types.Active, types.Inactive} {
		var out types.VersionStatus
		marshalUnmarshal(t, &in, &out)
		if in != out {
			t.Error("Unmarshaled not same as input ", in, out)
		}
	}
	var invalid types.VersionStatus = 12938798732 // This is not currently an VersionStatus
	_, marshalErr := invalid.MarshalJSON()
	if marshalErr == nil {
		t.Error("Marshaled invalid enum")
	}
	unmarshalErr := invalid.UnmarshalJSON([]byte("ThisInputIsNotValid"))
	if unmarshalErr == nil {
		t.Error("Unmarshaled invalid string")
	}
}

func TestKeyPathMarhaling(t *testing.T) {
	key := types.Key{
		ID:          "test",
		ACL:         types.ACL([]types.Access{}),
		VersionList: types.KeyVersionList{},
		VersionHash: "VersionHash",
	}

	out, err := json.Marshal(key)
	if err != nil {
		t.Errorf("Failed to marshal key: %v", err)
	} else if bytes.Contains(out, []byte("path")) {
		t.Error("Found unexpected 'path' key in JSON output")
	}

	key.Path = "/var/lib/knox/v0/keys/test:test"
	out, err = json.Marshal(key)
	if err != nil {
		t.Errorf("Failed to marshal key: %v", err)
	} else if !bytes.Contains(out, []byte("path")) {
		t.Error("Expected 'path' key in JSON output")
	}
}

func TestACLValidate(t *testing.T) {
	a1 := types.Access{ID: "testmachine1", AccessType: types.Admin, Type: types.Machine}
	a2 := types.Access{ID: "testuser", AccessType: types.Write, Type: types.User}
	a3 := types.Access{ID: "testmachine", AccessType: types.Read, Type: types.MachinePrefix}
	a6 := types.Access{ID: "spiffe://example.com/serviceA", AccessType: types.Read, Type: types.Service}
	a7 := types.Access{ID: "spiffe://example.com/serviceA/", AccessType: types.Read, Type: types.ServicePrefix}
	validACL := types.ACL([]types.Access{a1, a2, a3, a6, a7})
	if validACL.Validate() != nil {
		t.Error("ValidACL should be valid")
	}

	a4 := types.Access{ID: "testmachine", AccessType: types.None, Type: types.MachinePrefix}
	noneACL := types.ACL([]types.Access{a1, a2, a4})
	if noneACL.Validate() == nil {
		t.Error("noneACL should err")
	}

	a5 := types.Access{ID: "testmachine1", AccessType: types.Write, Type: types.Machine}
	dupACL := types.ACL([]types.Access{a1, a5, a3})
	if dupACL.Validate() == nil {
		t.Error("dupACL should err")
	}
}

func TestACLAddMultiple(t *testing.T) {
	a1 := types.Access{ID: "testmachine", AccessType: types.Admin, Type: types.Machine}
	a3 := types.Access{ID: "testmachine", AccessType: types.None, Type: types.Machine}
	a4 := types.Access{ID: "testmachine2", AccessType: types.Admin, Type: types.Machine}
	acl := types.ACL([]types.Access{a1})
	acl2 := acl.Add(a4)
	if len(acl2) != 2 {
		t.Error("Unexpected ACL for adding access")
	}
	acl3 := acl2.Add(a3)
	if len(acl3) != 1 {
		t.Error("Unexpected ACL length")
	}
	if acl3[0].ID != a4.ID {
		t.Error("Removed incorrect ID")
	}
	acl4 := acl3.Add(a3)
	if len(acl4) != 1 {
		t.Error("Unexpected ACL length")
	}
}

func TestACLAdd(t *testing.T) {
	a1 := types.Access{ID: "testmachine", AccessType: types.Admin, Type: types.Machine}
	a2 := types.Access{ID: "testmachine", AccessType: types.Write, Type: types.Machine}
	a3 := types.Access{ID: "testmachine", AccessType: types.None, Type: types.Machine}
	a4 := types.Access{ID: "testmachine2", AccessType: types.Admin, Type: types.Machine}
	acl := types.ACL([]types.Access{a1})
	acl1 := acl.Add(a2)
	if len(acl1) != 1 || acl1[0].AccessType != types.Write {
		t.Error("Unexpected ACL for adding different access type")
	}
	acl2 := acl.Add(a3)
	if len(acl2) != 0 {
		t.Error("Unexpected ACL for removing access")
	}
	acl3 := acl.Add(a4)
	if len(acl3) != 2 {
		t.Error("Unexpected ACL for adding access")
	}
}

func TestAccessTypeCanAccess(t *testing.T) {
	if types.Read.CanAccess(types.Admin) || types.Read.CanAccess(types.Write) || !types.Read.CanAccess(types.Read) || !types.Read.CanAccess(types.None) {
		t.Error("Read has incorrect access")
	}
	if types.Write.CanAccess(types.Admin) || !types.Write.CanAccess(types.Write) || !types.Write.CanAccess(types.Read) || !types.Write.CanAccess(types.None) {
		t.Error("Write has incorrect access")
	}
	if !types.Admin.CanAccess(types.Admin) || !types.Admin.CanAccess(types.Write) || !types.Admin.CanAccess(types.Read) || !types.Admin.CanAccess(types.None) {
		t.Error("Admin has incorrect access")
	}
	if types.None.CanAccess(types.Admin) || types.None.CanAccess(types.Write) || types.None.CanAccess(types.Read) || !types.None.CanAccess(types.None) {
		t.Error("None has incorrect access")
	}
}

func TestKeyValidate(t *testing.T) {
	d := []byte("test")
	v1 := types.KeyVersion{1, d, types.Primary, 10}
	v2 := types.KeyVersion{2, d, types.Active, 10}
	v3 := types.KeyVersion{3, d, types.Inactive, 10}
	v4 := types.KeyVersion{3, d, types.Active, 10}
	validKVL := types.KeyVersionList([]types.KeyVersion{v1, v2, v3})
	invalidKVL := types.KeyVersionList([]types.KeyVersion{v1, v2, v3, v4})

	a1 := types.Access{ID: "testmachine1", AccessType: types.Admin, Type: types.Machine}
	a2 := types.Access{ID: "testuser", AccessType: types.Write, Type: types.User}
	a3 := types.Access{ID: "testmachine", AccessType: types.Read, Type: types.MachinePrefix}
	a4 := types.Access{ID: "testmachine", AccessType: types.None, Type: types.MachinePrefix}
	a5 := types.Access{ID: "spiffe://example.com/serviceA", AccessType: types.Admin, Type: types.Service}
	validACL := types.ACL([]types.Access{a1, a2, a3, a5})
	invalidACL := types.ACL([]types.Access{a1, a2, a4})

	validKeyID := "test_key"
	invalidKeyID := "testkey "

	validHash := validKVL.Hash()
	invalidHash := "INVALID_HASH"

	validKey := types.Key{ID: validKeyID, ACL: validACL, VersionList: validKVL, VersionHash: validHash}
	invalidKey1 := types.Key{ID: invalidKeyID, ACL: validACL, VersionList: validKVL, VersionHash: validHash}
	invalidKey2 := types.Key{ID: validKeyID, ACL: invalidACL, VersionList: validKVL, VersionHash: validHash}
	invalidKey3 := types.Key{ID: validKeyID, ACL: validACL, VersionList: invalidKVL, VersionHash: validHash}
	invalidKey4 := types.Key{ID: validKeyID, ACL: validACL, VersionList: validKVL, VersionHash: invalidHash}

	if validKey.Validate() != nil {
		t.Error("Valid Key should validate successfully")
	}
	if invalidKey1.Validate() == nil {
		t.Error("Invalid Key ID should fail to validate successfully")
	}
	if invalidKey2.Validate() == nil {
		t.Error("Invalid ACL should fail to validate successfully")
	}
	if invalidKey3.Validate() == nil {
		t.Error("Invalid KVL should fail to validate successfully")
	}
	if invalidKey4.Validate() == nil {
		t.Error("Invalid Version Hash should fail to validate successfully")
	}
}

func TestKeyVersionListValidate(t *testing.T) {
	d := []byte("test")
	v1 := types.KeyVersion{1, d, types.Primary, 10}
	v2 := types.KeyVersion{2, d, types.Active, 10}
	v3 := types.KeyVersion{3, d, types.Inactive, 10}
	validKVL := types.KeyVersionList([]types.KeyVersion{v1, v2, v3})
	if validKVL.Validate() != nil {
		t.Error("Valid KVL should be valid")
	}

	v4 := types.KeyVersion{3, d, types.Active, 10}
	dupKVL := types.KeyVersionList([]types.KeyVersion{v1, v2, v3, v4})
	if dupKVL.Validate() == nil {
		t.Error("Duplicate version id, KVL should be invalid.")
	}

	v5 := types.KeyVersion{4, d, types.Primary, 10}
	twoPrimaryKVL := types.KeyVersionList([]types.KeyVersion{v1, v2, v3, v5})
	if twoPrimaryKVL.Validate() == nil {
		t.Error("KVL with two primary versions should be invalid.")
	}
}

func TestKVLGetActive(t *testing.T) {
	d := []byte("test")
	v1 := types.KeyVersion{1, d, types.Primary, 10}
	v2 := types.KeyVersion{2, d, types.Active, 10}
	v3 := types.KeyVersion{3, d, types.Inactive, 10}
	kvl := types.KeyVersionList([]types.KeyVersion{v1, v2, v3})
	keys := kvl.GetActive()
	if len(keys) != 2 {
		t.Error("Invalid number of keys returned from GetActive")
	}
	for _, k := range keys {
		switch k.ID {
		case 1:
		case 2:
		case 3:
			t.Error("Received invalid key in GetActive response")
		default:
			t.Error("Unknown key version in GetActive response")
		}
	}
}

func TestKVLGetPrimary(t *testing.T) {
	d := []byte("test")
	v1 := types.KeyVersion{1, d, types.Primary, 10}
	v2 := types.KeyVersion{2, d, types.Active, 10}
	v3 := types.KeyVersion{3, d, types.Inactive, 10}
	kvl := types.KeyVersionList([]types.KeyVersion{v1, v2, v3})
	keyVersion := kvl.GetPrimary()
	if keyVersion.ID != v1.ID {
		t.Error("Incorrect version returned from getPrimary")
	}
}

func TestMinComponentsValidator(t *testing.T) {
	validate := func(id string, minComponents int, valid bool) {
		err := types.ServicePrefixPathComponentsValidator(minComponents)(types.ServicePrefix, id)
		if valid && err != nil {
			t.Fatal("Should be valid, but was not:", id)
		}
		if !valid && err == nil {
			t.Fatal("Should not be valid, but was:", id)
		}
	}

	// Never valid w/o domain
	validate("spiffe://", 0, false)
	validate("spiffe://", 1, false)

	// Valid with domain only if min len is zero
	validate("spiffe://domain", 0, true)
	validate("spiffe://domain", 1, false)

	// If min len is 1, must have one path component
	validate("spiffe://domain/a", 0, true)
	validate("spiffe://domain/a", 1, true)
	validate("spiffe://domain/a", 2, false)

	// If min len is 2, must have two path components
	validate("spiffe://domain/a/b", 0, true)
	validate("spiffe://domain/a/b", 1, true)
	validate("spiffe://domain/a/b", 2, true)
	validate("spiffe://domain/a/b", 3, false)
}

func TestPrincipalValidation(t *testing.T) {
	validatePrincipal := func(principalType types.PrincipalType, id string, expected bool) {
		extraValidators := []types.PrincipalValidator{
			types.ServicePrefixPathComponentsValidator(1),
		}

		err := principalType.IsValidPrincipal(id, extraValidators)
		if err == nil && !expected {
			t.Errorf("Should not be valid, but is: '%s'", id)
		}
		if err != nil && expected {
			t.Errorf("Should be valid, but isn't: '%s' (error: %s)", id, err.Error())
		}
	}

	// -- Invalid examples --
	// Empty strings
	validatePrincipal(types.User, "", false)
	validatePrincipal(types.UserGroup, "", false)
	validatePrincipal(types.Machine, "", false)
	validatePrincipal(types.MachinePrefix, "", false)
	validatePrincipal(types.Service, "", false)
	validatePrincipal(types.ServicePrefix, "", false)

	// Not valid URLs
	validatePrincipal(types.Service, "not-a-url", false)
	validatePrincipal(types.ServicePrefix, "not-a-url", false)

	// Wrong URL scheme
	validatePrincipal(types.Service, "https://example.com", false)
	validatePrincipal(types.ServicePrefix, "https://example.com", false)

	// Not enough components
	validatePrincipal(types.ServicePrefix, "spiffe://example.com", false)
	validatePrincipal(types.ServicePrefix, "spiffe://example.com/", false)

	// No trailing slash
	validatePrincipal(types.ServicePrefix, "spiffe://example.com/foo", false)

	// -- Valid examples --
	validatePrincipal(types.User, "test", true)
	validatePrincipal(types.UserGroup, "test", true)
	validatePrincipal(types.Machine, "test", true)
	validatePrincipal(types.MachinePrefix, "test", true)
	validatePrincipal(types.Service, "spiffe://example.com/service", true)
	validatePrincipal(types.ServicePrefix, "spiffe://example.com/prefix/", true)
}
