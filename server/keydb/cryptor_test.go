package keydb

import (
	"testing"

	"github.com/hazayan/knox/pkg/types"
)

var testSecret = []byte("testtesttesttest")

func makeTestKey() *types.Key {
	return &types.Key{
		ID:          "testID",
		ACL:         types.ACL([]types.Access{{Type: types.User, ID: "testUser", AccessType: types.Read}}),
		VersionList: types.KeyVersionList([]types.KeyVersion{makeTestVersion()}),
		VersionHash: "testHash",
	}
}

func makeTestVersion() types.KeyVersion {
	return types.KeyVersion{
		ID:           12345,
		Data:         []byte("data"),
		Status:       types.Primary,
		CreationTime: 1,
	}
}

func TestEncryptDecryptVersion(t *testing.T) {
	k := makeTestKey()
	dbKey := &DBKey{
		ID:          k.ID,
		ACL:         k.ACL,
		VersionHash: k.VersionHash,
	}
	v := k.VersionList.GetPrimary()
	crypt := &aesGCMCryptor{testSecret, 10}
	encV, err := crypt.EncryptVersion(k, v)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	decV, err := crypt.decryptVersion(dbKey, encV)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if decV.ID != v.ID || !equalBytes(decV.Data, v.Data) || decV.Status != v.Status || decV.CreationTime != v.CreationTime {
		t.Fatal("decrypted key does not equal key")
	}
}

func TestEncryptDecryptKey(t *testing.T) {
	k := makeTestKey()
	crypt := NewAESGCMCryptor(10, testSecret)
	encK, err := crypt.Encrypt(k)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	decK, err := crypt.Decrypt(encK)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	if decK.ID != k.ID || !equalACL(decK.ACL, k.ACL) || decK.VersionHash != k.VersionHash || len(decK.VersionList) != len(k.VersionList) {
		t.Fatal("decrypted key does not equal key")
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

// equalACL compares two ACLs for equality.
func equalACL(a, b types.ACL) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].AccessType != b[i].AccessType || a[i].Type != b[i].Type {
			return false
		}
	}
	return true
}

func TestBadKeyData(t *testing.T) {
	k := makeTestKey()
	crypt := NewAESGCMCryptor(0, []byte("notAESlen"))
	_, err := crypt.Encrypt(k)
	if err == nil {
		t.Fatal("error is nil for a bad key")
	}

	_, err = crypt.Decrypt(&DBKey{VersionList: []EncKeyVersion{{CryptoMetadata: []byte{0}}}})
	if err == nil {
		t.Fatal("error is nil for bad data")
	}
}

func TestBadCryptorVersion(t *testing.T) {
	k := makeTestKey()
	crypt := NewAESGCMCryptor(10, testSecret)
	encK, err := crypt.Encrypt(k)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}

	crypt2 := NewAESGCMCryptor(1, testSecret)
	_, err = crypt2.Decrypt(encK)
	if err == nil {
		t.Fatal("err is nil on bad crypter version")
	}
}

func TestBadCiphertext(t *testing.T) {
	k := makeTestKey()
	crypt := NewAESGCMCryptor(10, testSecret)
	encK, err := crypt.Encrypt(k)
	if err != nil {
		t.Fatalf("%s is not nil", err)
	}
	encK.VersionList[0].EncData = []byte("invalidciphertext")
	_, err = crypt.Decrypt(encK)
	if err == nil {
		t.Fatal("error is nil for bad ciphertext")
	}
}

func TestAESMetadata(t *testing.T) {
	version := byte(1)
	nonce := []byte("abcd")
	cm := buildMetadata(version, nonce)
	if string(cm.Nonce()) != string(nonce) {
		t.Fatalf("nonces are not equal: %s expected: %s", string(cm.Nonce()), string(nonce))
	}
	if cm.Version() != version {
		t.Fatalf("%d does not equal %d", cm.Version(), version)
	}
}
