package crypto_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hazayan/knox/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testFido2Provider(t *testing.T, info string) *crypto.Fido2WrappingKeyProvider {
	t.Helper()
	metadata, err := crypto.NewFido2Metadata("identity-a-knox", "identity-a Knox", info)
	require.NoError(t, err)
	provider, err := crypto.NewFido2WrappingKeyProvider(metadata, []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	return provider
}

func TestFido2MetadataRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fido2.json")
	metadata, err := crypto.NewFido2Metadata("identity-a-knox", "identity-a Knox", crypto.DefaultFido2DeriveInfo)
	require.NoError(t, err)

	err = crypto.SaveFido2Metadata(path, metadata)
	require.NoError(t, err)

	loaded, err := crypto.LoadFido2Metadata(path)
	require.NoError(t, err)
	assert.Equal(t, metadata.RPID, loaded.RPID)
	assert.Equal(t, metadata.CredentialID, loaded.CredentialID)
	assert.Equal(t, "0600", fileMode(t, path))
}

func TestFido2WrappingKeyDerivationIsStableAndDomainSeparated(t *testing.T) {
	providerA := testFido2Provider(t, "knox master key fido2 v1")
	providerB, err := crypto.NewFido2WrappingKeyProvider(providerA.Metadata, []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	metadataC := providerA.Metadata
	metadataC.DeriveInfo = "different"
	providerC, err := crypto.NewFido2WrappingKeyProvider(metadataC, []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)

	keyA, err := providerA.WrappingKey()
	require.NoError(t, err)
	keyB, err := providerB.WrappingKey()
	require.NoError(t, err)
	keyC, err := providerC.WrappingKey()
	require.NoError(t, err)

	assert.Equal(t, keyA, keyB)
	assert.NotEqual(t, keyA, keyC)
}

func TestMasterKeyBundleRoundTrip(t *testing.T) {
	provider := testFido2Provider(t, crypto.DefaultFido2DeriveInfo)
	masterKey, err := crypto.GenerateMasterKey()
	require.NoError(t, err)

	bundle, err := crypto.EncryptMasterKeyBundle(masterKey, provider, crypto.MasterKeyBundleKind)
	require.NoError(t, err)

	var parsed crypto.MasterKeyBundle
	require.NoError(t, json.Unmarshal(bundle, &parsed))
	assert.Equal(t, crypto.MasterKeyBundleKind, parsed.Kind)
	assert.Equal(t, "fido2", parsed.Encryption.Backend)
	assert.NotContains(t, string(bundle), base64.StdEncoding.EncodeToString(masterKey))

	decrypted, err := crypto.DecryptMasterKeyBundle(bundle, provider, crypto.MasterKeyBundleKind)
	require.NoError(t, err)
	assert.Equal(t, masterKey, decrypted)
}

func TestMasterKeyBundleRejectsWrongWrappingKey(t *testing.T) {
	provider := testFido2Provider(t, crypto.DefaultFido2DeriveInfo)
	wrongProvider, err := crypto.NewFido2WrappingKeyProvider(provider.Metadata, []byte("abcdef0123456789abcdef0123456789"))
	require.NoError(t, err)
	masterKey, err := crypto.GenerateMasterKey()
	require.NoError(t, err)
	bundle, err := crypto.EncryptMasterKeyBundle(masterKey, provider, crypto.MasterKeyBundleKind)
	require.NoError(t, err)

	_, err = crypto.DecryptMasterKeyBundle(bundle, wrongProvider, crypto.MasterKeyBundleKind)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt")
}

func TestMasterKeyBackupAndRestore(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "master.key.fido2")
	provider := testFido2Provider(t, crypto.DefaultFido2DeriveInfo)
	backupProvider := testFido2Provider(t, crypto.DefaultFido2BackupDeriveInfo)
	masterKey, err := crypto.GenerateMasterKey()
	require.NoError(t, err)
	bundle, err := crypto.EncryptMasterKeyBundle(masterKey, provider, crypto.MasterKeyBundleKind)
	require.NoError(t, err)
	require.NoError(t, crypto.WriteMasterKeyBundleFile(bundlePath, bundle))

	backup, err := crypto.BackupMasterKeyBundle(bundlePath, provider, backupProvider)
	require.NoError(t, err)
	restoredBundle, err := crypto.RestoreMasterKeyBundle(backup, backupProvider, provider)
	require.NoError(t, err)
	restored, err := crypto.DecryptMasterKeyBundle(restoredBundle, provider, crypto.MasterKeyBundleKind)
	require.NoError(t, err)

	assert.Equal(t, masterKey, restored)
}

func TestLoadMasterKeyWithFido2ConfigUsesBundle(t *testing.T) {
	dir := t.TempDir()
	metadataPath := filepath.Join(dir, "fido2.json")
	bundlePath := filepath.Join(dir, "master.key.fido2")
	secret := []byte("0123456789abcdef0123456789abcdef")
	t.Setenv(crypto.FakeFido2SecretEnvironmentValue, base64.StdEncoding.EncodeToString(secret))

	metadata, err := crypto.NewFido2Metadata("identity-a-knox", "identity-a Knox", crypto.DefaultFido2DeriveInfo)
	require.NoError(t, err)
	require.NoError(t, crypto.SaveFido2Metadata(metadataPath, metadata))
	provider, err := crypto.NewFido2WrappingKeyProvider(metadata, secret)
	require.NoError(t, err)
	masterKey, err := crypto.GenerateMasterKey()
	require.NoError(t, err)
	bundle, err := crypto.EncryptMasterKeyBundle(masterKey, provider, crypto.MasterKeyBundleKind)
	require.NoError(t, err)
	require.NoError(t, crypto.WriteMasterKeyBundleFile(bundlePath, bundle))

	loaded, err := crypto.LoadMasterKeyWithConfig(crypto.MasterKeyConfig{
		Backend:          "fido2",
		EncryptedKeyFile: bundlePath,
		MetadataFile:     metadataPath,
	})
	require.NoError(t, err)
	assert.Equal(t, masterKey, loaded)
}

func fileMode(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	return fmt.Sprintf("%04o", info.Mode().Perm())
}
