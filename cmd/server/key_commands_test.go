package main

import (
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/hazayan/knox/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyCommandsInitUnlockBackupRestore(t *testing.T) {
	dir := t.TempDir()
	metadataPath := filepath.Join(dir, "fido2.json")
	backupMetadataPath := filepath.Join(dir, "backup-fido2.json")
	bundlePath := filepath.Join(dir, "master.key.fido2")
	backupPath := filepath.Join(dir, "master.key.backup")
	restoredPath := filepath.Join(dir, "master.key.restored")
	t.Setenv(crypto.FakeFido2SecretEnvironmentValue, base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))

	cmd := newKeyFido2EnrollCommand()
	cmd.SetArgs([]string{
		"--metadata-file", metadataPath,
		"--rp-id", "ishum-knox",
		"--rp-name", "ishum Knox",
	})
	require.NoError(t, cmd.Execute())
	assert.FileExists(t, metadataPath)

	backupMetadata, err := crypto.NewFido2Metadata("ishum-knox-backup", "ishum Knox backup", crypto.DefaultFido2BackupDeriveInfo)
	require.NoError(t, err)
	require.NoError(t, crypto.SaveFido2Metadata(backupMetadataPath, backupMetadata))

	cmd = newKeyInitCommand()
	cmd.SetArgs([]string{
		"--backend", "fido2",
		"--encrypted-key-file", bundlePath,
		"--fido2-metadata-file", metadataPath,
	})
	require.NoError(t, cmd.Execute())
	assert.FileExists(t, bundlePath)

	cmd = newKeyUnlockTestCommand()
	cmd.SetArgs([]string{
		"--backend", "fido2",
		"--encrypted-key-file", bundlePath,
		"--fido2-metadata-file", metadataPath,
	})
	require.NoError(t, cmd.Execute())

	cmd = newKeyBackupCommand()
	cmd.SetArgs([]string{
		"--backend", "fido2",
		"--encrypted-key-file", bundlePath,
		"--fido2-metadata-file", metadataPath,
		"--backup-fido2-metadata-file", backupMetadataPath,
		"--output", backupPath,
	})
	require.NoError(t, cmd.Execute())
	assert.FileExists(t, backupPath)

	cmd = newKeyRestoreCommand()
	cmd.SetArgs([]string{
		"--backend", "fido2",
		"--encrypted-key-file", restoredPath,
		"--fido2-metadata-file", metadataPath,
		"--backup-fido2-metadata-file", backupMetadataPath,
		"--input", backupPath,
	})
	require.NoError(t, cmd.Execute())
	assert.FileExists(t, restoredPath)

	original, err := crypto.DecryptMasterKeyBundleFile(bundlePath, mustWrappingProvider(t, metadataPath))
	require.NoError(t, err)
	restored, err := crypto.DecryptMasterKeyBundleFile(restoredPath, mustWrappingProvider(t, metadataPath))
	require.NoError(t, err)
	assert.Equal(t, original, restored)
}

func TestKeyMigrateCommand(t *testing.T) {
	dir := t.TempDir()
	metadataPath := filepath.Join(dir, "fido2.json")
	plainPath := filepath.Join(dir, "master.key")
	bundlePath := filepath.Join(dir, "master.key.fido2")
	t.Setenv(crypto.FakeFido2SecretEnvironmentValue, base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))

	metadata, err := crypto.NewFido2Metadata("ishum-knox", "ishum Knox", crypto.DefaultFido2DeriveInfo)
	require.NoError(t, err)
	require.NoError(t, crypto.SaveFido2Metadata(metadataPath, metadata))
	masterKey, err := crypto.GenerateMasterKey()
	require.NoError(t, err)
	require.NoError(t, crypto.SaveMasterKeyToFile(masterKey, plainPath))
	t.Setenv("KNOX_MASTER_KEY", base64.StdEncoding.EncodeToString([]byte("abcdef0123456789abcdef0123456789")))

	cmd := newKeyMigrateCommand()
	cmd.SetArgs([]string{
		"--backend", "fido2",
		"--encrypted-key-file", bundlePath,
		"--fido2-metadata-file", metadataPath,
		"--master-key-file", plainPath,
	})
	require.NoError(t, cmd.Execute())

	loaded, err := crypto.DecryptMasterKeyBundleFile(bundlePath, mustWrappingProvider(t, metadataPath))
	require.NoError(t, err)
	assert.Equal(t, masterKey, loaded)
}

func mustWrappingProvider(t *testing.T, metadataPath string) crypto.WrappingKeyProvider {
	t.Helper()
	provider, err := crypto.NewFido2WrappingKeyProviderFromMetadataFile(metadataPath)
	require.NoError(t, err)
	return provider
}
