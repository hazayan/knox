//go:build libfido2 && cgo

package crypto_test

import (
	"os"
	"testing"

	"github.com/hazayan/knox/pkg/crypto"
	"github.com/stretchr/testify/require"
)

func TestFido2NativeEnrollAndDerive(t *testing.T) {
	if os.Getenv("KNOX_FIDO2_INTEGRATION") != "1" {
		t.Skip("set KNOX_FIDO2_INTEGRATION=1 to create a real FIDO2 credential")
	}
	options := crypto.Fido2DeviceOptions{
		Device:  os.Getenv("KNOX_FIDO2_DEVICE"),
		PinFile: os.Getenv("KNOX_FIDO2_PIN_FILE"),
	}
	metadata, err := crypto.EnrollFido2Metadata("knox-integration", "Knox integration", crypto.DefaultFido2DeriveInfo, options)
	require.NoError(t, err)
	provider, err := crypto.NewFido2WrappingKeyProviderFromMetadataFileWithOptions(writeFido2Metadata(t, metadata), options)
	require.NoError(t, err)

	key, err := provider.WrappingKey()

	require.NoError(t, err)
	require.Len(t, key, crypto.MasterKeyLen)
}

func writeFido2Metadata(t *testing.T, metadata crypto.Fido2CredentialMetadata) string {
	t.Helper()
	path := t.TempDir() + "/fido2.json"
	require.NoError(t, crypto.SaveFido2Metadata(path, metadata))
	return path
}
