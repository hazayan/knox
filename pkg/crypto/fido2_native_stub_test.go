//go:build !libfido2

package crypto_test

import (
	"testing"

	"github.com/hazayan/knox/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFido2WrappingProviderRequiresLibfido2BuildTagWithoutFakeSecret(t *testing.T) {
	metadata, err := crypto.NewFido2Metadata("fixture-knox", "Fixture Knox", crypto.DefaultFido2DeriveInfo)
	require.NoError(t, err)
	provider, err := crypto.NewFido2WrappingKeyProvider(metadata, []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	provider.HMACSecret = nil

	_, err = provider.WrappingKey()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "built without libfido2 support")
}
