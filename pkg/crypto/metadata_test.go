package crypto

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCryptoMetadata_Marshal(t *testing.T) {
	t.Run("ValidMetadata", func(t *testing.T) {
		metadata := &CryptoMetadata{
			Algorithm:    "AES-256-GCM",
			EncryptedDEK: "base64-encrypted-key",
			Version:      1,
		}

		data, err := metadata.Marshal()
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		// Verify the marshaled data can be unmarshaled back
		var unmarshaled CryptoMetadata
		err = json.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)
		assert.Equal(t, metadata.Algorithm, unmarshaled.Algorithm)
		assert.Equal(t, metadata.EncryptedDEK, unmarshaled.EncryptedDEK)
		assert.Equal(t, metadata.Version, unmarshaled.Version)
	})

	t.Run("EmptyFields", func(t *testing.T) {
		metadata := &CryptoMetadata{
			Algorithm:    "",
			EncryptedDEK: "",
			Version:      0,
		}

		data, err := metadata.Marshal()
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		// Should still marshal successfully even with empty fields
		var unmarshaled CryptoMetadata
		err = json.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)
		assert.Equal(t, metadata.Algorithm, unmarshaled.Algorithm)
		assert.Equal(t, metadata.EncryptedDEK, unmarshaled.EncryptedDEK)
		assert.Equal(t, metadata.Version, unmarshaled.Version)
	})
}

func TestUnmarshalCryptoMetadata(t *testing.T) {
	t.Run("ValidJSON", func(t *testing.T) {
		validJSON := `{"algorithm":"AES-256-GCM","encrypted_dek":"abc123","version":1}`
		metadata, err := UnmarshalCryptoMetadata([]byte(validJSON))
		require.NoError(t, err)
		assert.Equal(t, "AES-256-GCM", metadata.Algorithm)
		assert.Equal(t, "abc123", metadata.EncryptedDEK)
		assert.Equal(t, 1, metadata.Version)
	})

	t.Run("MissingAlgorithm", func(t *testing.T) {
		invalidJSON := `{"encrypted_dek":"abc123","version":1}`
		metadata, err := UnmarshalCryptoMetadata([]byte(invalidJSON))
		assert.Error(t, err)
		assert.Nil(t, metadata)
		assert.Contains(t, err.Error(), "missing algorithm")
	})

	t.Run("MissingEncryptedDEK", func(t *testing.T) {
		invalidJSON := `{"algorithm":"AES-256-GCM","version":1}`
		metadata, err := UnmarshalCryptoMetadata([]byte(invalidJSON))
		assert.Error(t, err)
		assert.Nil(t, metadata)
		assert.Contains(t, err.Error(), "missing encrypted DEK")
	})

	t.Run("MissingVersion", func(t *testing.T) {
		invalidJSON := `{"algorithm":"AES-256-GCM","encrypted_dek":"abc123"}`
		metadata, err := UnmarshalCryptoMetadata([]byte(invalidJSON))
		assert.Error(t, err)
		assert.Nil(t, metadata)
		assert.Contains(t, err.Error(), "missing version")
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		invalidJSON := `{"algorithm":"AES-256-GCM","encrypted_dek":"abc123","version":1`
		metadata, err := UnmarshalCryptoMetadata([]byte(invalidJSON))
		assert.Error(t, err)
		assert.Nil(t, metadata)
		assert.Contains(t, err.Error(), "failed to unmarshal crypto metadata")
	})

	t.Run("EmptyJSON", func(t *testing.T) {
		metadata, err := UnmarshalCryptoMetadata([]byte("{}"))
		assert.Error(t, err)
		assert.Nil(t, metadata)
		assert.Contains(t, err.Error(), "missing algorithm")
	})

	t.Run("NullJSON", func(t *testing.T) {
		metadata, err := UnmarshalCryptoMetadata([]byte("null"))
		assert.Error(t, err)
		assert.Nil(t, metadata)
		assert.Contains(t, err.Error(), "missing algorithm")
	})

	t.Run("EmptyString", func(t *testing.T) {
		metadata, err := UnmarshalCryptoMetadata([]byte(""))
		assert.Error(t, err)
		assert.Nil(t, metadata)
		assert.Contains(t, err.Error(), "failed to unmarshal crypto metadata")
	})

	t.Run("WhitespaceOnly", func(t *testing.T) {
		metadata, err := UnmarshalCryptoMetadata([]byte("   "))
		assert.Error(t, err)
		assert.Nil(t, metadata)
		assert.Contains(t, err.Error(), "failed to unmarshal crypto metadata")
	})

	t.Run("VersionZero", func(t *testing.T) {
		invalidJSON := `{"algorithm":"AES-256-GCM","encrypted_dek":"abc123","version":0}`
		metadata, err := UnmarshalCryptoMetadata([]byte(invalidJSON))
		assert.Error(t, err)
		assert.Nil(t, metadata)
		assert.Contains(t, err.Error(), "missing version")
	})

	t.Run("NegativeVersion", func(t *testing.T) {
		invalidJSON := `{"algorithm":"AES-256-GCM","encrypted_dek":"abc123","version":-1}`
		metadata, err := UnmarshalCryptoMetadata([]byte(invalidJSON))
		assert.NoError(t, err)
		assert.NotNil(t, metadata)
		assert.Equal(t, -1, metadata.Version)
	})
}

func TestCryptoMetadata_RoundTrip(t *testing.T) {
	t.Run("CompleteRoundTrip", func(t *testing.T) {
		original := &CryptoMetadata{
			Algorithm:    "AES-256-GCM",
			EncryptedDEK: "very-long-base64-encoded-key-data-here",
			Version:      2,
		}

		// Marshal
		data, err := original.Marshal()
		require.NoError(t, err)

		// Unmarshal
		restored, err := UnmarshalCryptoMetadata(data)
		require.NoError(t, err)

		// Compare
		assert.Equal(t, original.Algorithm, restored.Algorithm)
		assert.Equal(t, original.EncryptedDEK, restored.EncryptedDEK)
		assert.Equal(t, original.Version, restored.Version)
	})

	t.Run("WithSpecialCharacters", func(t *testing.T) {
		original := &CryptoMetadata{
			Algorithm:    "AES-256-GCM+PKCS7",
			EncryptedDEK: "base64+with+plus+and/slash==",
			Version:      3,
		}

		data, err := original.Marshal()
		require.NoError(t, err)

		restored, err := UnmarshalCryptoMetadata(data)
		require.NoError(t, err)

		assert.Equal(t, original.Algorithm, restored.Algorithm)
		assert.Equal(t, original.EncryptedDEK, restored.EncryptedDEK)
		assert.Equal(t, original.Version, restored.Version)
	})
}

func TestCryptoMetadata_FieldValidation(t *testing.T) {
	testCases := []struct {
		name         string
		algorithm    string
		encryptedDEK string
		version      int
		shouldError  bool
		errorMsg     string
	}{
		{
			name:         "AllFieldsValid",
			algorithm:    "AES-256-GCM",
			encryptedDEK: "key123",
			version:      1,
			shouldError:  false,
		},
		{
			name:         "EmptyAlgorithm",
			algorithm:    "",
			encryptedDEK: "key123",
			version:      1,
			shouldError:  true,
			errorMsg:     "missing algorithm",
		},
		{
			name:         "EmptyEncryptedDEK",
			algorithm:    "AES-256-GCM",
			encryptedDEK: "",
			version:      1,
			shouldError:  true,
			errorMsg:     "missing encrypted DEK",
		},
		{
			name:         "ZeroVersion",
			algorithm:    "AES-256-GCM",
			encryptedDEK: "key123",
			version:      0,
			shouldError:  true,
			errorMsg:     "missing version",
		},
		{
			name:         "AllFieldsMissing",
			algorithm:    "",
			encryptedDEK: "",
			version:      0,
			shouldError:  true,
			errorMsg:     "missing algorithm",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jsonData := []byte(`{"algorithm":"` + tc.algorithm + `","encrypted_dek":"` + tc.encryptedDEK + `","version":` + strconv.Itoa(tc.version) + `}`)
			metadata, err := UnmarshalCryptoMetadata(jsonData)

			if tc.shouldError {
				assert.Error(t, err)
				assert.Nil(t, metadata)
				if tc.errorMsg != "" {
					assert.Contains(t, err.Error(), tc.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, metadata)
				assert.Equal(t, tc.algorithm, metadata.Algorithm)
				assert.Equal(t, tc.encryptedDEK, metadata.EncryptedDEK)
				assert.Equal(t, tc.version, metadata.Version)
			}
		})
	}
}
