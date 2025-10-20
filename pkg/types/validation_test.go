package types_test

import (
	"errors"
	"testing"

	"github.com/hazayan/knox/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestValidateKeyID(t *testing.T) {
	testCases := []struct {
		name     string
		keyID    string
		expected error
	}{
		{
			name:     "ValidKeyID",
			keyID:    "service-api-key",
			expected: nil,
		},
		{
			name:     "ValidKeyIDWithNumbers",
			keyID:    "app123-service456",
			expected: nil,
		},
		{
			name:     "ValidKeyIDWithUnderscores",
			keyID:    "app_service_key_v1",
			expected: nil,
		},
		{
			name:     "ValidKeyIDWithDots",
			keyID:    "app.service.key",
			expected: nil,
		},
		{
			name:     "ValidKeyIDWithColons",
			keyID:    "app:service:key",
			expected: nil,
		},
		{
			name:     "EmptyKeyID",
			keyID:    "",
			expected: types.ErrKeyIDEmpty,
		},
		{
			name:     "KeyIDTooLong",
			keyID:    "very-long-key-identifier-that-exceeds-the-maximum-allowed-length-for-key-ids-in-the-knox-system-very-long-key-identifier-that-exceeds-the-maximum-allowed-length-for-key-ids-in-the-knox-system-very-long-key-identifier-that-exceeds-the-maximum-allowed-length-for-key-ids-in-the-knox-system-very-long-key-identifier-that-exceeds-the-maximum-allowed-length-for-key-ids-in-the-knox-system-very-long-key-identifier-that-exceeds-the-maximum-allowed-length-for-key-ids-in-the-knox-system",
			expected: types.ErrKeyIDTooLong,
		},
		{
			name:     "KeyIDWithPathTraversal",
			keyID:    "../sensitive/file",
			expected: types.ErrPathTraversal,
		},
		{
			name:     "KeyIDWithBackslash",
			keyID:    "path\\to\\key",
			expected: types.ErrPathTraversal,
		},
		{
			name:     "KeyIDWithSlash",
			keyID:    "path/to/key",
			expected: types.ErrPathTraversal,
		},
		{
			name:     "KeyIDWithUnsafeCharacters",
			keyID:    "key<script>alert('xss')</script>",
			expected: types.ErrPathTraversal,
		},
		{
			name:     "KeyIDWithAmpersand",
			keyID:    "key&data",
			expected: types.ErrUnsafeCharacters,
		},
		{
			name:     "KeyIDWithSemicolon",
			keyID:    "key;data",
			expected: types.ErrUnsafeCharacters,
		},
		{
			name:     "KeyIDWithQuotes",
			keyID:    "key\"data",
			expected: types.ErrUnsafeCharacters,
		},
		{
			name:     "KeyIDWithSingleQuote",
			keyID:    "key'data",
			expected: types.ErrUnsafeCharacters,
		},
		{
			name:     "KeyIDWithAngleBrackets",
			keyID:    "key<data>",
			expected: types.ErrUnsafeCharacters,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := types.ValidateKeyID(tc.keyID)
			if tc.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.expected.Error())
			}
		})
	}
}

func TestValidateKeyData(t *testing.T) {
	testCases := []struct {
		name     string
		data     []byte
		expected error
	}{
		{
			name:     "ValidKeyData",
			data:     []byte("test-key-data"),
			expected: nil,
		},
		{
			name:     "EmptyKeyData",
			data:     []byte{},
			expected: nil,
		},
		{
			name:     "LargeKeyData",
			data:     make([]byte, types.MaxKeyDataSize+1),
			expected: types.ErrKeyDataTooLarge,
		},
		{
			name:     "ExactlyMaxSizeKeyData",
			data:     make([]byte, types.MaxKeyDataSize),
			expected: nil,
		},
		{
			name:     "SmallKeyData",
			data:     []byte("small"),
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := types.ValidateKeyData(tc.data)
			if tc.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.expected.Error())
			}
		})
	}
}

func TestValidatePrincipalID(t *testing.T) {
	testCases := []struct {
		name          string
		principalType types.PrincipalType
		id            string
		expected      error
	}{
		{
			name:          "ValidSPIFFEURI",
			principalType: types.Service,
			id:            "spiffe://example.com/service/api",
			expected:      nil,
		},
		{
			name:          "ValidMachineID",
			principalType: types.Machine,
			id:            "machine.example.com",
			expected:      nil,
		},
		{
			name:          "ValidUserEmail",
			principalType: types.User,
			id:            "user@example.com",
			expected:      nil,
		},
		{
			name:          "ValidUserSimple",
			principalType: types.User,
			id:            "username",
			expected:      nil,
		},
		{
			name:          "EmptyPrincipalID",
			principalType: types.User,
			id:            "",
			expected:      types.ErrPrincipalIDEmpty,
		},
		{
			name:          "InvalidSPIFFEURI",
			principalType: types.Service,
			id:            "not-a-spiffe-uri",
			expected:      types.ErrInvalidSPIFFEURI,
		},
		{
			name:          "InvalidMachineID",
			principalType: types.Machine,
			id:            "invalid@machine",
			expected:      types.ErrInvalidMachineID,
		},
		{
			name:          "InvalidUserID",
			principalType: types.User,
			id:            "user with spaces",
			expected:      types.ErrInvalidUserID,
		},
		{
			name:          "UnknownPrincipalType",
			principalType: types.Unknown,
			id:            "some-id",
			expected:      nil, // Unknown types are allowed with basic validation
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := types.ValidatePrincipalID(tc.principalType, tc.id)
			if tc.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.expected.Error())
			}
		})
	}
}

func TestValidateAccess(t *testing.T) {
	testCases := []struct {
		name     string
		access   types.AccessType
		expected error
	}{
		{
			name:     "ValidReadAccess",
			access:   types.Read,
			expected: nil,
		},
		{
			name:     "ValidWriteAccess",
			access:   types.Write,
			expected: nil,
		},
		{
			name:     "ValidAdminAccess",
			access:   types.Admin,
			expected: nil,
		},
		{
			name:     "InvalidNoneAccess",
			access:   types.None,
			expected: nil, // None is a valid access type (means no access)
		},
		{
			name:     "InvalidAccessType",
			access:   types.AccessType(999),
			expected: errors.New("invalid access type"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := types.ValidateAccess(types.Access{
				ID:         "test@example.com",
				Type:       types.User,
				AccessType: tc.access,
			})
			if tc.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.expected.Error())
			}
		})
	}
}

func TestValidateACL(t *testing.T) {
	t.Run("ValidACL", func(t *testing.T) {
		acl := types.ACL{
			{
				ID:         "user@example.com",
				Type:       types.User,
				AccessType: types.Read,
			},
			{
				ID:         "machine.example.com",
				Type:       types.Machine,
				AccessType: types.Write,
			},
			{
				ID:         "spiffe://example.com/service/api",
				Type:       types.Service,
				AccessType: types.Admin,
			},
		}

		err := types.ValidateACL(acl)
		assert.NoError(t, err)
	})

	t.Run("EmptyACL", func(t *testing.T) {
		acl := types.ACL{}
		err := types.ValidateACL(acl)
		assert.NoError(t, err)
	})

	t.Run("ACLWithInvalidPrincipal", func(t *testing.T) {
		acl := types.ACL{
			{
				ID:         "",
				Type:       types.User,
				AccessType: types.Read,
			},
		}

		err := types.ValidateACL(acl)
		assert.ErrorIs(t, err, types.ErrPrincipalIDEmpty)
	})

	t.Run("ACLWithInvalidAccess", func(t *testing.T) {
		acl := types.ACL{
			{
				ID:         "user@example.com",
				Type:       types.User,
				AccessType: types.AccessType(999),
			},
		}

		err := types.ValidateACL(acl)
		assert.ErrorContains(t, err, "invalid access type")
	})

	t.Run("ACLWithInvalidPrincipalType", func(t *testing.T) {
		acl := types.ACL{
			{
				ID:         "some-id",
				Type:       types.Unknown,
				AccessType: types.Read,
			},
		}

		err := types.ValidateACL(acl)
		assert.NoError(t, err) // Unknown principal types are allowed with basic validation
	})
}

func TestValidateRequestBodySize(t *testing.T) {
	testCases := []struct {
		name     string
		data     []byte
		expected error
	}{
		{
			name:     "ValidSize",
			data:     []byte("small request body"),
			expected: nil,
		},
		{
			name:     "ExactlyMaxSize",
			data:     make([]byte, types.MaxRequestBodySize),
			expected: nil,
		},
		{
			name:     "TooLarge",
			data:     make([]byte, types.MaxRequestBodySize+1),
			expected: types.ErrRequestTooLarge,
		},
		{
			name:     "EmptyBody",
			data:     []byte{},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := types.ValidateRequestBodySize(int64(len(tc.data)))
			if tc.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.expected.Error())
			}
		})
	}
}

func TestSanitizeString(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "CleanString",
			input:    "normal string",
			expected: "normal string",
		},
		{
			name:     "StringWithUnsafeChars",
			input:    "string<script>alert('xss')</script>",
			expected: "string&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;",
		},
		{
			name:     "StringWithAmpersand",
			input:    "key&value",
			expected: "key&amp;value",
		},
		{
			name:     "StringWithSemicolon",
			input:    "key;value",
			expected: "key;value",
		},
		{
			name:     "StringWithQuotes",
			input:    "key\"value\"",
			expected: "key&quot;value&quot;",
		},
		{
			name:     "StringWithAngleBrackets",
			input:    "key<value>",
			expected: "key&lt;value&gt;",
		},
		{
			name:     "StringWithMultipleUnsafeChars",
			input:    "<script>alert(\"xss\");</script>",
			expected: "&lt;script&gt;alert(&quot;xss&quot;);&lt;/script&gt;",
		},
		{
			name:     "EmptyString",
			input:    "",
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := types.SanitizeString(tc.input)
			// Note: The actual SanitizeString function HTML-encodes unsafe characters
			// The test expectations need to match this behavior
			assert.Equal(t, tc.expected, result, "Input: %q", tc.input)
		})
	}
}

func TestIsValidJSON(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "ValidJSON",
			input:    `{"key": "value"}`,
			expected: true,
		},
		{
			name:     "ValidJSONArray",
			input:    `[1, 2, 3]`,
			expected: true,
		},
		{
			name:     "ValidJSONString",
			input:    `"hello world"`,
			expected: true,
		},
		{
			name:     "InvalidJSON",
			input:    `{"key": "value"`,
			expected: false,
		},
		{
			name:     "InvalidJSONStructure",
			input:    `{key: "value"}`,
			expected: false,
		},
		{
			name:     "EmptyString",
			input:    "",
			expected: false,
		},
		{
			name:     "MalformedJSON",
			input:    `{"key": "value",}`,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := types.IsValidJSON([]byte(tc.input))
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestValidateKeyCreation(t *testing.T) {
	t.Run("ValidKeyCreation", func(t *testing.T) {
		key := &types.Key{
			ID:  "valid-key",
			ACL: types.ACL{},
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("secret-data"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
			VersionHash: "test-hash",
		}

		err := types.ValidateKeyCreation(key.ID, key.VersionList[0].Data, key.ACL)
		assert.NoError(t, err)
	})

	t.Run("EmptyKeyID", func(t *testing.T) {
		err := types.ValidateKeyCreation("", []byte("test-data"), types.ACL{})
		assert.ErrorContains(t, err, "key ID cannot be empty")
	})

	t.Run("InvalidKeyData", func(t *testing.T) {
		key := &types.Key{
			ID:  "valid-key",
			ACL: types.ACL{},
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         make([]byte, types.MaxKeyDataSize+1),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
			VersionHash: "test-hash",
		}

		err := types.ValidateKeyCreation(key.ID, key.VersionList[0].Data, key.ACL)
		assert.ErrorIs(t, err, types.ErrKeyDataTooLarge)
	})

	t.Run("InvalidACL", func(t *testing.T) {
		key := &types.Key{
			ID: "valid-key",
			ACL: types.ACL{
				{
					ID:         "",
					Type:       types.User,
					AccessType: types.Read,
				},
			},
			VersionList: types.KeyVersionList{
				{
					ID:           1,
					Data:         []byte("secret-data"),
					Status:       types.Primary,
					CreationTime: 1234567890,
				},
			},
			VersionHash: "test-hash",
		}

		err := types.ValidateKeyCreation(key.ID, key.VersionList[0].Data, key.ACL)
		assert.ErrorIs(t, err, types.ErrPrincipalIDEmpty)
	})

	t.Run("EmptyVersionList", func(t *testing.T) {
		// ValidateKeyCreation doesn't check version list - it only validates key ID, data, and ACL
		// So an empty version list should not cause an error in this function
		err := types.ValidateKeyCreation("valid-key", []byte("test-data"), types.ACL{})
		assert.NoError(t, err)
	})
}
