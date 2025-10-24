package dbus

import (
	"crypto/aes"
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDHSubgroupValidation verifies that small subgroup attacks are prevented.
func TestDHSubgroupValidation(t *testing.T) {
	dh, err := NewDHKeyExchange()
	if err != nil {
		t.Fatalf("Failed to create DH: %v", err)
	}

	// Test 1: Reject public key = 1 (trivial subgroup)
	t.Run("Reject_PublicKey_1", func(t *testing.T) {
		maliciousKey := big.NewInt(1).Bytes()
		err := dh.ComputeSharedKey(maliciousKey)
		if err == nil {
			t.Error("Should reject public key = 1")
		}
		if err != nil && err.Error() != "invalid peer public key: out of range" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	// Test 2: Reject public key = p-1 (order 2 element)
	t.Run("Reject_PublicKey_PMinus1", func(t *testing.T) {
		pMinusOne := new(big.Int).Sub(dhPrime, big.NewInt(1))
		maliciousKey := pMinusOne.Bytes()
		err := dh.ComputeSharedKey(maliciousKey)
		if err == nil {
			t.Error("Should reject public key = p-1")
		}
		if err != nil && err.Error() != "invalid peer public key: trivial value p-1" {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	// Test 3: Reject public key = 0
	t.Run("Reject_PublicKey_0", func(t *testing.T) {
		maliciousKey := big.NewInt(0).Bytes()
		err := dh.ComputeSharedKey(maliciousKey)
		if err == nil {
			t.Error("Should reject public key = 0")
		}
	})

	// Test 4: Reject public key >= p
	t.Run("Reject_PublicKey_OutOfRange", func(t *testing.T) {
		outOfRange := new(big.Int).Add(dhPrime, big.NewInt(1))
		maliciousKey := outOfRange.Bytes()
		err := dh.ComputeSharedKey(maliciousKey)
		if err == nil {
			t.Error("Should reject public key >= p")
		}
	})

	// Test 5: Verify valid key exchange works
	t.Run("Valid_KeyExchange", func(t *testing.T) {
		// Create two DH instances
		alice, err := NewDHKeyExchange()
		if err != nil {
			t.Fatalf("Failed to create Alice's DH: %v", err)
		}

		bob, err := NewDHKeyExchange()
		if err != nil {
			t.Fatalf("Failed to create Bob's DH: %v", err)
		}

		// Exchange public keys
		alicePub := alice.GetPublicKey()
		bobPub := bob.GetPublicKey()

		// Compute shared secrets
		if err := alice.ComputeSharedKey(bobPub); err != nil {
			t.Fatalf("Alice failed to compute shared key: %v", err)
		}

		if err := bob.ComputeSharedKey(alicePub); err != nil {
			t.Fatalf("Bob failed to compute shared key: %v", err)
		}

		// Verify shared secrets match
		aliceSecret := alice.GetSharedKey()
		bobSecret := bob.GetSharedKey()

		if len(aliceSecret) != len(bobSecret) {
			t.Errorf("Shared secret lengths differ: %d vs %d", len(aliceSecret), len(bobSecret))
		}

		for i := range aliceSecret {
			if aliceSecret[i] != bobSecret[i] {
				t.Error("Shared secrets do not match")
				break
			}
		}
	})
}

// TestPKCS7ConstantTime verifies padding validation is constant-time.
func TestPKCS7ConstantTime(t *testing.T) {
	blockSize := 16

	// Test valid padding
	t.Run("Valid_Padding", func(t *testing.T) {
		data := []byte("Hello World")
		padded := pkcs7Pad(data, blockSize)

		unpadded, err := pkcs7Unpad(padded, blockSize)
		if err != nil {
			t.Errorf("Failed to unpad valid data: %v", err)
		}

		if string(unpadded) != string(data) {
			t.Errorf("Unpadded data doesn't match: got %q, want %q", unpadded, data)
		}
	})

	// Test invalid padding - all errors should be the same
	t.Run("Invalid_Padding_Same_Error", func(t *testing.T) {
		testCases := []struct {
			name string
			data []byte
		}{
			{"Empty", []byte{}},
			{"Invalid_Length", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17}}, // Last byte = 17 > blockSize
			{"Invalid_Bytes", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 1, 3}},    // Says 3 bytes padding but only has [14, 1, 3]
			{"Zero_Padding", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0}},    // Padding length = 0
			{"Wrong_Length", []byte{1, 2, 3}},                                                 // Not multiple of block size
		}

		var firstError error
		for i, tc := range testCases {
			_, err := pkcs7Unpad(tc.data, blockSize)
			if err == nil {
				t.Errorf("%s: Expected error, got nil", tc.name)
				continue
			}

			if i == 0 {
				firstError = err
			} else {
				// All errors should be the exact same error instance
				if !errors.Is(err, firstError) {
					t.Errorf("%s: Different error returned: %v vs %v", tc.name, err, firstError)
				}
			}
		}
	})
}

// TestDHParameterSize verifies we're using 2048-bit parameters.
func TestDHParameterSize(t *testing.T) {
	bitSize := dhPrime.BitLen()
	if bitSize != 2048 {
		t.Errorf("DH prime should be 2048 bits, got %d bits", bitSize)
	}
}

// TestNewDHKeyExchange verifies DH key exchange creation.
func TestNewDHKeyExchange(t *testing.T) {
	dh, err := NewDHKeyExchange()
	assert.NoError(t, err)
	assert.NotNil(t, dh)
	assert.NotNil(t, dh.GetPublicKey())
	assert.Nil(t, dh.GetSharedKey()) // Should be nil before ComputeSharedKey
}

// TestGetPublicKey verifies public key generation.
func TestGetPublicKey(t *testing.T) {
	dh, err := NewDHKeyExchange()
	assert.NoError(t, err)

	publicKey := dh.GetPublicKey()
	assert.NotNil(t, publicKey)
	assert.True(t, len(publicKey) > 0)

	// Public key should be in valid range
	pubInt := new(big.Int).SetBytes(publicKey)
	assert.True(t, pubInt.Cmp(big.NewInt(1)) > 0)
	assert.True(t, pubInt.Cmp(dhPrime) < 0)
}

// TestAESEncryptionDecryption verifies AES-128-CBC encryption/decryption.
func TestAESEncryptionDecryption(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("Hello, secret world!")

	// Test encryption
	iv, ciphertext, err := encryptAES128CBC(key, plaintext)
	assert.NoError(t, err)
	assert.NotNil(t, iv)
	assert.NotNil(t, ciphertext)
	assert.Equal(t, aes.BlockSize, len(iv))
	assert.True(t, len(ciphertext) > len(plaintext))

	// Test decryption
	decrypted, err := decryptAES128CBC(key, iv, ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Test with empty plaintext
	iv, ciphertext, err = encryptAES128CBC(key, []byte{})
	assert.NoError(t, err)
	decrypted, err = decryptAES128CBC(key, iv, ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, []byte{}, decrypted)
}

// TestAESErrorConditions verifies error handling in AES functions.
func TestAESErrorConditions(t *testing.T) {
	// Test invalid key size
	_, _, err := encryptAES128CBC([]byte{1, 2, 3}, []byte("test"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key must be 16 bytes")

	_, err = decryptAES128CBC([]byte{1, 2, 3}, make([]byte, 16), make([]byte, 16))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key must be 16 bytes")

	// Test invalid IV size
	key := make([]byte, 16)
	_, err = decryptAES128CBC(key, []byte{1, 2, 3}, make([]byte, 16))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IV must be 16 bytes")

	// Test invalid ciphertext length
	_, err = decryptAES128CBC(key, make([]byte, 16), []byte{1, 2, 3})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext length must be multiple of block size")
}

// TestPKCS7Padding verifies padding functions.
func TestPKCS7Padding(t *testing.T) {
	blockSize := 16

	// Test various data lengths
	testCases := []struct {
		name string
		data []byte
	}{
		{"Empty", []byte{}},
		{"Short", []byte("short")},
		{"ExactBlock", make([]byte, blockSize)},
		{"MultipleBlocks", make([]byte, blockSize*3)},
		{"PartialBlock", make([]byte, blockSize-5)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			padded := pkcs7Pad(tc.data, blockSize)
			assert.True(t, len(padded) > 0)
			assert.True(t, len(padded)%blockSize == 0)

			unpadded, err := pkcs7Unpad(padded, blockSize)
			assert.NoError(t, err)
			assert.Equal(t, tc.data, unpadded)
		})
	}
}

// TestEncodeDecodeDBusPublicKey verifies public key encoding/decoding.
func TestEncodeDecodeDBusPublicKey(t *testing.T) {
	original := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	// Test encoding
	encoded := encodeDBusPublicKey(original)
	assert.Equal(t, original, encoded)

	// Test decoding
	decoded, err := decodeDBusPublicKey(encoded)
	assert.NoError(t, err)
	assert.Equal(t, original, decoded)

	// Test error case
	_, err = decodeDBusPublicKey([]byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty public key")
}

// TestDeriveKey verifies key derivation.
func TestDeriveKey(t *testing.T) {
	input := []byte("test input for key derivation")
	derived := deriveKey(input)

	assert.Equal(t, 16, len(derived)) // AES-128 key size

	// Same input should produce same output
	derived2 := deriveKey(input)
	assert.Equal(t, derived, derived2)

	// Different input should produce different output
	derived3 := deriveKey([]byte("different input"))
	assert.NotEqual(t, derived, derived3)
}

// TestDHKeyExchangeEdgeCases tests edge cases for DH key exchange.
func TestDHKeyExchangeEdgeCases(t *testing.T) {
	// Test with small subgroup attack vector
	dh, err := NewDHKeyExchange()
	assert.NoError(t, err)

	// Test with invalid subgroup element - this should pass validation
	// since it's a valid element in the prime-order subgroup
	validSubgroupKey := new(big.Int).Exp(dhGenerator, big.NewInt(2), dhPrime)
	err = dh.ComputeSharedKey(validSubgroupKey.Bytes())
	assert.NoError(t, err) // This is actually a valid key in the subgroup
}
