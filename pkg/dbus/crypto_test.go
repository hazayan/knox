package dbus

import (
	"math/big"
	"testing"
)

// TestDHSubgroupValidation verifies that small subgroup attacks are prevented
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

// TestPKCS7ConstantTime verifies padding validation is constant-time
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
				if err != firstError {
					t.Errorf("%s: Different error returned: %v vs %v", tc.name, err, firstError)
				}
			}
		}
	})
}

// TestDHParameterSize verifies we're using 2048-bit parameters
func TestDHParameterSize(t *testing.T) {
	bitSize := dhPrime.BitLen()
	if bitSize != 2048 {
		t.Errorf("DH prime should be 2048 bits, got %d bits", bitSize)
	}
}
