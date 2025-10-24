package dbus

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSessionEncryption tests the complete DH-AES session encryption flow.
func TestSessionEncryption(t *testing.T) {
	t.Run("DH_AES_Complete_Flow", func(t *testing.T) {
		// Create two sessions to simulate client and server
		serverSession, serverOutput, err := NewSession(AlgorithmDHAES)
		require.NoError(t, err)
		require.NotNil(t, serverSession)
		require.NotEmpty(t, serverOutput)

		clientSession, clientOutput, err := NewSession(AlgorithmDHAES)
		require.NoError(t, err)
		require.NotNil(t, clientSession)
		require.NotEmpty(t, clientOutput)

		// Exchange public keys and complete key exchange
		err = serverSession.CompleteKeyExchange(clientOutput)
		require.NoError(t, err)

		err = clientSession.CompleteKeyExchange(serverOutput)
		require.NoError(t, err)

		// Test encryption and decryption
		testData := []byte("This is a test secret that needs to be encrypted securely")

		// Server encrypts data
		iv, ciphertext, err := serverSession.Encrypt(testData)
		require.NoError(t, err)
		require.NotEmpty(t, iv)
		require.NotEmpty(t, ciphertext)
		require.NotEqual(t, testData, ciphertext, "Ciphertext should not match plaintext")

		// Client decrypts data
		decrypted, err := clientSession.Decrypt(iv, ciphertext)
		require.NoError(t, err)
		require.Equal(t, testData, decrypted, "Decrypted data should match original")

		// Verify bidirectional encryption works
		testData2 := []byte("Another test message for bidirectional verification")

		// Client encrypts data
		iv2, ciphertext2, err := clientSession.Encrypt(testData2)
		require.NoError(t, err)
		require.NotEmpty(t, iv2)
		require.NotEmpty(t, ciphertext2)

		// Server decrypts data
		decrypted2, err := serverSession.Decrypt(iv2, ciphertext2)
		require.NoError(t, err)
		require.Equal(t, testData2, decrypted2, "Bidirectional decryption should work")

		// Clean up
		err = serverSession.close()
		require.NoError(t, err)

		err = clientSession.close()
		require.NoError(t, err)
	})

	t.Run("Plain_Session_Flow", func(t *testing.T) {
		session, output, err := NewSession(AlgorithmPlain)
		require.NoError(t, err)
		require.NotNil(t, session)
		require.Empty(t, output) // Plain sessions should have empty output

		testData := []byte("Test data for plain session")

		// Plain session should not encrypt data
		iv, ciphertext, err := session.Encrypt(testData)
		require.NoError(t, err)
		require.Empty(t, iv)
		require.Equal(t, testData, ciphertext, "Plain session should return unencrypted data")

		// Plain session should not decrypt data
		decrypted, err := session.Decrypt(iv, ciphertext)
		require.NoError(t, err)
		require.Equal(t, testData, decrypted, "Plain session should return unmodified data")

		err = session.close()
		require.NoError(t, err)
	})

	t.Run("Session_Reuse_Prevention", func(t *testing.T) {
		session, _, err := NewSession(AlgorithmDHAES)
		require.NoError(t, err)

		err = session.close()
		require.NoError(t, err)

		// Attempt to use closed session
		_, _, err = session.Encrypt([]byte("test"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "closed")

		_, err = session.Decrypt([]byte{}, []byte("test"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "closed")
	})

	t.Run("DH_AES_Invalid_Key_Exchange", func(t *testing.T) {
		session, _, err := NewSession(AlgorithmDHAES)
		require.NoError(t, err)

		// Test with invalid public key (empty)
		err = session.CompleteKeyExchange([]byte{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid peer public key")

		// Test with invalid public key (all zeros)
		invalidKey := make([]byte, 256) // 2048-bit key should be 256 bytes
		err = session.CompleteKeyExchange(invalidKey)
		require.Error(t, err)

		err = session.close()
		require.NoError(t, err)
	})

	t.Run("Session_Algorithm_Validation", func(t *testing.T) {
		// Test unsupported algorithm
		_, _, err := NewSession("unsupported-algorithm")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported algorithm")

		// Test DH-AES session with plain operations
		session, _, err := NewSession(AlgorithmDHAES)
		require.NoError(t, err)

		// Should fail to encrypt/decrypt without key exchange
		_, _, err = session.Encrypt([]byte("test"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "shared key not established")

		_, err = session.Decrypt([]byte{}, []byte("test"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "shared key not established")

		err = session.close()
		require.NoError(t, err)
	})

	t.Run("Session_Concurrent_Access", func(t *testing.T) {
		session, output, err := NewSession(AlgorithmDHAES)
		require.NoError(t, err)

		// Create a second session for key exchange
		peerSession, peerOutput, err := NewSession(AlgorithmDHAES)
		require.NoError(t, err)

		// Complete key exchange
		err = session.CompleteKeyExchange(peerOutput)
		require.NoError(t, err)
		err = peerSession.CompleteKeyExchange(output)
		require.NoError(t, err)

		testData := []byte("Concurrent access test data")

		// Test concurrent encryption
		done := make(chan bool, 2)
		for range 2 {
			go func() {
				_, _, err := session.Encrypt(testData)
				assert.NoError(t, err)
				done <- true
			}()
		}

		// Wait for both goroutines to complete
		<-done
		<-done

		// Test concurrent decryption
		iv, ciphertext, err := session.Encrypt(testData)
		require.NoError(t, err)

		for range 2 {
			go func() {
				decrypted, err := session.Decrypt(iv, ciphertext)
				assert.NoError(t, err)
				assert.Equal(t, testData, decrypted)
				done <- true
			}()
		}

		// Wait for both goroutines to complete
		<-done
		<-done

		err = session.close()
		require.NoError(t, err)
		err = peerSession.close()
		require.NoError(t, err)
	})

	t.Run("Session_Path_Generation", func(t *testing.T) {
		session, _, err := NewSession(AlgorithmPlain)
		require.NoError(t, err)

		path := session.Path()
		require.NotEmpty(t, path)
		assert.Contains(t, string(path), SessionPrefix)

		err = session.close()
		require.NoError(t, err)
	})

	t.Run("Session_Key_Clearing", func(t *testing.T) {
		session, output, err := NewSession(AlgorithmDHAES)
		require.NoError(t, err)

		// Complete key exchange to establish shared key
		peerSession, peerOutput, err := NewSession(AlgorithmDHAES)
		require.NoError(t, err)
		err = session.CompleteKeyExchange(peerOutput)
		require.NoError(t, err)
		err = peerSession.CompleteKeyExchange(output)
		require.NoError(t, err)

		// Verify encryption works before closing
		testData := []byte("Test data before close")
		_, ciphertext, err := session.Encrypt(testData)
		require.NoError(t, err)
		require.NotEmpty(t, ciphertext)

		// Close session (should clear keys)
		err = session.close()
		require.NoError(t, err)

		// Verify encryption fails after closing
		_, _, err = session.Encrypt(testData)
		require.Error(t, err)

		err = peerSession.close()
		require.NoError(t, err)
	})
}
