package dbus

import (
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSessionManager_Simple tests basic session manager functionality.
func TestSessionManager_Simple(t *testing.T) {
	t.Run("Session_Lifecycle", func(t *testing.T) {
		// Test creating and managing sessions without D-Bus export
		session, output, err := NewSession(AlgorithmPlain)
		require.NoError(t, err)
		require.NotNil(t, session)
		require.Empty(t, output)

		// Test session path generation
		path := session.Path()
		assert.Contains(t, string(path), SessionPrefix)

		// Test session operations
		testData := []byte("test data")
		iv, ciphertext, err := session.Encrypt(testData)
		require.NoError(t, err)
		assert.Equal(t, testData, ciphertext) // Plain algorithm should not encrypt

		decrypted, err := session.Decrypt(iv, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, testData, decrypted)

		// Test session closure
		err = session.close()
		require.NoError(t, err)

		// Verify closed session cannot be used
		_, _, err = session.Encrypt(testData)
		require.Error(t, err)
	})

	t.Run("DH_AES_Session_Without_Export", func(t *testing.T) {
		// Test DH-AES session creation without D-Bus
		session, output, err := NewSession(AlgorithmDHAES)
		require.NoError(t, err)
		require.NotNil(t, session)
		require.NotEmpty(t, output)

		// Test that encryption fails without key exchange
		_, _, err = session.Encrypt([]byte("test"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "shared key not established")

		err = session.close()
		require.NoError(t, err)
	})
}

// TestSessionManager_Internal tests internal session manager methods.
func TestSessionManager_Internal(t *testing.T) {
	sessionMgr := NewSessionManager()

	t.Run("Session_Storage_And_Retrieval", func(t *testing.T) {
		// Create a session manually
		session, _, err := NewSession(AlgorithmPlain)
		require.NoError(t, err)

		// Manually add to session manager (simulating CreateSession)
		sessionMgr.mu.Lock()
		sessionMgr.sessions[session.id] = session
		sessionMgr.mu.Unlock()

		// Test retrieval
		retrieved, err := sessionMgr.GetSession(session.Path())
		require.NoError(t, err)
		assert.Equal(t, session.Path(), retrieved.Path())

		// Test closure with nil connection (should handle gracefully)
		err = sessionMgr.CloseSession(nil, session.Path()) // nil conn is OK for testing
		require.NoError(t, err)

		// Verify session is removed
		_, err = sessionMgr.GetSession(session.Path())
		require.Error(t, err)
	})

	t.Run("Session_Expiration_Logic", func(t *testing.T) {
		// Test session expiration logic directly
		session, _, err := NewSession(AlgorithmPlain)
		require.NoError(t, err)

		// Manually set old timestamps to simulate expired session
		session.createdAt = time.Now().Add(-2 * time.Hour)
		session.lastUsed = time.Now().Add(-30 * time.Minute)

		sessionMgr.mu.Lock()
		sessionMgr.sessions[session.id] = session
		sessionMgr.mu.Unlock()

		// Manually trigger cleanup
		sessionMgr.removeExpiredSessions()

		// Verify expired session was removed
		sessionMgr.mu.RLock()
		_, exists := sessionMgr.sessions[session.id]
		sessionMgr.mu.RUnlock()
		assert.False(t, exists, "Expired session should be removed")
	})
}

// TestSession_DBus_Interface tests D-Bus interface methods.
func TestSession_DBus_Interface(t *testing.T) {
	t.Run("Session_CloseDBus", func(t *testing.T) {
		session, _, err := NewSession(AlgorithmPlain)
		require.NoError(t, err)

		// Test Close method (D-Bus interface)
		dbusErr := session.Close()
		require.Nil(t, dbusErr)

		// Verify session is closed
		_, _, err = session.Encrypt([]byte("test"))
		require.Error(t, err)
	})

	t.Run("Session_Introspect", func(t *testing.T) {
		session, _, err := NewSession(AlgorithmPlain)
		require.NoError(t, err)

		// Test Introspect method
		node := session.Introspect()
		require.NotNil(t, node)
		assert.NotEmpty(t, node.Interfaces)

		// Verify it contains expected interfaces
		foundSession := false
		foundIntrospectable := false
		for _, iface := range node.Interfaces {
			if iface.Name == SessionInterface {
				foundSession = true
			}
			if iface.Name == "org.freedesktop.DBus.Introspectable" {
				foundIntrospectable = true
			}
		}
		assert.True(t, foundSession, "Should contain Session interface")
		assert.True(t, foundIntrospectable, "Should contain Introspectable interface")
	})
}

// TestSession_Error_Conditions tests error handling.
func TestSession_Error_Conditions(t *testing.T) {
	t.Run("Invalid_Algorithm", func(t *testing.T) {
		_, _, err := NewSession("invalid-algorithm")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported algorithm")
	})

	t.Run("Closed_Session_Operations", func(t *testing.T) {
		session, _, err := NewSession(AlgorithmPlain)
		require.NoError(t, err)

		err = session.close()
		require.NoError(t, err)

		// All operations should fail on closed session
		_, _, err = session.Encrypt([]byte("test"))
		require.Error(t, err)

		_, err = session.Decrypt([]byte{}, []byte("test"))
		require.Error(t, err)

		err = session.CompleteKeyExchange([]byte("key"))
		require.Error(t, err)
	})

	t.Run("DH_AES_Without_KeyExchange", func(t *testing.T) {
		session, _, err := NewSession(AlgorithmDHAES)
		require.NoError(t, err)

		// Operations should fail without key exchange
		_, _, err = session.Encrypt([]byte("test"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "shared key not established")

		_, err = session.Decrypt([]byte{}, []byte("test"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "shared key not established")
	})
}

// TestSessionManager_Concurrent tests concurrent access patterns.
func TestSessionManager_Concurrent(t *testing.T) {
	sessionMgr := NewSessionManager()

	t.Run("Concurrent_Session_Creation", func(t *testing.T) {
		const numGoroutines = 5
		done := make(chan bool, numGoroutines)

		for range numGoroutines {
			go func() {
				session, _, err := NewSession(AlgorithmPlain)
				assert.NoError(t, err)
				assert.NotNil(t, session)

				// Manually add to session manager
				sessionMgr.mu.Lock()
				sessionMgr.sessions[session.id] = session
				sessionMgr.mu.Unlock()

				done <- true
			}()
		}

		for range numGoroutines {
			<-done
		}

		// Verify all sessions were created
		sessionMgr.mu.RLock()
		assert.Equal(t, numGoroutines, len(sessionMgr.sessions))
		sessionMgr.mu.RUnlock()
	})
}

// TestSession_Path_Helpers tests path generation helpers.
func TestSession_Path_Helpers(t *testing.T) {
	t.Run("Path_Generation", func(t *testing.T) {
		sessionID := "test-session-123"
		path := makeSessionPath(sessionID)
		assert.Equal(t, dbus.ObjectPath(SessionPrefix+sessionID), path)

		// Test collection path
		collectionName := "test-collection"
		collectionPath := makeCollectionPath(collectionName)
		assert.Equal(t, dbus.ObjectPath(CollectionPrefix+collectionName), collectionPath)

		// Test item path
		itemPath := makeItemPath(collectionName, "test-item")
		assert.Equal(t, dbus.ObjectPath(CollectionPrefix+collectionName+"/test-item"), itemPath)
	})
}
