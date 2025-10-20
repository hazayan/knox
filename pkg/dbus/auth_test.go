package dbus

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/pbkdf2"
)

func TestNewAuthManager(t *testing.T) {
	am := NewAuthManager()
	require.NotNil(t, am)

	enabled, locked, attempts := am.GetStatus()
	assert.True(t, enabled || !locked, "if enabled, should start locked; if disabled, should be unlocked")
	assert.Equal(t, 0, attempts)
}

func TestAuthManager_Authenticate_Success(t *testing.T) {
	tempDir := t.TempDir()
	configDir := filepath.Join(tempDir, "knox")
	require.NoError(t, os.MkdirAll(configDir, 0o700))
	authFile := filepath.Join(configDir, "dbus-auth")

	// Create auth manager and generate password
	am := &AuthManager{
		locked:            true,
		lockTimeout:       15 * time.Minute,
		lastActivity:      time.Now(),
		maxAuthAttempts:   5,
		lockAfterAttempts: 3,
		enabled:           true,
	}

	err := am.generateMasterPassword(authFile)
	require.NoError(t, err)

	// Save a known password - must be exactly 32 bytes
	am.salt = make([]byte, 32)
	copy(am.salt, []byte("test-salt"))

	am.masterPassword = make([]byte, 32)
	copy(am.masterPassword, []byte("test-master-password"))

	require.NoError(t, am.saveMasterPasswordToFile(authFile))

	// Reload to verify we can load it back
	data, err := os.ReadFile(authFile)
	require.NoError(t, err)

	am2 := &AuthManager{
		locked:            true,
		maxAuthAttempts:   5,
		lockAfterAttempts: 3,
		enabled:           true,
	}
	require.NoError(t, am2.loadMasterPassword(data))

	// The passwords should match
	assert.Equal(t, am.salt, am2.salt)
	assert.Equal(t, am.masterPassword, am2.masterPassword)
}

func TestAuthManager_Authenticate_WhenDisabled(t *testing.T) {
	am := &AuthManager{
		enabled: false,
		locked:  false,
	}

	success, err := am.Authenticate("any-password")
	assert.NoError(t, err)
	assert.True(t, success)
}

func TestAuthManager_Authenticate_MaxAttemptsExceeded(t *testing.T) {
	am := &AuthManager{
		enabled:         true,
		locked:          true,
		authAttempts:    5,
		maxAuthAttempts: 5,
		salt:            make([]byte, 32),
		masterPassword:  make([]byte, 32),
	}

	success, err := am.Authenticate("wrong-password")
	assert.Error(t, err)
	assert.False(t, success)
	assert.Contains(t, err.Error(), "maximum authentication attempts exceeded")
}

func TestAuthManager_Authenticate_WrongPassword(t *testing.T) {
	am := &AuthManager{
		enabled:         true,
		locked:          true,
		authAttempts:    0,
		maxAuthAttempts: 5,
		salt:            []byte("test-salt-32-bytes-----------32"),
		masterPassword:  []byte("correct-password-32-bytes----32"),
	}

	success, err := am.Authenticate("wrong-password")
	assert.Error(t, err)
	assert.False(t, success)
	assert.Contains(t, err.Error(), "authentication failed")
	assert.Equal(t, 1, am.authAttempts)
}

func TestAuthManager_IsLocked(t *testing.T) {
	t.Run("WhenDisabled", func(t *testing.T) {
		am := &AuthManager{
			enabled: false,
			locked:  true,
		}
		assert.False(t, am.IsLocked())
	})

	t.Run("WhenLocked", func(t *testing.T) {
		am := &AuthManager{
			enabled:      true,
			locked:       true,
			lastActivity: time.Now(),
			lockTimeout:  15 * time.Minute,
		}
		assert.True(t, am.IsLocked())
	})

	t.Run("WhenUnlockedButTimedOut", func(t *testing.T) {
		am := &AuthManager{
			enabled:      true,
			locked:       false,
			lastActivity: time.Now().Add(-20 * time.Minute),
			lockTimeout:  15 * time.Minute,
		}
		assert.True(t, am.IsLocked())
	})

	t.Run("WhenUnlockedAndActive", func(t *testing.T) {
		am := &AuthManager{
			enabled:      true,
			locked:       false,
			lastActivity: time.Now(),
			lockTimeout:  15 * time.Minute,
		}
		assert.False(t, am.IsLocked())
	})
}

func TestAuthManager_UpdateActivity(t *testing.T) {
	t.Run("WhenEnabled", func(t *testing.T) {
		am := &AuthManager{
			enabled:      true,
			lastActivity: time.Now().Add(-1 * time.Hour),
		}

		oldTime := am.lastActivity
		time.Sleep(10 * time.Millisecond)
		am.UpdateActivity()

		assert.True(t, am.lastActivity.After(oldTime))
	})

	t.Run("WhenDisabled", func(t *testing.T) {
		am := &AuthManager{
			enabled:      false,
			lastActivity: time.Now().Add(-1 * time.Hour),
		}

		oldTime := am.lastActivity
		am.UpdateActivity()

		assert.Equal(t, oldTime, am.lastActivity)
	})
}

func TestAuthManager_Lock(t *testing.T) {
	t.Run("WhenEnabled", func(t *testing.T) {
		am := &AuthManager{
			enabled: true,
			locked:  false,
		}

		am.Lock()
		assert.True(t, am.locked)
	})

	t.Run("WhenDisabled", func(t *testing.T) {
		am := &AuthManager{
			enabled: false,
			locked:  false,
		}

		am.Lock()
		assert.False(t, am.locked)
	})
}

func TestAuthManager_Unlock(t *testing.T) {
	am := &AuthManager{
		enabled:         true,
		locked:          true,
		authAttempts:    0,
		maxAuthAttempts: 5,
		salt:            []byte("test-salt-32-bytes-----------32"),
		masterPassword:  make([]byte, 32),
	}

	// Unlock is just an alias for Authenticate
	success, err := am.Unlock("test-password")
	assert.Error(t, err)
	assert.False(t, success)
}

func TestAuthManager_ChangePassword_WhenDisabled(t *testing.T) {
	am := &AuthManager{
		enabled: false,
	}

	success, err := am.ChangePassword("old", "new")
	assert.NoError(t, err)
	assert.True(t, success)
}

func TestAuthManager_ChangePassword_WrongOldPassword(t *testing.T) {
	am := &AuthManager{
		enabled:        true,
		salt:           []byte("test-salt-32-bytes-----------32"),
		masterPassword: []byte("correct-password-32-bytes----32"),
	}

	success, err := am.ChangePassword("wrong-old-password", "new-password")
	assert.Error(t, err)
	assert.False(t, success)
	assert.Contains(t, err.Error(), "current password is incorrect")
}

func TestAuthManager_ChangePassword_Success(t *testing.T) {
	tempDir := t.TempDir()
	knoxDir := filepath.Join(tempDir, "knox")
	require.NoError(t, os.MkdirAll(knoxDir, 0o700))

	// Set XDG_CONFIG_HOME for this test
	t.Setenv("XDG_CONFIG_HOME", tempDir)

	am := &AuthManager{
		enabled:        true,
		salt:           make([]byte, 32),
		masterPassword: make([]byte, 32),
		authAttempts:   3,
	}

	// Set a known old password by deriving it
	copy(am.salt, []byte("test-salt-32-bytes-----------32"))
	oldKey := pbkdf2.Key([]byte("old-password"), am.salt, 100000, 32, sha256.New)
	copy(am.masterPassword, oldKey)

	success, err := am.ChangePassword("old-password", "new-password")
	assert.NoError(t, err)
	assert.True(t, success)
	assert.Equal(t, 0, am.authAttempts)
	assert.NotEqual(t, oldKey, am.masterPassword)
}

func TestAuthManager_SetEnabled(t *testing.T) {
	t.Run("Disable", func(t *testing.T) {
		am := &AuthManager{
			enabled: true,
			locked:  true,
		}

		am.SetEnabled(false)
		assert.False(t, am.enabled)
		assert.False(t, am.locked)
	})

	t.Run("Enable", func(t *testing.T) {
		am := &AuthManager{
			enabled: false,
			locked:  false,
		}

		am.SetEnabled(true)
		assert.True(t, am.enabled)
	})
}

func TestAuthManager_SetAutoLockTimeout(t *testing.T) {
	am := &AuthManager{
		lockTimeout: 15 * time.Minute,
	}

	am.SetAutoLockTimeout(30 * time.Minute)
	assert.Equal(t, 30*time.Minute, am.lockTimeout)
}

func TestAuthManager_GetStatus(t *testing.T) {
	am := &AuthManager{
		enabled:      true,
		locked:       true,
		authAttempts: 2,
	}

	enabled, locked, attempts := am.GetStatus()
	assert.True(t, enabled)
	assert.True(t, locked)
	assert.Equal(t, 2, attempts)
}

func TestAuthManager_loadOrGenerateMasterPassword(t *testing.T) {
	tempDir := t.TempDir()

	// Set XDG_CONFIG_HOME for this test
	t.Setenv("XDG_CONFIG_HOME", tempDir)

	am := &AuthManager{}
	err := am.loadOrGenerateMasterPassword()
	assert.NoError(t, err)
	assert.NotNil(t, am.salt)
	assert.NotNil(t, am.masterPassword)
}

func TestAuthManager_generateMasterPassword(t *testing.T) {
	tempDir := t.TempDir()
	authFile := filepath.Join(tempDir, "test-auth")

	am := &AuthManager{}
	err := am.generateMasterPassword(authFile)
	assert.NoError(t, err)
	assert.NotNil(t, am.salt)
	assert.NotNil(t, am.masterPassword)
	assert.Len(t, am.salt, 32)
	assert.Len(t, am.masterPassword, 32)

	// Verify file was created
	_, err = os.Stat(authFile)
	assert.NoError(t, err)
}

func TestAuthManager_loadMasterPassword_InvalidFormat(t *testing.T) {
	am := &AuthManager{}

	// Too short
	err := am.loadMasterPassword([]byte("short"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid auth file format")
}

func TestAuthManager_loadMasterPassword_InvalidBase64(t *testing.T) {
	am := &AuthManager{}

	// 32 bytes salt + 64 bytes of invalid base64
	data := make([]byte, 96)
	copy(data[:32], []byte("test-salt-32-bytes-----------32"))
	copy(data[32:], []byte("!!!invalid-base64-data-that-is-64-bytes-long------------------!!"))

	err := am.loadMasterPassword(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode master password")
}

func TestAuthManager_loadMasterPassword_Success(t *testing.T) {
	am := &AuthManager{}

	// Create valid auth data - must be exactly 32 bytes
	salt := make([]byte, 32)
	copy(salt, []byte("test-salt-32-bytes"))

	masterPassword := make([]byte, 32)
	copy(masterPassword, []byte("test-master-password"))

	encodedMasterPassword := base64.StdEncoding.EncodeToString(masterPassword)

	data := make([]byte, 32+len(encodedMasterPassword))
	copy(data[:32], salt)
	copy(data[32:], []byte(encodedMasterPassword))

	err := am.loadMasterPassword(data)
	assert.NoError(t, err)
	assert.Equal(t, salt, am.salt)
	assert.Equal(t, masterPassword, am.masterPassword)
}

func TestAuthManager_saveMasterPassword(t *testing.T) {
	tempDir := t.TempDir()
	knoxDir := filepath.Join(tempDir, "knox")
	require.NoError(t, os.MkdirAll(knoxDir, 0o700))

	// Set XDG_CONFIG_HOME for this test
	t.Setenv("XDG_CONFIG_HOME", tempDir)

	am := &AuthManager{
		salt:           []byte("test-salt-32-bytes-----------32"),
		masterPassword: []byte("test-master-password-32-bytes32"),
	}

	err := am.saveMasterPassword()
	assert.NoError(t, err)

	// Verify file was created
	authFile := filepath.Join(knoxDir, "dbus-auth")
	_, err = os.Stat(authFile)
	assert.NoError(t, err)
}

func TestAuthManager_saveMasterPasswordToFile(t *testing.T) {
	tempDir := t.TempDir()
	authFile := filepath.Join(tempDir, "test-auth")

	salt := make([]byte, 32)
	copy(salt, []byte("test-salt"))

	masterPassword := make([]byte, 32)
	copy(masterPassword, []byte("test-master-password"))

	am := &AuthManager{
		salt:           salt,
		masterPassword: masterPassword,
	}

	err := am.saveMasterPasswordToFile(authFile)
	assert.NoError(t, err)

	// Verify file contents
	data, err := os.ReadFile(authFile)
	assert.NoError(t, err)

	// Should be 32 bytes salt + base64 encoded master password
	assert.True(t, len(data) >= 32)
	assert.Equal(t, am.salt, data[:32])
}

func TestCompareKeys(t *testing.T) {
	t.Run("Equal", func(t *testing.T) {
		a := []byte("test-key-32-bytes-long-------32")
		b := []byte("test-key-32-bytes-long-------32")
		assert.True(t, compareKeys(a, b))
	})

	t.Run("NotEqual", func(t *testing.T) {
		a := []byte("test-key-32-bytes-long-------32")
		b := []byte("different-key-32-bytes-long--32")
		assert.False(t, compareKeys(a, b))
	})

	t.Run("DifferentLength", func(t *testing.T) {
		a := []byte("short")
		b := []byte("much-longer-key")
		assert.False(t, compareKeys(a, b))
	})
}

func TestNewAuthPromptHandler(t *testing.T) {
	am := NewAuthManager()
	handler := NewAuthPromptHandler(am)
	require.NotNil(t, handler)
	assert.Equal(t, am, handler.authManager)
}

func TestAuthPromptHandler_HandleUnlockPrompt(t *testing.T) {
	t.Run("WithEnvironmentPassword", func(t *testing.T) {
		// Set environment variable
		testPassword := "test-env-password"
		t.Setenv("KNOX_DBUS_PASSWORD", testPassword)

		am := &AuthManager{
			enabled:         true,
			locked:          true,
			authAttempts:    0,
			maxAuthAttempts: 5,
			salt:            make([]byte, 32),
			masterPassword:  make([]byte, 32),
		}

		handler := NewAuthPromptHandler(am)
		success, err := handler.HandleUnlockPrompt("test-prompt")
		// Will fail auth but should attempt with env password
		assert.Error(t, err)
		assert.False(t, success)
	})

	t.Run("WithDefaultPassword", func(t *testing.T) {
		// Clear environment variable
		oldEnv := os.Getenv("KNOX_DBUS_PASSWORD")
		if err := os.Unsetenv("KNOX_DBUS_PASSWORD"); err != nil {
			t.Logf("Failed to unset KNOX_DBUS_PASSWORD: %v", err)
		}
		defer func() {
			if oldEnv != "" {
				t.Setenv("KNOX_DBUS_PASSWORD", oldEnv)
			}
		}()

		am := &AuthManager{
			enabled:         true,
			locked:          true,
			authAttempts:    0,
			maxAuthAttempts: 5,
			salt:            make([]byte, 32),
			masterPassword:  make([]byte, 32),
		}

		handler := NewAuthPromptHandler(am)
		success, err := handler.HandleUnlockPrompt("test-prompt")
		// Will fail auth but should attempt with default password
		assert.Error(t, err)
		assert.False(t, success)
	})
}

func TestAuthPromptHandler_HandleChangePasswordPrompt(t *testing.T) {
	am := NewAuthManager()
	handler := NewAuthPromptHandler(am)

	success, oldPass, newPass, err := handler.HandleChangePasswordPrompt("test-prompt")
	assert.Error(t, err)
	assert.False(t, success)
	assert.Empty(t, oldPass)
	assert.Empty(t, newPass)
	assert.Contains(t, err.Error(), "password change not implemented")
}

func TestAuthPromptHandler_IsAuthenticationRequired(t *testing.T) {
	am := &AuthManager{
		enabled: true,
		locked:  true,
	}
	handler := NewAuthPromptHandler(am)

	tests := []struct {
		operation string
		required  bool
	}{
		{"GetSecrets", true},
		{"CreateItem", true},
		{"SetSecret", true},
		{"Delete", true},
		{"CreateCollection", true},
		{"DeleteCollection", true},
		{"SetAlias", true},
		{"SearchItems", false},
		{"GetCollections", false},
		{"UnknownOperation", false},
	}

	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			result := handler.IsAuthenticationRequired(tt.operation)
			assert.Equal(t, tt.required, result)
		})
	}
}

func TestAuthPromptHandler_IsAuthenticationRequired_WhenUnlocked(t *testing.T) {
	am := &AuthManager{
		enabled:      true,
		locked:       false,
		lastActivity: time.Now(),
		lockTimeout:  15 * time.Minute,
	}
	handler := NewAuthPromptHandler(am)

	// Even locked operations should not require auth when unlocked
	assert.False(t, handler.IsAuthenticationRequired("GetSecrets"))
	assert.False(t, handler.IsAuthenticationRequired("CreateItem"))
}

func TestAuthPromptHandler_GetAuthenticationPromptMessage(t *testing.T) {
	am := NewAuthManager()
	handler := NewAuthPromptHandler(am)

	tests := []struct {
		operation       string
		expectedContain string
	}{
		{"GetSecrets", "access secrets"},
		{"CreateItem", "create new secret"},
		{"SetSecret", "modify secret"},
		{"Delete", "delete secret"},
		{"CreateCollection", "create collection"},
		{"DeleteCollection", "delete collection"},
		{"SetAlias", "set alias"},
		{"UnknownOperation", "Authentication required"},
	}

	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			msg := handler.GetAuthenticationPromptMessage(tt.operation)
			assert.Contains(t, msg, tt.expectedContain)
		})
	}
}
