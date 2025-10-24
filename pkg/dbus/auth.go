// Package dbus implements the FreeDesktop Secret Service API.
// Spec: https://specifications.freedesktop.org/secret-service-spec/latest/
package dbus

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// AuthManager manages authentication and locking for the D-Bus bridge.
type AuthManager struct {
	mu                sync.RWMutex
	masterPassword    []byte
	salt              []byte
	locked            bool
	lockTimeout       time.Duration
	lastActivity      time.Time
	authAttempts      int
	maxAuthAttempts   int
	lockAfterAttempts int
	enabled           bool
}

// NewAuthManager creates a new authentication manager.
func NewAuthManager() *AuthManager {
	am := &AuthManager{
		locked:            true, // Start locked by default for security
		lockTimeout:       15 * time.Minute,
		lastActivity:      time.Now(),
		maxAuthAttempts:   5,
		lockAfterAttempts: 3,
		enabled:           true,
	}

	// Try to load existing master password or generate new one
	if err := am.loadOrGenerateMasterPassword(); err != nil {
		// If we can't load/generate, disable authentication
		am.enabled = false
		am.locked = false // Allow access without authentication
	}

	return am
}

// Authenticate attempts to authenticate with the provided password.
func (am *AuthManager) Authenticate(password string) (bool, error) {
	if !am.enabled {
		return true, nil // Always succeed if authentication is disabled
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	if am.authAttempts >= am.maxAuthAttempts {
		return false, errors.New("maximum authentication attempts exceeded")
	}

	// Derive key from provided password
	derivedKey := pbkdf2.Key([]byte(password), am.salt, 100000, 32, sha256.New)

	// Compare with stored master password
	if !compareKeys(derivedKey, am.masterPassword) {
		am.authAttempts++
		return false, fmt.Errorf("authentication failed (attempt %d/%d)", am.authAttempts, am.maxAuthAttempts)
	}

	// Authentication successful
	am.authAttempts = 0
	am.locked = false
	am.lastActivity = time.Now()
	return true, nil
}

// IsLocked returns whether the service is currently locked.
func (am *AuthManager) IsLocked() bool {
	if !am.enabled {
		return false // Never locked if authentication is disabled
	}

	am.mu.RLock()
	defer am.mu.RUnlock()

	// Check if we've been inactive for too long
	if !am.locked && time.Since(am.lastActivity) > am.lockTimeout {
		am.mu.RUnlock()
		am.mu.Lock()
		am.locked = true
		am.mu.Unlock()
		am.mu.RLock()
	}

	return am.locked
}

// UpdateActivity updates the last activity timestamp.
func (am *AuthManager) UpdateActivity() {
	if !am.enabled {
		return
	}

	am.mu.Lock()
	defer am.mu.Unlock()
	am.lastActivity = time.Now()
}

// Lock immediately locks the service.
func (am *AuthManager) Lock() {
	if !am.enabled {
		return
	}

	am.mu.Lock()
	defer am.mu.Unlock()
	am.locked = true
}

// Unlock unlocks the service with the provided password.
func (am *AuthManager) Unlock(password string) (bool, error) {
	return am.Authenticate(password)
}

// ChangePassword changes the master password.
func (am *AuthManager) ChangePassword(oldPassword, newPassword string) (bool, error) {
	if !am.enabled {
		return true, nil // Always succeed if authentication is disabled
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	// Verify old password
	oldDerivedKey := pbkdf2.Key([]byte(oldPassword), am.salt, 100000, 32, sha256.New)
	if !compareKeys(oldDerivedKey, am.masterPassword) {
		return false, errors.New("current password is incorrect")
	}

	// Generate new salt and derive new key
	newSalt := make([]byte, 32)
	if _, err := rand.Read(newSalt); err != nil {
		return false, fmt.Errorf("failed to generate new salt: %w", err)
	}

	newMasterPassword := pbkdf2.Key([]byte(newPassword), newSalt, 100000, 32, sha256.New)

	// Update stored values
	am.masterPassword = newMasterPassword
	am.salt = newSalt
	am.authAttempts = 0

	// Save to file
	if err := am.saveMasterPassword(); err != nil {
		return false, fmt.Errorf("failed to save new password: %w", err)
	}

	return true, nil
}

// SetEnabled enables or disables authentication.
func (am *AuthManager) SetEnabled(enabled bool) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.enabled = enabled
	if !enabled {
		am.locked = false
	}
}

// SetAutoLockTimeout sets the auto-lock timeout duration.
func (am *AuthManager) SetAutoLockTimeout(timeout time.Duration) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.lockTimeout = timeout
}

// GetStatus returns the current authentication status.
func (am *AuthManager) GetStatus() (bool, bool, int) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.enabled, am.locked, am.authAttempts
}

// Helper methods

// loadOrGenerateMasterPassword loads an existing master password or generates a new one.
func (am *AuthManager) loadOrGenerateMasterPassword() error {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	knoxDir := filepath.Join(configDir, "knox")
	if err := os.MkdirAll(knoxDir, 0o700); err != nil {
		return fmt.Errorf("failed to create knox directory: %w", err)
	}

	authFile := filepath.Join(knoxDir, "dbus-auth")

	// Try to load existing auth data
	// #nosec G304 -- authFile path is constructed from user's config directory, not user input
	if data, err := os.ReadFile(authFile); err == nil {
		return am.loadMasterPassword(data)
	}

	// Generate new master password
	return am.generateMasterPassword(authFile)
}

// generateMasterPassword generates a new random master password.
func (am *AuthManager) generateMasterPassword(authFile string) error {
	// Generate random salt
	am.salt = make([]byte, 32)
	if _, err := rand.Read(am.salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate random master password
	randomPassword := make([]byte, 32)
	if _, err := rand.Read(randomPassword); err != nil {
		return fmt.Errorf("failed to generate master password: %w", err)
	}

	// Derive key from random password
	am.masterPassword = pbkdf2.Key(randomPassword, am.salt, 100000, 32, sha256.New)

	// Clear the random password from memory
	for i := range randomPassword {
		randomPassword[i] = 0
	}

	// Save to file
	return am.saveMasterPasswordToFile(authFile)
}

// loadMasterPassword loads master password from data.
func (am *AuthManager) loadMasterPassword(data []byte) error {
	if len(data) < 32 { // Must have at least 32 bytes for salt
		return errors.New("invalid auth file format")
	}

	am.salt = make([]byte, 32)
	copy(am.salt, data[:32])

	encodedMasterPassword := data[32:]
	decoded, err := base64.StdEncoding.DecodeString(string(encodedMasterPassword))
	if err != nil {
		return fmt.Errorf("failed to decode master password: %w", err)
	}

	am.masterPassword = decoded
	return nil
}

// saveMasterPassword saves the current master password to the default location.
func (am *AuthManager) saveMasterPassword() error {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	authFile := filepath.Join(configDir, "knox", "dbus-auth")
	return am.saveMasterPasswordToFile(authFile)
}

// saveMasterPasswordToFile saves master password to a specific file.
func (am *AuthManager) saveMasterPasswordToFile(authFile string) error {
	// Encode master password
	encodedMasterPassword := base64.StdEncoding.EncodeToString(am.masterPassword)

	// Combine salt and encoded master password
	data := make([]byte, 32+len(encodedMasterPassword))
	copy(data[:32], am.salt)
	copy(data[32:], []byte(encodedMasterPassword))

	// Write to file with restricted permissions
	if err := os.WriteFile(authFile, data, 0o600); err != nil {
		return fmt.Errorf("failed to write auth file: %w", err)
	}

	return nil
}

// compareKeys compares two byte arrays in constant time to prevent timing attacks.
func compareKeys(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

// AuthPromptHandler handles authentication prompts.
type AuthPromptHandler struct {
	authManager *AuthManager
}

// NewAuthPromptHandler creates a new authentication prompt handler.
func NewAuthPromptHandler(authManager *AuthManager) *AuthPromptHandler {
	return &AuthPromptHandler{
		authManager: authManager,
	}
}

// HandleUnlockPrompt handles an unlock prompt.
func (h *AuthPromptHandler) HandleUnlockPrompt(_ string) (bool, error) {
	// In a real implementation, this would show a dialog to the user
	// For now, we'll use a simple approach that reads from environment
	// or uses a default password for development

	// Try to get password from environment
	password := os.Getenv("KNOX_DBUS_PASSWORD")
	if password == "" {
		// For development, use a default password
		// In production, this should be configured by the user
		password = "knox-default-password-change-me"
	}

	return h.authManager.Authenticate(password)
}

// HandleChangePasswordPrompt handles a change password prompt.
func (h *AuthPromptHandler) HandleChangePasswordPrompt(_ string) (bool, string, string, error) {
	// In a real implementation, this would show a dialog to the user
	// For now, return empty strings to indicate cancellation
	return false, "", "", errors.New("password change not implemented in this version")
}

// IsAuthenticationRequired checks if authentication is required for an operation.
func (h *AuthPromptHandler) IsAuthenticationRequired(operation string) bool {
	// Operations that require authentication when locked
	lockedOperations := map[string]bool{
		"GetSecrets":       true,
		"CreateItem":       true,
		"SetSecret":        true,
		"Delete":           true,
		"CreateCollection": true,
		"DeleteCollection": true,
		"SetAlias":         true,
	}

	if required, ok := lockedOperations[operation]; ok {
		return required && h.authManager.IsLocked()
	}

	// Read-only operations don't require authentication
	return false
}

// GetAuthenticationPromptMessage returns the message for an authentication prompt.
func (h *AuthPromptHandler) GetAuthenticationPromptMessage(operation string) string {
	messages := map[string]string{
		"GetSecrets":       "Authentication required to access secrets",
		"CreateItem":       "Authentication required to create new secret",
		"SetSecret":        "Authentication required to modify secret",
		"Delete":           "Authentication required to delete secret",
		"CreateCollection": "Authentication required to create collection",
		"DeleteCollection": "Authentication required to delete collection",
		"SetAlias":         "Authentication required to set alias",
	}

	if msg, ok := messages[operation]; ok {
		return msg
	}

	return "Authentication required"
}
