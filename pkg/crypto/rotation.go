package crypto

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hazayan/knox/pkg/types"
	"github.com/hazayan/knox/server/keydb"
)

// KeyRotationManager manages graceful rotation of encryption keys.
type KeyRotationManager struct {
	currentCryptor keydb.Cryptor
	oldCryptors    []keydb.Cryptor
	mu             sync.RWMutex
}

// NewKeyRotationManager creates a new key rotation manager.
func NewKeyRotationManager(currentCryptor keydb.Cryptor) *KeyRotationManager {
	return &KeyRotationManager{
		currentCryptor: currentCryptor,
		oldCryptors:    make([]keydb.Cryptor, 0),
	}
}

// Encrypt always uses the current (newest) cryptor.
func (krm *KeyRotationManager) Encrypt(key *types.Key) (*keydb.DBKey, error) {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	return krm.currentCryptor.Encrypt(key)
}

// Decrypt tries the current cryptor first, then falls back to old cryptors.
// This allows reading keys encrypted with old master keys during rotation.
func (krm *KeyRotationManager) Decrypt(dbKey *keydb.DBKey) (*types.Key, error) {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	// Try current cryptor first
	key, err := krm.currentCryptor.Decrypt(dbKey)
	if err == nil {
		return key, nil
	}

	// Try old cryptors in reverse order (newest to oldest)
	for i := len(krm.oldCryptors) - 1; i >= 0; i-- {
		key, err := krm.oldCryptors[i].Decrypt(dbKey)
		if err == nil {
			return key, nil
		}
	}

	return nil, fmt.Errorf("failed to decrypt with any available cryptor: %w", err)
}

// EncryptVersion encrypts a single version using the current cryptor.
func (krm *KeyRotationManager) EncryptVersion(key *types.Key, version *types.KeyVersion) (*keydb.EncKeyVersion, error) {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	return krm.currentCryptor.EncryptVersion(key, version)
}

// RotateToNewKey rotates to a new master key.
// The old cryptor is kept for decryption compatibility.
func (krm *KeyRotationManager) RotateToNewKey(newCryptor keydb.Cryptor) {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	// Move current cryptor to old cryptors list
	krm.oldCryptors = append(krm.oldCryptors, krm.currentCryptor)

	// Set new cryptor as current
	krm.currentCryptor = newCryptor
}

// RemoveOldCryptor removes an old cryptor (after re-encryption is complete).
func (krm *KeyRotationManager) RemoveOldCryptor(index int) error {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	if index < 0 || index >= len(krm.oldCryptors) {
		return fmt.Errorf("invalid cryptor index: %d", index)
	}

	// Remove from slice
	krm.oldCryptors = append(krm.oldCryptors[:index], krm.oldCryptors[index+1:]...)

	return nil
}

// ReencryptDB re-encrypts all keys in the database with the current cryptor.
// This should be run after rotating to a new master key.
func ReencryptDB(ctx context.Context, db keydb.DB, rotationManager *KeyRotationManager) error {
	// Get all keys
	dbKeys, err := db.GetAll()
	if err != nil {
		return fmt.Errorf("failed to get all keys: %w", err)
	}

	total := len(dbKeys)
	reencrypted := 0
	failed := 0

	for i, dbKey := range dbKeys {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			return fmt.Errorf("re-encryption cancelled: %w", ctx.Err())
		default:
		}

		// Decrypt with any available cryptor (might use old one)
		key, err := rotationManager.Decrypt(&dbKey)
		if err != nil {
			failed++
			continue
		}

		// Re-encrypt with current cryptor
		newDBKey, err := rotationManager.Encrypt(key)
		if err != nil {
			failed++
			continue
		}

		// Update in database
		if err := db.Update(newDBKey); err != nil {
			failed++
			continue
		}

		reencrypted++

		// Log progress every 100 keys
		if (i+1)%100 == 0 {
			fmt.Printf("Re-encryption progress: %d/%d (%.1f%%)\n", i+1, total, float64(i+1)/float64(total)*100)
		}
	}

	fmt.Printf("Re-encryption complete: %d succeeded, %d failed out of %d total\n", reencrypted, failed, total)

	if failed > 0 {
		return fmt.Errorf("re-encryption completed with %d failures", failed)
	}

	return nil
}

// RotationStatus represents the status of a key rotation operation.
type RotationStatus struct {
	InProgress       bool
	TotalKeys        int
	ReencryptedKeys  int
	FailedKeys       int
	StartTime        time.Time
	EstimatedEndTime time.Time
}

// Verify interface compliance.
var _ keydb.Cryptor = (*KeyRotationManager)(nil)
