// Package crypto provides cryptographic operations for Knox.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/hazayan/knox/pkg/types"
	"github.com/hazayan/knox/server/keydb"
	"golang.org/x/crypto/hkdf"
)

// AESCryptor implements keydb.Cryptor using AES-256-GCM.
// It uses envelope encryption: each key version is encrypted with a unique DEK (Data Encryption Key),
// and the DEK is encrypted with the master KEK (Key Encryption Key).
type AESCryptor struct {
	kek []byte // Key Encryption Key (master key)
}

// NewAESCryptor creates a new AES cryptor with the given master key.
// The master key should be 32 bytes (256 bits) for AES-256.
func NewAESCryptor(masterKey []byte) (*AESCryptor, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes (256 bits), got %d", len(masterKey))
	}

	return &AESCryptor{
		kek: masterKey,
	}, nil
}

// NewAESCryptorFromFile loads the master key from a file.
func NewAESCryptorFromFile(path string) (*AESCryptor, error) {
	// This would load from a secure key file
	// For now, this is a placeholder - in production, integrate with KMS/HSM
	return nil, errors.New("file-based key loading not yet implemented - use environment variable")
}

// Encrypt encrypts a Knox key using envelope encryption.
func (c *AESCryptor) Encrypt(key *types.Key) (*keydb.DBKey, error) {
	dbKey := &keydb.DBKey{
		ID:          key.ID,
		ACL:         key.ACL,
		VersionHash: key.VersionHash,
		VersionList: make([]keydb.EncKeyVersion, len(key.VersionList)),
	}

	for i, v := range key.VersionList {
		encVersion, err := c.encryptVersion(&v)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt version %d: %w", i, err)
		}
		dbKey.VersionList[i] = *encVersion
	}

	return dbKey, nil
}

// Decrypt decrypts a Knox key.
func (c *AESCryptor) Decrypt(dbKey *keydb.DBKey) (*types.Key, error) {
	key := &types.Key{
		ID:          dbKey.ID,
		ACL:         dbKey.ACL,
		VersionHash: dbKey.VersionHash,
		VersionList: make(types.KeyVersionList, len(dbKey.VersionList)),
	}

	for i, ev := range dbKey.VersionList {
		version, err := c.decryptVersion(&ev)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt version %d: %w", i, err)
		}
		key.VersionList[i] = *version
	}

	return key, nil
}

// EncryptVersion encrypts a single key version.
func (c *AESCryptor) EncryptVersion(key *types.Key, version *types.KeyVersion) (*keydb.EncKeyVersion, error) {
	return c.encryptVersion(version)
}

// encryptVersion performs the actual encryption using envelope encryption.
func (c *AESCryptor) encryptVersion(version *types.KeyVersion) (*keydb.EncKeyVersion, error) {
	// Generate a random DEK (Data Encryption Key) for this version
	dek := make([]byte, 32) // 256-bit key
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}
	// Ensure DEK is cleared from memory after use
	defer clearBytes(dek)

	// Encrypt the data with the DEK using AES-256-GCM
	encData, err := c.encryptWithKey(dek, version.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Encrypt the DEK with the KEK
	encDEK, err := c.encryptWithKey(c.kek, dek)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt DEK: %w", err)
	}

	// Store metadata: encrypted DEK and version info
	metadata := &CryptoMetadata{
		Algorithm:    "AES-256-GCM",
		EncryptedDEK: base64.StdEncoding.EncodeToString(encDEK),
		Version:      1,
	}

	metadataBytes, err := metadata.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	return &keydb.EncKeyVersion{
		ID:             version.ID,
		EncData:        encData,
		Status:         version.Status,
		CreationTime:   version.CreationTime,
		CryptoMetadata: metadataBytes,
	}, nil
}

// decryptVersion performs the actual decryption using envelope encryption.
func (c *AESCryptor) decryptVersion(encVersion *keydb.EncKeyVersion) (*types.KeyVersion, error) {
	// Parse metadata
	metadata, err := UnmarshalCryptoMetadata(encVersion.CryptoMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	if metadata.Algorithm != "AES-256-GCM" {
		return nil, fmt.Errorf("unsupported algorithm: %s", metadata.Algorithm)
	}

	// Decode the encrypted DEK
	encDEK, err := base64.StdEncoding.DecodeString(metadata.EncryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted DEK: %w", err)
	}

	// Decrypt the DEK using the KEK
	dek, err := c.decryptWithKey(c.kek, encDEK)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}
	defer clearBytes(dek) // Clear DEK from memory after use

	// Decrypt the data using the DEK
	data, err := c.decryptWithKey(dek, encVersion.EncData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return &types.KeyVersion{
		ID:           encVersion.ID,
		Data:         data,
		Status:       encVersion.Status,
		CreationTime: encVersion.CreationTime,
	}, nil
}

// encryptWithKey encrypts data with the given key using AES-256-GCM.
func (c *AESCryptor) encryptWithKey(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

// decryptWithKey decrypts data with the given key using AES-256-GCM.
func (c *AESCryptor) decryptWithKey(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// DeriveKey derives a key from a password using HKDF.
func DeriveKey(password []byte, salt []byte, info []byte) ([]byte, error) {
	if len(salt) < 16 {
		return nil, errors.New("salt must be at least 16 bytes")
	}

	kdf := hkdf.New(sha256.New, password, salt, info)
	key := make([]byte, 32) // 256-bit key

	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	return key, nil
}

// GenerateMasterKey generates a new random master key.
func GenerateMasterKey() ([]byte, error) {
	key := make([]byte, 32) // 256-bit key
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}
	return key, nil
}

// clearBytes overwrites a byte slice with zeros (best-effort memory clearing).
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Verify that AESCryptor implements keydb.Cryptor at compile time.
var _ keydb.Cryptor = (*AESCryptor)(nil)
