package dbus

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// Diffie-Hellman parameters using RFC 3526 Group 14 (2048-bit MODP)
// SECURITY: Upgraded from 1024-bit to 2048-bit for ~112-bit security level
// NOTE: This deviates from original FreeDesktop spec (1024-bit) for better security
var (
	// Prime modulus (2048-bit safe prime) - RFC 3526 Group 14
	dhPrime = mustParseBigInt(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
			"15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)

	// Generator
	dhGenerator = big.NewInt(2)
)

// DHKeyExchange performs Diffie-Hellman key exchange.
type DHKeyExchange struct {
	privateKey *big.Int
	publicKey  *big.Int
	sharedKey  []byte
}

// NewDHKeyExchange creates a new DH key exchange.
func NewDHKeyExchange() (*DHKeyExchange, error) {
	// Generate private key (random number between 1 and prime-1)
	privateKey, err := generateDHPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Calculate public key: g^private mod p
	publicKey := new(big.Int).Exp(dhGenerator, privateKey, dhPrime)

	return &DHKeyExchange{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

// GetPublicKey returns the public key as bytes (big-endian).
func (dh *DHKeyExchange) GetPublicKey() []byte {
	return dh.publicKey.Bytes()
}

// ComputeSharedKey computes the shared secret from the peer's public key.
// Implements comprehensive validation to prevent small subgroup attacks.
func (dh *DHKeyExchange) ComputeSharedKey(peerPublicKeyBytes []byte) error {
	peerPublicKey := new(big.Int).SetBytes(peerPublicKeyBytes)

	// 1. Validate peer's public key is in valid range (1 < key < p)
	if peerPublicKey.Cmp(big.NewInt(1)) <= 0 || peerPublicKey.Cmp(dhPrime) >= 0 {
		return fmt.Errorf("invalid peer public key: out of range")
	}

	// 2. Reject trivial values that could leak information
	pMinusOne := new(big.Int).Sub(dhPrime, big.NewInt(1))
	if peerPublicKey.Cmp(pMinusOne) == 0 {
		return fmt.Errorf("invalid peer public key: trivial value p-1")
	}

	// 3. Verify key is in correct subgroup (prevents small subgroup attack)
	// For MODP group with safe prime p = 2q+1, verify: key^q mod p == 1
	// This ensures the key is in the prime-order subgroup
	q := new(big.Int).Rsh(pMinusOne, 1) // q = (p-1)/2
	subgroupTest := new(big.Int).Exp(peerPublicKey, q, dhPrime)
	if subgroupTest.Cmp(big.NewInt(1)) != 0 {
		return fmt.Errorf("invalid peer public key: not in prime-order subgroup")
	}

	// 4. Calculate shared secret: peer_public^private mod p
	sharedSecret := new(big.Int).Exp(peerPublicKey, dh.privateKey, dhPrime)

	// 5. Verify shared secret is not trivial
	if sharedSecret.Cmp(big.NewInt(1)) == 0 || sharedSecret.Cmp(pMinusOne) == 0 {
		return fmt.Errorf("invalid shared secret: trivial value")
	}

	// Derive encryption key from shared secret using SHA-256
	dh.sharedKey = deriveKey(sharedSecret.Bytes())

	return nil
}

// GetSharedKey returns the derived shared key (16 bytes for AES-128).
func (dh *DHKeyExchange) GetSharedKey() []byte {
	return dh.sharedKey
}

// generateDHPrivateKey generates a random private key for DH.
func generateDHPrivateKey() (*big.Int, error) {
	// Generate random bytes
	bytes := make([]byte, 128) // 1024 bits
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}

	// Convert to big int
	privateKey := new(big.Int).SetBytes(bytes)

	// Ensure it's in range [2, prime-2]
	privateKey.Mod(privateKey, new(big.Int).Sub(dhPrime, big.NewInt(2)))
	privateKey.Add(privateKey, big.NewInt(2))

	return privateKey, nil
}

// deriveKey derives an AES-128 key from the DH shared secret using SHA-256.
func deriveKey(sharedSecret []byte) []byte {
	hash := sha256.Sum256(sharedSecret)
	// Return first 16 bytes for AES-128
	return hash[:16]
}

// encryptAES128CBC encrypts data using AES-128-CBC with PKCS7 padding.
func encryptAES128CBC(key, plaintext []byte) (iv []byte, ciphertext []byte, err error) {
	if len(key) != 16 {
		return nil, nil, fmt.Errorf("key must be 16 bytes for AES-128")
	}

	// Apply PKCS7 padding
	paddedPlaintext := pkcs7Pad(plaintext, aes.BlockSize)

	// Generate random IV
	iv = make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Encrypt
	ciphertext = make([]byte, len(paddedPlaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	return iv, ciphertext, nil
}

// decryptAES128CBC decrypts data using AES-128-CBC with PKCS7 padding.
func decryptAES128CBC(key, iv, ciphertext []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("key must be 16 bytes for AES-128")
	}

	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("IV must be %d bytes", aes.BlockSize)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length must be multiple of block size")
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Decrypt
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding
	unpaddedPlaintext, err := pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("failed to unpad: %w", err)
	}

	return unpaddedPlaintext, nil
}

// pkcs7Pad applies PKCS7 padding to data.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

// errInvalidPadding is returned for any padding validation failure.
// Using a single error prevents padding oracle attacks.
var errInvalidPadding = errors.New("invalid padding")

// pkcs7Unpad removes PKCS7 padding from data with improved constant-time validation.
// Uses single error return to mitigate padding oracle attacks.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 || length%blockSize != 0 {
		return nil, errInvalidPadding
	}

	paddingLen := int(data[length-1])

	// Validate padding length bounds
	if paddingLen == 0 || paddingLen > blockSize {
		return nil, errInvalidPadding
	}

	// Check all padding bytes match paddingLen
	// Note: This is not fully constant-time, but mitigates oracle by:
	// 1. Always returning the same error
	// 2. CBC mode in local D-Bus context has limited oracle exposure
	// 3. Full constant-time would require subtle library operations throughout
	for i := length - paddingLen; i < length; i++ {
		if data[i] != byte(paddingLen) {
			return nil, errInvalidPadding
		}
	}

	return data[:length-paddingLen], nil
}

// encodeDBusVariant encodes the DH public key as a D-Bus variant (ay = byte array).
func encodeDBusPublicKey(publicKey []byte) []byte {
	// For D-Bus, we return the raw bytes which will be wrapped in a variant
	return publicKey
}

// decodeDBusPublicKey decodes a DH public key from D-Bus variant data.
func decodeDBusPublicKey(data []byte) ([]byte, error) {
	// The data is already the raw bytes from the D-Bus variant
	if len(data) == 0 {
		return nil, fmt.Errorf("empty public key")
	}
	return data, nil
}

// mustParseBigInt parses a big integer from a string (panics on error).
func mustParseBigInt(s string, base int) *big.Int {
	n, ok := new(big.Int).SetString(s, base)
	if !ok {
		panic(fmt.Sprintf("failed to parse big int: %s", s))
	}
	return n
}

// serializeU32 serializes a uint32 as big-endian bytes.
func serializeU32(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return b
}

// deserializeU32 deserializes a uint32 from big-endian bytes.
func deserializeU32(b []byte) (uint32, error) {
	if len(b) != 4 {
		return 0, fmt.Errorf("expected 4 bytes, got %d", len(b))
	}
	return binary.BigEndian.Uint32(b), nil
}
