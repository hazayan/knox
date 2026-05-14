package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	MasterKeyLen                    = 32
	MasterKeyBundleKind             = "knox-master-key"
	MasterKeyBackupKind             = "knox-master-key-backup"
	DefaultFido2DeriveInfo          = "knox master key fido2 v1"
	DefaultFido2BackupDeriveInfo    = "knox master key backup fido2 v1"
	FakeFido2SecretEnvironmentValue = "KNOX_FIDO2_FAKE_SECRET_B64"
)

type MasterKeyProvider interface {
	Name() string
	MasterKey() ([]byte, error)
}

type WrappingKeyProvider interface {
	Name() string
	WrappingKey() ([]byte, error)
}

type Fido2CredentialMetadata struct {
	Version      int    `json:"version"`
	RPID         string `json:"rp_id"`
	RPName       string `json:"rp_name"`
	CredentialID string `json:"credential_id"`
	Salt         string `json:"salt"`
	UV           string `json:"uv"`
	UP           bool   `json:"up"`
	DeriveInfo   string `json:"derive_info"`
}

type Fido2DeviceOptions struct {
	Device  string
	PinFile string
}

type MasterKeyBundle struct {
	Version    int                     `json:"version"`
	Kind       string                  `json:"kind"`
	CreatedAt  string                  `json:"created_at"`
	Encryption MasterKeyBundleEnvelope `json:"encryption"`
}

type MasterKeyBundleEnvelope struct {
	Backend    string                  `json:"backend"`
	Cipher     string                  `json:"cipher"`
	Metadata   Fido2CredentialMetadata `json:"metadata,omitempty"`
	Nonce      string                  `json:"nonce"`
	Ciphertext string                  `json:"ciphertext"`
}

type Fido2WrappingKeyProvider struct {
	Metadata   Fido2CredentialMetadata
	HMACSecret []byte
	Device     Fido2DeviceOptions
}

func NewFido2Metadata(rpID, rpName, deriveInfo string) (Fido2CredentialMetadata, error) {
	if strings.TrimSpace(rpID) == "" {
		return Fido2CredentialMetadata{}, errors.New("rp_id cannot be empty")
	}
	if strings.TrimSpace(rpName) == "" {
		rpName = rpID
	}
	if strings.TrimSpace(deriveInfo) == "" {
		deriveInfo = DefaultFido2DeriveInfo
	}
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return Fido2CredentialMetadata{}, fmt.Errorf("failed to generate fido2 salt: %w", err)
	}
	credentialID := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, credentialID); err != nil {
		return Fido2CredentialMetadata{}, fmt.Errorf("failed to generate placeholder credential id: %w", err)
	}
	return Fido2CredentialMetadata{
		Version:      1,
		RPID:         rpID,
		RPName:       rpName,
		CredentialID: base64.RawURLEncoding.EncodeToString(credentialID),
		Salt:         base64.RawURLEncoding.EncodeToString(salt),
		UV:           "discouraged",
		UP:           true,
		DeriveInfo:   deriveInfo,
	}, nil
}

func LoadFido2Metadata(path string) (Fido2CredentialMetadata, error) {
	if err := validateAbsoluteCleanPath(path, "metadata file"); err != nil {
		return Fido2CredentialMetadata{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Fido2CredentialMetadata{}, fmt.Errorf("failed to read fido2 metadata: %w", err)
	}
	var metadata Fido2CredentialMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return Fido2CredentialMetadata{}, fmt.Errorf("failed to parse fido2 metadata: %w", err)
	}
	if err := metadata.Validate(); err != nil {
		return Fido2CredentialMetadata{}, err
	}
	return metadata, nil
}

func SaveFido2Metadata(path string, metadata Fido2CredentialMetadata) error {
	if err := validateAbsoluteCleanPath(path, "metadata file"); err != nil {
		return err
	}
	if err := metadata.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("failed to create metadata directory: %w", err)
	}
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode fido2 metadata: %w", err)
	}
	return writeNewFile(path, append(data, '\n'), 0o600)
}

func (m Fido2CredentialMetadata) Validate() error {
	if m.Version != 1 {
		return fmt.Errorf("unsupported fido2 metadata version: %d", m.Version)
	}
	if strings.TrimSpace(m.RPID) == "" {
		return errors.New("fido2 metadata missing rp_id")
	}
	if strings.TrimSpace(m.CredentialID) == "" {
		return errors.New("fido2 metadata missing credential_id")
	}
	salt, err := base64.RawURLEncoding.DecodeString(m.Salt)
	if err != nil {
		return fmt.Errorf("invalid fido2 salt: %w", err)
	}
	if len(salt) != 32 {
		return fmt.Errorf("fido2 salt must be 32 bytes, got %d", len(salt))
	}
	if strings.TrimSpace(m.DeriveInfo) == "" {
		return errors.New("fido2 metadata missing derive_info")
	}
	return nil
}

func NewFido2WrappingKeyProviderFromMetadataFile(path string) (*Fido2WrappingKeyProvider, error) {
	return NewFido2WrappingKeyProviderFromMetadataFileWithOptions(path, Fido2DeviceOptions{})
}

func NewFido2WrappingKeyProviderFromMetadataFileWithOptions(path string, options Fido2DeviceOptions) (*Fido2WrappingKeyProvider, error) {
	metadata, err := LoadFido2Metadata(path)
	if err != nil {
		return nil, err
	}
	if secret, ok, err := fakeFido2HMACSecret(); ok || err != nil {
		if err != nil {
			return nil, err
		}
		return &Fido2WrappingKeyProvider{Metadata: metadata, HMACSecret: secret, Device: options}, nil
	}
	return &Fido2WrappingKeyProvider{Metadata: metadata, Device: options}, nil
}

func NewFido2WrappingKeyProvider(metadata Fido2CredentialMetadata, hmacSecret []byte) (*Fido2WrappingKeyProvider, error) {
	if err := metadata.Validate(); err != nil {
		return nil, err
	}
	if len(hmacSecret) < 32 {
		return nil, errors.New("fido2 hmac secret must be at least 32 bytes")
	}
	secret := make([]byte, len(hmacSecret))
	copy(secret, hmacSecret)
	return &Fido2WrappingKeyProvider{Metadata: metadata, HMACSecret: secret}, nil
}

func (p *Fido2WrappingKeyProvider) Name() string {
	return "fido2"
}

func (p *Fido2WrappingKeyProvider) WrappingKey() ([]byte, error) {
	salt, err := base64.RawURLEncoding.DecodeString(p.Metadata.Salt)
	if err != nil {
		return nil, fmt.Errorf("invalid fido2 salt: %w", err)
	}
	hmacSecret := p.HMACSecret
	if len(hmacSecret) == 0 {
		hmacSecret, err = fido2HMACSecret(p.Metadata, p.Device)
		if err != nil {
			return nil, err
		}
		defer clearBytes(hmacSecret)
	}
	reader := hkdf.New(sha256.New, hmacSecret, salt, []byte(p.Metadata.DeriveInfo))
	key := make([]byte, MasterKeyLen)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("failed to derive fido2 wrapping key: %w", err)
	}
	return key, nil
}

type wrappedMasterKeyProvider struct {
	Path     string
	Wrapping WrappingKeyProvider
}

func NewWrappedMasterKeyProvider(path string, wrapping WrappingKeyProvider) MasterKeyProvider {
	return &wrappedMasterKeyProvider{Path: path, Wrapping: wrapping}
}

func (p *wrappedMasterKeyProvider) Name() string {
	return "wrapped-" + p.Wrapping.Name()
}

func (p *wrappedMasterKeyProvider) MasterKey() ([]byte, error) {
	return DecryptMasterKeyBundleFile(p.Path, p.Wrapping)
}

func EncryptMasterKeyBundle(masterKey []byte, wrapping WrappingKeyProvider, kind string) ([]byte, error) {
	if len(masterKey) != MasterKeyLen {
		return nil, fmt.Errorf("master key must be %d bytes", MasterKeyLen)
	}
	if kind == "" {
		kind = MasterKeyBundleKind
	}
	wrappingKey, err := wrapping.WrappingKey()
	if err != nil {
		return nil, err
	}
	defer clearBytes(wrappingKey)

	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create master-key bundle cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create master-key bundle gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate master-key bundle nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, masterKey, []byte(kind))
	bundle := MasterKeyBundle{
		Version:   1,
		Kind:      kind,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Encryption: MasterKeyBundleEnvelope{
			Backend:    wrapping.Name(),
			Cipher:     "AES-256-GCM",
			Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
			Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
		},
	}
	if fido2, ok := wrapping.(*Fido2WrappingKeyProvider); ok {
		bundle.Encryption.Metadata = fido2.Metadata
	}
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to encode master-key bundle: %w", err)
	}
	return append(data, '\n'), nil
}

func DecryptMasterKeyBundle(data []byte, wrapping WrappingKeyProvider, expectedKind string) ([]byte, error) {
	var bundle MasterKeyBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("failed to parse master-key bundle: %w", err)
	}
	if err := bundle.Validate(expectedKind); err != nil {
		return nil, err
	}
	wrappingKey, err := wrapping.WrappingKey()
	if err != nil {
		return nil, err
	}
	defer clearBytes(wrappingKey)
	nonce, err := base64.RawURLEncoding.DecodeString(bundle.Encryption.Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid master-key bundle nonce: %w", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(bundle.Encryption.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid master-key bundle ciphertext: %w", err)
	}
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create master-key bundle cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create master-key bundle gcm: %w", err)
	}
	masterKey, err := gcm.Open(nil, nonce, ciphertext, []byte(bundle.Kind))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt master-key bundle: %w", err)
	}
	if len(masterKey) != MasterKeyLen {
		return nil, fmt.Errorf("decrypted master key has wrong length: %d bytes", len(masterKey))
	}
	return masterKey, nil
}

func (b MasterKeyBundle) Validate(expectedKind string) error {
	if b.Version != 1 {
		return fmt.Errorf("unsupported master-key bundle version: %d", b.Version)
	}
	if expectedKind != "" && b.Kind != expectedKind {
		return fmt.Errorf("unexpected master-key bundle kind %q, expected %q", b.Kind, expectedKind)
	}
	if b.Kind != MasterKeyBundleKind && b.Kind != MasterKeyBackupKind {
		return fmt.Errorf("unsupported master-key bundle kind: %s", b.Kind)
	}
	if b.Encryption.Cipher != "AES-256-GCM" {
		return fmt.Errorf("unsupported master-key bundle cipher: %s", b.Encryption.Cipher)
	}
	if b.Encryption.Backend == "" {
		return errors.New("master-key bundle missing backend")
	}
	if b.Encryption.Nonce == "" || b.Encryption.Ciphertext == "" {
		return errors.New("master-key bundle missing encrypted payload")
	}
	return nil
}

func WriteMasterKeyBundleFile(path string, data []byte) error {
	if err := validateAbsoluteCleanPath(path, "master-key bundle file"); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("failed to create bundle directory: %w", err)
	}
	return writeNewFile(path, data, 0o600)
}

func DecryptMasterKeyBundleFile(path string, wrapping WrappingKeyProvider) ([]byte, error) {
	if err := validateAbsoluteCleanPath(path, "master-key bundle file"); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read master-key bundle: %w", err)
	}
	return DecryptMasterKeyBundle(data, wrapping, MasterKeyBundleKind)
}

func BackupMasterKeyBundle(inputPath string, inputWrapping WrappingKeyProvider, outputWrapping WrappingKeyProvider) ([]byte, error) {
	masterKey, err := DecryptMasterKeyBundleFile(inputPath, inputWrapping)
	if err != nil {
		return nil, err
	}
	defer clearBytes(masterKey)
	return EncryptMasterKeyBundle(masterKey, outputWrapping, MasterKeyBackupKind)
}

func RestoreMasterKeyBundle(backup []byte, backupWrapping WrappingKeyProvider, outputWrapping WrappingKeyProvider) ([]byte, error) {
	masterKey, err := DecryptMasterKeyBundle(backup, backupWrapping, MasterKeyBackupKind)
	if err != nil {
		return nil, err
	}
	defer clearBytes(masterKey)
	return EncryptMasterKeyBundle(masterKey, outputWrapping, MasterKeyBundleKind)
}

func EnrollFido2Metadata(rpID, rpName, deriveInfo string, options Fido2DeviceOptions) (Fido2CredentialMetadata, error) {
	if _, ok, err := fakeFido2HMACSecret(); ok || err != nil {
		if err != nil {
			return Fido2CredentialMetadata{}, err
		}
		return NewFido2Metadata(rpID, rpName, deriveInfo)
	}
	if strings.TrimSpace(rpID) == "" {
		return Fido2CredentialMetadata{}, errors.New("rp_id cannot be empty")
	}
	if strings.TrimSpace(rpName) == "" {
		rpName = rpID
	}
	if strings.TrimSpace(deriveInfo) == "" {
		deriveInfo = DefaultFido2DeriveInfo
	}
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return Fido2CredentialMetadata{}, fmt.Errorf("failed to generate fido2 salt: %w", err)
	}
	credentialID, err := fido2EnrollCredential(rpID, rpName, options)
	if err != nil {
		return Fido2CredentialMetadata{}, err
	}
	return Fido2CredentialMetadata{
		Version:      1,
		RPID:         rpID,
		RPName:       rpName,
		CredentialID: base64.RawURLEncoding.EncodeToString(credentialID),
		Salt:         base64.RawURLEncoding.EncodeToString(salt),
		UV:           "discouraged",
		UP:           true,
		DeriveInfo:   deriveInfo,
	}, nil
}

func fakeFido2HMACSecret() ([]byte, bool, error) {
	value := os.Getenv(FakeFido2SecretEnvironmentValue)
	if value == "" {
		return nil, false, nil
	}
	secret, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, true, fmt.Errorf("invalid fake fido2 hmac secret: %w", err)
	}
	if len(secret) < 32 {
		return nil, true, errors.New("fake fido2 hmac secret must be at least 32 bytes")
	}
	return secret, true, nil
}

func validateAbsoluteCleanPath(path, label string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s path must be absolute", label)
	}
	if strings.Contains(path, "..") {
		return fmt.Errorf("%s path cannot contain parent directory references", label)
	}
	return nil
}

func writeNewFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", path, err)
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("failed to chmod %s: %w", path, err)
	}
	return nil
}
