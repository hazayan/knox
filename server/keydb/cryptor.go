package keydb

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/hazayan/knox/pkg/types"
)

var ErrCryptorVersion = fmt.Errorf("Cryptor version does not match")

// Cryptor is an interface for converting a knox Key to a DB Key
type Cryptor interface {
	Decrypt(*DBKey) (*types.Key, error)
	Encrypt(*types.Key) (*DBKey, error)
	EncryptVersion(*types.Key, *types.KeyVersion) (*EncKeyVersion, error)
}

// NewAESGCMCryptor creates a Cryptor that performs AES GCM AEAD encryption on key data.
func NewAESGCMCryptor(version byte, keyData []byte) Cryptor {
	return &aesGCMCryptor{keyData, version}
}

// aesGCMCryptor does AES encryption, but does not include correct associated data.
type aesGCMCryptor struct {
	keyData []byte
	version byte
}

func (c *aesGCMCryptor) EncryptVersion(k *types.Key, v *types.KeyVersion) (*EncKeyVersion, error) {
	b, err := aes.NewCipher(c.keyData)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, v.Data, c.generateAD(k.ID, v.ID, v.CreationTime))

	return &EncKeyVersion{
		ID:             v.ID,
		EncData:        ciphertext,
		Status:         v.Status,
		CreationTime:   v.CreationTime,
		CryptoMetadata: buildMetadata(c.version, nonce),
	}, nil
}

// generateAD generates the data to be signed with key version versionid|creationtime|keyid
func (c *aesGCMCryptor) generateAD(kid string, vid uint64, creation int64) []byte {
	idBytes := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(idBytes, vid)
	creationBytes := make([]byte, binary.MaxVarintLen64)
	binary.PutVarint(creationBytes, creation)

	b := bytes.NewBuffer(idBytes)
	b.Write(creationBytes)
	b.WriteString(kid)
	return b.Bytes()
}

func (c *aesGCMCryptor) decryptVersion(k *DBKey, v *EncKeyVersion) (*types.KeyVersion, error) {
	md := aesCryptoMetadata(v.CryptoMetadata)
	if md.Version() != c.version {
		return nil, ErrCryptorVersion
	}
	b, err := aes.NewCipher(c.keyData)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, md.Nonce(), v.EncData, c.generateAD(k.ID, v.ID, v.CreationTime))
	if err != nil {
		return nil, err
	}

	return &types.KeyVersion{
		ID:           v.ID,
		Data:         plaintext,
		Status:       v.Status,
		CreationTime: v.CreationTime,
	}, nil
}

func (c *aesGCMCryptor) Encrypt(k *types.Key) (*DBKey, error) {
	dbVersions := make([]EncKeyVersion, len(k.VersionList))
	for i, v := range k.VersionList {
		dbv, err := c.EncryptVersion(k, &v)
		if err != nil {
			return nil, err
		}
		dbVersions[i] = *dbv
	}

	newKey := DBKey{
		ID:          k.ID,
		ACL:         k.ACL,
		VersionList: dbVersions,
		VersionHash: k.VersionHash,
	}
	return &newKey, nil
}

func (c *aesGCMCryptor) Decrypt(k *DBKey) (*types.Key, error) {
	versions := make([]types.KeyVersion, len(k.VersionList))
	for i, v := range k.VersionList {
		dbv, err := c.decryptVersion(k, &v)
		if err != nil {
			return nil, err
		}
		versions[i] = *dbv
	}

	newKey := types.Key{
		ID:          k.ID,
		ACL:         k.ACL,
		VersionList: versions,
		VersionHash: k.VersionHash,
	}
	return &newKey, nil
}

type aesCryptoMetadata []byte

func (c aesCryptoMetadata) Version() byte {
	return c[0]
}

func (c aesCryptoMetadata) Nonce() []byte {
	return c[1:]
}

func buildMetadata(version byte, nonce []byte) aesCryptoMetadata {
	c := make([]byte, len(nonce)+1)
	c[0] = version
	copy(c[1:], nonce)
	return c
}
