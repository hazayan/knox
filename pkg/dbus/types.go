// Package dbus implements the FreeDesktop Secret Service API.
// Spec: https://specifications.freedesktop.org/secret-service-spec/latest/
package dbus

import (
	"github.com/godbus/dbus/v5"
)

const (
	// DBus service name
	ServiceName = "org.freedesktop.secrets"

	// Object paths
	ServicePath      = "/org/freedesktop/secrets"
	SessionPrefix    = "/org/freedesktop/secrets/session/"
	CollectionPrefix = "/org/freedesktop/secrets/collection/"
	AliasPrefix      = "/org/freedesktop/secrets/aliases/"

	// Interface names
	ServiceInterface    = "org.freedesktop.Secret.Service"
	CollectionInterface = "org.freedesktop.Secret.Collection"
	ItemInterface       = "org.freedesktop.Secret.Item"
	SessionInterface    = "org.freedesktop.Secret.Session"
	PromptInterface     = "org.freedesktop.Secret.Prompt"

	// Special aliases
	DefaultCollection = "default"
	SessionCollection = "session"
)

// Secret represents a secret value transferred over D-Bus.
// The secret is encrypted using the session's negotiated algorithm.
type Secret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// SecretProperties represents properties for creating a secret item.
type SecretProperties struct {
	Label      string
	Attributes map[string]string
}

// EncryptionAlgorithm represents supported encryption algorithms.
type EncryptionAlgorithm string

const (
	AlgorithmPlain EncryptionAlgorithm = "plain"
	AlgorithmDHAES EncryptionAlgorithm = "dh-ietf1024-sha256-aes128-cbc-pkcs7"
)

// ObjectPath helpers
func makeSessionPath(id string) dbus.ObjectPath {
	return dbus.ObjectPath(SessionPrefix + id)
}

func makeCollectionPath(name string) dbus.ObjectPath {
	return dbus.ObjectPath(CollectionPrefix + name)
}

func makeItemPath(collection, itemID string) dbus.ObjectPath {
	return dbus.ObjectPath(CollectionPrefix + collection + "/" + itemID)
}

func makeAliasPath(alias string) dbus.ObjectPath {
	return dbus.ObjectPath(AliasPrefix + alias)
}
