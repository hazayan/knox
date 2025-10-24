package dbus

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/godbus/dbus/v5"
)

const (
	maxLabelLength     = 1024
	maxAttributeLength = 1024
	maxAttributeCount  = 100
	maxCollectionName  = 255
	maxSecretSize      = 1024 * 1024 // 1 MB max secret size
)

// validateLabel validates a collection or item label.
func validateLabel(label string) error {
	if !utf8.ValidString(label) {
		return errors.New("label contains invalid UTF-8")
	}

	if len(label) > maxLabelLength {
		return fmt.Errorf("label exceeds maximum length of %d bytes", maxLabelLength)
	}

	// Check for null bytes
	if strings.Contains(label, "\x00") {
		return errors.New("label contains null bytes")
	}

	return nil
}

// validateCollectionName validates a collection name.
func validateCollectionName(name string) error {
	if !utf8.ValidString(name) {
		return errors.New("collection name contains invalid UTF-8")
	}

	if len(name) > maxCollectionName {
		return fmt.Errorf("collection name exceeds maximum length of %d bytes", maxCollectionName)
	}

	if len(name) == 0 {
		return errors.New("collection name cannot be empty")
	}

	// Check for null bytes
	if strings.Contains(name, "\x00") {
		return errors.New("collection name contains null bytes")
	}

	// Prevent path traversal and other issues
	forbiddenChars := []string{"..", "/", "\\", ":", "|", "*", "?", "\"", "'", "<", ">", "[", "]", "{", "}", "%", "&", "=", "+", ",", ";", " ", "\t", "\n", "\r"}
	for _, char := range forbiddenChars {
		if strings.Contains(name, char) {
			return fmt.Errorf("collection name contains invalid character: %q", char)
		}
	}

	return nil
}

// validateItemID validates an item ID.
func validateItemID(id string) error {
	if !utf8.ValidString(id) {
		return errors.New("item ID contains invalid UTF-8")
	}

	if len(id) > maxCollectionName {
		return fmt.Errorf("item ID exceeds maximum length of %d bytes", maxCollectionName)
	}

	if len(id) == 0 {
		return errors.New("item ID cannot be empty")
	}

	// Check for null bytes
	if strings.Contains(id, "\x00") {
		return errors.New("item ID contains null bytes")
	}

	// Prevent path traversal and other issues
	forbiddenChars := []string{"..", "/", "\\", ":", "|", "*", "?", "\"", "'", "<", ">", "[", "]", "{", "}", "%", "&", "=", "+", ",", ";", " ", "\t", "\n", "\r"}
	for _, char := range forbiddenChars {
		if strings.Contains(id, char) {
			return fmt.Errorf("item ID contains invalid character: %q", char)
		}
	}

	return nil
}

// validateAttributes validates item attributes.
func validateAttributes(attributes map[string]string) error {
	if len(attributes) > maxAttributeCount {
		return fmt.Errorf("too many attributes: %d (max %d)", len(attributes), maxAttributeCount)
	}

	for key, value := range attributes {
		if !utf8.ValidString(key) {
			return fmt.Errorf("attribute key contains invalid UTF-8: %q", key)
		}

		if !utf8.ValidString(value) {
			return fmt.Errorf("attribute value contains invalid UTF-8 for key %q", key)
		}

		if len(key) > maxAttributeLength {
			return fmt.Errorf("attribute key too long: %q (%d bytes, max %d)", key, len(key), maxAttributeLength)
		}

		if len(value) > maxAttributeLength {
			return fmt.Errorf("attribute value too long for key %q (%d bytes, max %d)", key, len(value), maxAttributeLength)
		}

		// Check for newlines in values
		if strings.Contains(value, "\n") || strings.Contains(value, "\r") {
			return fmt.Errorf("attribute value contains newlines for key %q", key)
		}

		// Check for null bytes and other problematic characters
		if strings.Contains(key, "\x00") || strings.Contains(key, "\n") || strings.Contains(key, "\r") {
			return fmt.Errorf("attribute key contains invalid characters: %q", key)
		}

		if strings.Contains(value, "\x00") {
			return fmt.Errorf("attribute value contains null bytes for key %q", key)
		}
	}

	return nil
}

// validateSessionPath validates a D-Bus session path.
func validateSessionPath(path dbus.ObjectPath) error {
	pathStr := string(path)

	if len(pathStr) == 0 {
		return errors.New("session path cannot be empty")
	}

	if !strings.HasPrefix(pathStr, SessionPrefix) {
		return fmt.Errorf("session path must start with %q", SessionPrefix)
	}

	sessionID := strings.TrimPrefix(pathStr, SessionPrefix)
	if len(sessionID) == 0 {
		return errors.New("session path missing session ID")
	}

	// Check for path traversal attempts
	if strings.Contains(sessionID, "..") || strings.Contains(sessionID, "/") {
		return errors.New("session path contains invalid characters")
	}

	return nil
}

// validateCollectionPath validates a D-Bus collection path.
func validateCollectionPath(path dbus.ObjectPath) error {
	pathStr := string(path)

	if len(pathStr) == 0 {
		return errors.New("collection path cannot be empty")
	}

	if !strings.HasPrefix(pathStr, CollectionPrefix) {
		return fmt.Errorf("collection path must start with %q", CollectionPrefix)
	}

	collectionName := strings.TrimPrefix(pathStr, CollectionPrefix)
	if len(collectionName) == 0 {
		return errors.New("collection path missing collection name")
	}

	// Check for path traversal attempts
	if strings.Contains(collectionName, "..") || strings.Contains(collectionName, "/") {
		return errors.New("collection path contains invalid characters")
	}

	return validateCollectionName(collectionName)
}
