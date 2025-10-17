package dbus

import (
	"fmt"
	"strings"
	"unicode/utf8"
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
		return fmt.Errorf("label contains invalid UTF-8")
	}

	if len(label) > maxLabelLength {
		return fmt.Errorf("label exceeds maximum length of %d bytes", maxLabelLength)
	}

	// Check for null bytes
	if strings.Contains(label, "\x00") {
		return fmt.Errorf("label contains null bytes")
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
			return fmt.Errorf("attribute key contains invalid UTF-8")
		}
		if !utf8.ValidString(value) {
			return fmt.Errorf("attribute value contains invalid UTF-8")
		}

		if len(key) > maxAttributeLength {
			return fmt.Errorf("attribute key exceeds maximum length of %d bytes", maxAttributeLength)
		}
		if len(value) > maxAttributeLength {
			return fmt.Errorf("attribute value exceeds maximum length of %d bytes", maxAttributeLength)
		}

		// Check for null bytes
		if strings.Contains(key, "\x00") || strings.Contains(value, "\x00") {
			return fmt.Errorf("attribute contains null bytes")
		}
	}

	return nil
}

// validateSecretData validates secret data size.
func validateSecretData(data []byte) error {
	if len(data) > maxSecretSize {
		return fmt.Errorf("secret data exceeds maximum size of %d bytes", maxSecretSize)
	}
	return nil
}

// validateCollectionName validates a collection name.
func validateCollectionName(name string) error {
	if !utf8.ValidString(name) {
		return fmt.Errorf("collection name contains invalid UTF-8")
	}

	if len(name) > maxCollectionName {
		return fmt.Errorf("collection name exceeds maximum length of %d bytes", maxCollectionName)
	}

	if len(name) == 0 {
		return fmt.Errorf("collection name cannot be empty")
	}

	// Check for null bytes
	if strings.Contains(name, "\x00") {
		return fmt.Errorf("collection name contains null bytes")
	}

	// Prevent path traversal
	if strings.Contains(name, "..") || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return fmt.Errorf("collection name contains invalid characters")
	}

	return nil
}

// sanitizeID creates a safe ID from a string.
