package dbus

import (
	"errors"
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

	// Prevent path traversal
	if strings.Contains(name, "..") || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return errors.New("collection name contains invalid characters")
	}

	return nil
}

// sanitizeID creates a safe ID from a string.
