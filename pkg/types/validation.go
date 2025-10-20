// Package types provides type definitions and validation for Knox.
package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Validation errors.
var (
	ErrKeyIDTooLong       = errors.New("key ID too long (max 256 characters)")
	ErrKeyIDInvalidFormat = errors.New("key ID contains invalid characters")
	ErrKeyIDEmpty         = errors.New("key ID cannot be empty")
	ErrKeyDataTooLarge    = errors.New("key data too large (max 1MB)")
	ErrPrincipalIDTooLong = errors.New("principal ID too long (max 512 characters)")
	ErrPrincipalIDEmpty   = errors.New("principal ID cannot be empty")
	ErrInvalidSPIFFEURI   = errors.New("invalid SPIFFE URI format")
	ErrInvalidMachineID   = errors.New("invalid machine ID format")
	ErrInvalidUserID      = errors.New("invalid user ID format")
	ErrRequestTooLarge    = errors.New("request body too large (max 10MB)")
	ErrPathTraversal      = errors.New("path traversal attempt detected")
	ErrInvalidJSON        = errors.New("invalid JSON format")
	ErrUnsafeCharacters   = errors.New("input contains unsafe characters")
)

// Constants for validation limits.
const (
	MaxKeyIDLength       = 256
	MaxPrincipalIDLength = 512
	MaxKeyDataSize       = 1024 * 1024      // 1MB
	MaxRequestBodySize   = 10 * 1024 * 1024 // 10MB
)

// keyIDRegex validates key ID format.
// Allowed: alphanumeric, colon, underscore, hyphen, dot.
var keyIDRegex = regexp.MustCompile(`^[a-zA-Z0-9:_\-\.]+$`)

// machineIDRegex validates machine ID format.
var machineIDRegex = regexp.MustCompile(`^[a-zA-Z0-9\-\.]+$`)

// userIDRegex validates user ID format.
var userIDRegex = regexp.MustCompile(`^[a-zA-Z0-9@_\-\.]+$`)

// unsafeCharsRegex detects potentially dangerous characters.
var unsafeCharsRegex = regexp.MustCompile(`[<>"'&;]`)

// ValidateKeyID validates a key ID according to security requirements.
func ValidateKeyID(keyID string) error {
	if keyID == "" {
		return ErrKeyIDEmpty
	}

	if utf8.RuneCountInString(keyID) > MaxKeyIDLength {
		return ErrKeyIDTooLong
	}

	// Check for path traversal attempts first (security critical)
	if strings.Contains(keyID, "..") || strings.Contains(keyID, "/") || strings.Contains(keyID, "\\") {
		return ErrPathTraversal
	}

	// Check for unsafe characters (security critical)
	if unsafeCharsRegex.MatchString(keyID) {
		return ErrUnsafeCharacters
	}

	// Check format last
	if !keyIDRegex.MatchString(keyID) {
		return ErrKeyIDInvalidFormat
	}

	return nil
}

// ValidateKeyData validates key data size.
func ValidateKeyData(data []byte) error {
	if len(data) > MaxKeyDataSize {
		return ErrKeyDataTooLarge
	}
	return nil
}

// ValidatePrincipalID validates a principal ID based on its type.
func ValidatePrincipalID(principalType PrincipalType, id string) error {
	if id == "" {
		return ErrPrincipalIDEmpty
	}

	if utf8.RuneCountInString(id) > MaxPrincipalIDLength {
		return ErrPrincipalIDTooLong
	}

	// Check for unsafe characters
	if unsafeCharsRegex.MatchString(id) {
		return ErrUnsafeCharacters
	}

	// Type-specific validation
	switch principalType {
	case Service, ServicePrefix:
		return validateSPIFFEURI(id)
	case Machine, MachinePrefix:
		return validateMachineID(id)
	case User, UserGroup:
		return validateUserID(id)
	default:
		// For unknown types, perform basic validation
		return nil
	}
}

// validateSPIFFEURI validates SPIFFE URI format.
func validateSPIFFEURI(id string) error {
	u, err := url.Parse(id)
	if err != nil {
		return ErrInvalidSPIFFEURI
	}

	// Must be spiffe scheme
	if u.Scheme != "spiffe" {
		return ErrInvalidSPIFFEURI
	}

	// Must have a trust domain
	if u.Host == "" {
		return ErrInvalidSPIFFEURI
	}

	// Path must be non-empty for Service, or end with / for ServicePrefix
	if u.Path == "" || u.Path == "/" {
		return ErrInvalidSPIFFEURI
	}

	return nil
}

// validateMachineID validates machine ID format.
func validateMachineID(id string) error {
	if !machineIDRegex.MatchString(id) {
		return ErrInvalidMachineID
	}
	return nil
}

// validateUserID validates user ID format.
func validateUserID(id string) error {
	if !userIDRegex.MatchString(id) {
		return ErrInvalidUserID
	}
	return nil
}

// ValidateAccess validates an access entry.
func ValidateAccess(access Access) error {
	if err := ValidatePrincipalID(access.Type, access.ID); err != nil {
		return fmt.Errorf("invalid principal: %w", err)
	}

	// Validate access type
	if access.AccessType < None || access.AccessType > Admin {
		return errors.New("invalid access type")
	}

	return nil
}

// ValidateACL validates an ACL.
func ValidateACL(acl ACL) error {
	seen := make(map[string]bool)

	for _, access := range acl {
		if err := ValidateAccess(access); err != nil {
			return fmt.Errorf("invalid access entry: %w", err)
		}

		// Check for duplicates
		key := fmt.Sprintf("%d:%s", access.Type, access.ID)
		if seen[key] {
			return errors.New("duplicate principal in ACL")
		}
		seen[key] = true
	}

	return nil
}

// ValidateRequestBodySize validates that request body size is within limits.
func ValidateRequestBodySize(size int64) error {
	if size > MaxRequestBodySize {
		return ErrRequestTooLarge
	}
	return nil
}

// SanitizeString removes potentially dangerous characters from a string.
func SanitizeString(input string) string {
	// Remove null bytes and control characters
	input = strings.Map(func(r rune) rune {
		if r < 32 && r != 9 && r != 10 && r != 13 { // Allow tab, LF, CR
			return -1
		}
		return r
	}, input)

	// Escape HTML special characters
	input = strings.ReplaceAll(input, "&", "&amp;")
	input = strings.ReplaceAll(input, "<", "&lt;")
	input = strings.ReplaceAll(input, ">", "&gt;")
	input = strings.ReplaceAll(input, "\"", "&quot;")
	input = strings.ReplaceAll(input, "'", "&#39;")

	return input
}

// IsValidJSON checks if data is valid JSON.
func IsValidJSON(data []byte) bool {
	var js any
	return json.Unmarshal(data, &js) == nil
}

// ValidateKeyCreation validates all parameters for key creation.
func ValidateKeyCreation(keyID string, data []byte, acl ACL) error {
	if err := ValidateKeyID(keyID); err != nil {
		return fmt.Errorf("invalid key ID: %w", err)
	}

	if err := ValidateKeyData(data); err != nil {
		return fmt.Errorf("invalid key data: %w", err)
	}

	if err := ValidateACL(acl); err != nil {
		return fmt.Errorf("invalid ACL: %w", err)
	}

	return nil
}
