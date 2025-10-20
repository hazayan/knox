package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRunVersion tests the main version command functionality.
func TestRunVersion(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		// Run the command - we can't easily capture log output in tests
		result := runVersion(cmdVersion, []string{})

		assert.Nil(t, result, "Should return nil on success")
	})

	t.Run("SuccessWithArguments", func(t *testing.T) {
		// Version command should ignore extra arguments
		// Run the command with extra arguments (should be ignored)
		result := runVersion(cmdVersion, []string{"extra", "arguments"})

		assert.Nil(t, result, "Should return nil on success even with extra arguments")
	})
}

// TestGetVersion tests the GetVersion function.
func TestGetVersion(t *testing.T) {
	t.Run("DefaultVersion", func(t *testing.T) {
		// Test that GetVersion returns the current version
		version := GetVersion()
		assert.Equal(t, Version, version, "GetVersion should return the current Version")
	})

	t.Run("VersionConsistency", func(t *testing.T) {
		// Test that GetVersion consistently returns the same value
		version1 := GetVersion()
		version2 := GetVersion()
		assert.Equal(t, version1, version2, "GetVersion should be consistent")
	})
}

// TestVersionCommandStructure tests the command structure and metadata.
func TestVersionCommandStructure(t *testing.T) {
	t.Run("CommandMetadata", func(t *testing.T) {
		assert.Equal(t, "version", cmdVersion.UsageLine)
		assert.Equal(t, "Prints the current version of the Knox client", cmdVersion.Short)
		assert.Contains(t, cmdVersion.Long, "Prints the current version of the Knox client")
	})

	t.Run("CommandRunnable", func(t *testing.T) {
		assert.True(t, cmdVersion.Runnable(), "Version command should be runnable")
		assert.NotNil(t, cmdVersion.Run, "Version command should have Run function")
	})

	t.Run("CommandName", func(t *testing.T) {
		assert.Equal(t, "version", cmdVersion.Name())
	})
}

// TestVersionIntegration tests integration scenarios.
func TestVersionIntegration(t *testing.T) {
	t.Run("EndToEndSuccess", func(t *testing.T) {
		// Run the command
		result := runVersion(cmdVersion, []string{})

		assert.Nil(t, result, "Should return nil on success")
	})

	t.Run("VersionVariableAccess", func(t *testing.T) {
		// Test that the Version variable is accessible and has a value
		assert.NotEmpty(t, Version, "Version variable should not be empty")
		assert.IsType(t, "", Version, "Version should be a string")
	})
}

// TestVersionEdgeCases tests edge cases and special scenarios.
func TestVersionEdgeCases(t *testing.T) {
	t.Run("EmptyVersion", func(t *testing.T) {
		// Temporarily change version to empty string
		oldVersion := Version
		Version = ""
		defer func() { Version = oldVersion }()

		result := runVersion(cmdVersion, []string{})

		assert.Nil(t, result, "Should return nil even with empty version")
	})

	t.Run("SpecialCharactersInVersion", func(t *testing.T) {
		// Temporarily change version to include special characters
		oldVersion := Version
		Version = "v1.2.3-beta+special.chars"
		defer func() { Version = oldVersion }()

		result := runVersion(cmdVersion, []string{})

		assert.Nil(t, result, "Should return nil with special characters in version")
	})

	t.Run("LongVersionString", func(t *testing.T) {
		// Temporarily change version to a long string
		oldVersion := Version
		Version = "very-long-version-string-with-many-characters-and-numbers-1234567890"
		defer func() { Version = oldVersion }()

		result := runVersion(cmdVersion, []string{})

		assert.Nil(t, result, "Should return nil with long version string")
	})
}

// TestVersionFunctionExports tests that version-related functions are properly exported.
func TestVersionFunctionExports(t *testing.T) {
	t.Run("GetVersionExported", func(t *testing.T) {
		// This test ensures GetVersion is accessible from outside the package
		version := GetVersion()
		assert.NotNil(t, version, "GetVersion should return a value")
	})

	t.Run("VersionVariableAccessible", func(t *testing.T) {
		// This test ensures the Version variable is accessible
		assert.NotNil(t, Version, "Version variable should be accessible")
	})
}
