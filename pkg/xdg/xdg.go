// Package xdg provides XDG Base Directory Specification helpers for Knox.
//
// The XDG Base Directory Specification defines standard directories for
// user-specific configuration, data, cache, state, and runtime files.
// This package provides helpers to locate and create these directories
// for Knox applications.
//
// See: https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html
package xdg

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// AppName is the application name used for Knox directories.
const AppName = "knox"

// DirType represents the type of XDG directory.
type DirType string

const (
	// ConfigDir is for user-specific configuration files.
	ConfigDir DirType = "config"
	// DataDir is for user-specific data files.
	DataDir DirType = "data"
	// CacheDir is for user-specific non-essential data files.
	CacheDir DirType = "cache"
	// StateDir is for user-specific state files (preserved between sessions).
	StateDir DirType = "state"
	// RuntimeDir is for user-specific runtime files (cleared on logout).
	RuntimeDir DirType = "runtime"
)

// Permissions for different directory types.
const (
	ConfigDirPerm  = 0o755 // rwxr-xr-x
	DataDirPerm    = 0o700 // rwx------
	CacheDirPerm   = 0o755 // rwxr-xr-x
	StateDirPerm   = 0o700 // rwx------
	RuntimeDirPerm = 0o700 // rwx------
)

// ErrRuntimeDirUnavailable is returned when XDG_RUNTIME_DIR is not available.
var ErrRuntimeDirUnavailable = errors.New("XDG runtime directory not available")

// GetDir returns the XDG directory for the given type and application name.
// If the directory doesn't exist, it will be created with appropriate permissions.
func GetDir(dirType DirType, appName string) (string, error) {
	var baseDir string
	var perm os.FileMode
	var err error

	switch dirType {
	case ConfigDir:
		baseDir, err = os.UserConfigDir()
		perm = ConfigDirPerm
	case DataDir:
		baseDir, err = getUserDataDir()
		perm = DataDirPerm
	case CacheDir:
		baseDir, err = os.UserCacheDir()
		perm = CacheDirPerm
	case StateDir:
		baseDir, err = getUserStateDir()
		perm = StateDirPerm
	case RuntimeDir:
		baseDir, err = getRuntimeDir()
		perm = RuntimeDirPerm
	default:
		return "", fmt.Errorf("unknown directory type: %s", dirType)
	}

	if err != nil {
		return "", fmt.Errorf("failed to get %s directory: %w", dirType, err)
	}

	// Special handling for runtime directory
	if dirType == RuntimeDir && baseDir == "" {
		return "", ErrRuntimeDirUnavailable
	}

	// Construct app-specific directory path
	appDir := filepath.Join(baseDir, appName)

	// Create directory if it doesn't exist
	if err := os.MkdirAll(appDir, perm); err != nil {
		return "", fmt.Errorf("failed to create %s directory: %w", dirType, err)
	}

	return appDir, nil
}

// getUserDataDir returns the user data directory according to XDG spec.
// Falls back to ~/.local/share if XDG_DATA_HOME is not set.
func getUserDataDir() (string, error) {
	// Check XDG_DATA_HOME environment variable
	if xdgDataHome := os.Getenv("XDG_DATA_HOME"); xdgDataHome != "" {
		return xdgDataHome, nil
	}

	// Fallback to ~/.local/share
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(homeDir, ".local", "share"), nil
}

// getUserStateDir returns the user state directory according to XDG spec.
// Falls back to ~/.local/state if XDG_STATE_HOME is not set.
func getUserStateDir() (string, error) {
	// Check XDG_STATE_HOME environment variable
	if xdgStateHome := os.Getenv("XDG_STATE_HOME"); xdgStateHome != "" {
		return xdgStateHome, nil
	}

	// Fallback to ~/.local/state
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(homeDir, ".local", "state"), nil
}

// getRuntimeDir returns the runtime directory according to XDG spec.
// Returns empty string if XDG_RUNTIME_DIR is not available.
func getRuntimeDir() (string, error) {
	// Check XDG_RUNTIME_DIR environment variable
	if xdgRuntimeDir := os.Getenv("XDG_RUNTIME_DIR"); xdgRuntimeDir != "" {
		// Verify the directory exists and has correct permissions
		info, err := os.Stat(xdgRuntimeDir)
		if err != nil {
			return "", fmt.Errorf("XDG_RUNTIME_DIR not accessible: %w", err)
		}
		if !info.IsDir() {
			return "", errors.New("XDG_RUNTIME_DIR is not a directory")
		}
		// Check permissions (should be 0700)
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
			return "", errors.New("XDG_RUNTIME_DIR has incorrect permissions")
		}
		return xdgRuntimeDir, nil
	}

	// XDG_RUNTIME_DIR is not set, return empty string
	return "", nil
}

// Knox-specific directory helpers

// KnoxConfigDir returns the Knox configuration directory.
func KnoxConfigDir() (string, error) {
	return GetDir(ConfigDir, AppName)
}

// KnoxDataDir returns the Knox data directory.
func KnoxDataDir() (string, error) {
	return GetDir(DataDir, AppName)
}

// KnoxCacheDir returns the Knox cache directory.
func KnoxCacheDir() (string, error) {
	return GetDir(CacheDir, AppName)
}

// KnoxStateDir returns the Knox state directory.
func KnoxStateDir() (string, error) {
	return GetDir(StateDir, AppName)
}

// KnoxRuntimeDir returns the Knox runtime directory.
// Returns ErrRuntimeDirUnavailable if XDG_RUNTIME_DIR is not available.
func KnoxRuntimeDir() (string, error) {
	return GetDir(RuntimeDir, AppName)
}

// File path helpers

// ConfigFile returns the full path to a configuration file within the Knox config directory.
func ConfigFile(filename string) (string, error) {
	configDir, err := KnoxConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, filename), nil
}

// DataFile returns the full path to a data file within the Knox data directory.
func DataFile(filename string) (string, error) {
	dataDir, err := KnoxDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dataDir, filename), nil
}

// CacheFile returns the full path to a cache file within the Knox cache directory.
func CacheFile(filename string) (string, error) {
	cacheDir, err := KnoxCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cacheDir, filename), nil
}

// StateFile returns the full path to a state file within the Knox state directory.
func StateFile(filename string) (string, error) {
	stateDir, err := KnoxStateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(stateDir, filename), nil
}

// RuntimeFile returns the full path to a runtime file within the Knox runtime directory.
// Returns ErrRuntimeDirUnavailable if XDG_RUNTIME_DIR is not available.
func RuntimeFile(filename string) (string, error) {
	runtimeDir, err := KnoxRuntimeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(runtimeDir, filename), nil
}

// Migration helpers

// LegacyConfigDir returns the legacy ~/.knox configuration directory.
func LegacyConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, ".knox"), nil
}

// LegacyConfigFile returns the full path to a file in the legacy ~/.knox directory.
func LegacyConfigFile(filename string) (string, error) {
	legacyDir, err := LegacyConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(legacyDir, filename), nil
}

// MigrateIfLegacyExists checks if legacy configuration exists and returns the path
// to use. This supports backward compatibility during transition.
//
// Returns (legacyPath, true, nil) if legacy file exists and should be used.
// Returns (xdgPath, false, nil) if legacy file doesn't exist.
// Returns error if there's an issue checking the files.
func MigrateIfLegacyExists(filename string) (string, bool, error) {
	// Check if legacy file exists
	legacyPath, err := LegacyConfigFile(filename)
	if err != nil {
		return "", false, err
	}

	if _, err := os.Stat(legacyPath); err == nil {
		// Legacy file exists, use it
		return legacyPath, true, nil
	} else if !os.IsNotExist(err) {
		// Some other error
		return "", false, err
	}

	// Legacy file doesn't exist, use XDG location
	xdgPath, err := ConfigFile(filename)
	if err != nil {
		return "", false, err
	}

	return xdgPath, false, nil
}

// MigrateFile migrates a file from legacy location to XDG location.
// If the file doesn't exist in the legacy location, does nothing.
// If migration succeeds, the legacy file is removed.
func MigrateFile(filename string) error {
	legacyPath, err := LegacyConfigFile(filename)
	if err != nil {
		return err
	}

	// Check if legacy file exists
	legacyData, err := os.ReadFile(legacyPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Nothing to migrate
			return nil
		}
		return fmt.Errorf("failed to read legacy file: %w", err)
	}

	// Get XDG destination
	xdgPath, err := ConfigFile(filename)
	if err != nil {
		return err
	}

	// Ensure XDG directory exists
	xdgDir := filepath.Dir(xdgPath)
	if err := os.MkdirAll(xdgDir, ConfigDirPerm); err != nil {
		return fmt.Errorf("failed to create XDG directory: %w", err)
	}

	// Write to XDG location
	if err := os.WriteFile(xdgPath, legacyData, 0o600); err != nil {
		return fmt.Errorf("failed to write to XDG location: %w", err)
	}

	// Remove legacy file
	if err := os.Remove(legacyPath); err != nil {
		// Log but don't fail - we successfully migrated even if we can't clean up
		_ = err
	}

	return nil
}

// Profile-specific helpers

// ProfileCacheDir returns the cache directory for a specific profile.
func ProfileCacheDir(profileName string) (string, error) {
	cacheDir, err := KnoxCacheDir()
	if err != nil {
		return "", err
	}
	profileDir := filepath.Join(cacheDir, "profiles", profileName)
	if err := os.MkdirAll(profileDir, CacheDirPerm); err != nil {
		return "", fmt.Errorf("failed to create profile cache directory: %w", err)
	}
	return profileDir, nil
}

// ProfileCacheFile returns the full path to a cache file for a specific profile.
func ProfileCacheFile(profileName, filename string) (string, error) {
	profileDir, err := ProfileCacheDir(profileName)
	if err != nil {
		return "", err
	}
	return filepath.Join(profileDir, filename), nil
}
