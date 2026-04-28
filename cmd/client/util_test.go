package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hazayan/knox/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateAuthHandlersEnvironmentTokens(t *testing.T) {
	t.Setenv("KNOX_USER_AUTH", " user-token\n")
	t.Setenv("KNOX_MACHINE_AUTH", "machine-token")

	handlers := createAuthHandlers(&config.ClientProfile{})
	require.Len(t, handlers, 2)

	authToken, authType, clientOverride := handlers[0]()
	assert.Equal(t, "0uuser-token", authToken)
	assert.Equal(t, "user_token", authType)
	assert.Nil(t, clientOverride)
}

func TestCreateAuthHandlersMachineTokenFallback(t *testing.T) {
	t.Setenv("KNOX_USER_AUTH", "")
	t.Setenv("KNOX_MACHINE_AUTH", " machine-token\n")

	handlers := createAuthHandlers(&config.ClientProfile{})
	require.Len(t, handlers, 2)

	authToken, authType, clientOverride := handlers[0]()
	assert.Equal(t, "0mmachine-token", authToken)
	assert.Equal(t, "machine_token", authType)
	assert.Nil(t, clientOverride)
}

func TestCreateAuthHandlersTokenFileFallback(t *testing.T) {
	t.Setenv("KNOX_USER_AUTH", "")
	t.Setenv("KNOX_MACHINE_AUTH", "")
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)

	tokenDir := filepath.Join(configHome, "knox")
	require.NoError(t, os.MkdirAll(tokenDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(tokenDir, "token"), []byte("file-token\n"), 0o600))

	handlers := createAuthHandlers(&config.ClientProfile{})
	require.Len(t, handlers, 2)

	authToken, authType, clientOverride := handlers[1]()
	assert.Equal(t, "0ufile-token", authToken)
	assert.Equal(t, "user_token_file", authType)
	assert.Nil(t, clientOverride)
}

func TestCreateAuthHandlersMissingTokenFile(t *testing.T) {
	t.Setenv("KNOX_USER_AUTH", "")
	t.Setenv("KNOX_MACHINE_AUTH", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	handlers := createAuthHandlers(&config.ClientProfile{})
	require.Len(t, handlers, 2)

	authToken, authType, clientOverride := handlers[1]()
	assert.Empty(t, authToken)
	assert.Empty(t, authType)
	assert.Nil(t, clientOverride)
}

func TestReadAuthTokenFileRejectsInsecurePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission checks do not apply on Windows")
	}

	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("file-token\n"), 0o644))

	_, err := readAuthTokenFile(tokenFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insecure permissions")
}

func TestReadAuthTokenFileRejectsEmptyToken(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("\n"), 0o600))

	_, err := readAuthTokenFile(tokenFile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestResolveCacheFolderUsesXDGProfileDefault(t *testing.T) {
	cacheHome := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheHome)

	cacheDir, err := resolveCacheFolder("laptop", "")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(cacheHome, "knox", "profiles", "laptop"), cacheDir)

	info, err := os.Stat(cacheDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	}
}

func TestResolveCacheFolderSecuresConfiguredDirectory(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0o755))

	resolved, err := resolveCacheFolder("default", cacheDir)
	require.NoError(t, err)
	assert.Equal(t, cacheDir, resolved)

	if runtime.GOOS != "windows" {
		info, err := os.Stat(cacheDir)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	}
}

func TestResolveCacheFolderRejectsTraversal(t *testing.T) {
	_, err := resolveCacheFolder("default", "/tmp/../cache")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parent directory references")
}
