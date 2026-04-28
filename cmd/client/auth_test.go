package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthLoginStoresToken(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)

	cmd := newAuthLoginCmd()
	cmd.SetArgs([]string{"token-value"})
	var out strings.Builder
	cmd.SetOut(&out)

	err := cmd.Execute()
	require.NoError(t, err)

	tokenFile := filepath.Join(configHome, "knox", "token")
	token, err := readAuthTokenFile(tokenFile)
	require.NoError(t, err)
	assert.Equal(t, "token-value", token)
	assert.Contains(t, out.String(), tokenFile)

	if runtime.GOOS != "windows" {
		info, err := os.Stat(tokenFile)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

		dirInfo, err := os.Stat(filepath.Dir(tokenFile))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())
	}
}

func TestAuthLoginReadsTokenFromStdin(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)

	cmd := newAuthLoginCmd()
	cmd.SetIn(strings.NewReader("stdin-token\n"))
	cmd.SetOut(&strings.Builder{})

	err := cmd.Execute()
	require.NoError(t, err)

	token, err := readAuthTokenFile(filepath.Join(configHome, "knox", "token"))
	require.NoError(t, err)
	assert.Equal(t, "stdin-token", token)
}

func TestAuthLoginRejectsEmptyToken(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	cmd := newAuthLoginCmd()
	cmd.SetIn(strings.NewReader("\n"))

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestAuthStatusJSON(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	require.NoError(t, writeAuthTokenFile(filepath.Join(configHome, "knox", "token"), "token-value"))

	jsonOutput = true
	defer func() { jsonOutput = false }()

	cmd := newAuthStatusCmd()
	var out strings.Builder
	cmd.SetOut(&out)

	err := cmd.Execute()
	require.NoError(t, err)

	var status map[string]any
	require.NoError(t, json.Unmarshal([]byte(out.String()), &status))
	assert.Equal(t, "present", status["status"])
	assert.Equal(t, true, status["present"])
}

func TestAuthLogoutRemovesToken(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	tokenFile := filepath.Join(configHome, "knox", "token")
	require.NoError(t, writeAuthTokenFile(tokenFile, "token-value"))

	cmd := newAuthLogoutCmd()
	var out strings.Builder
	cmd.SetOut(&out)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "Removed token")
	_, err = os.Stat(tokenFile)
	assert.True(t, os.IsNotExist(err))
}

func TestAuthLogoutMissingToken(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)

	cmd := newAuthLogoutCmd()
	var out strings.Builder
	cmd.SetOut(&out)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Contains(t, out.String(), "No stored token")
}
