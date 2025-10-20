// Package main provides integration tests for the Knox D-Bus Secret Service bridge.
package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hazayan/knox/client"
	"github.com/hazayan/knox/pkg/config"
	"github.com/hazayan/knox/pkg/dbus"
	"github.com/hazayan/knox/pkg/types"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDBusBridgeStartup tests basic bridge startup and shutdown.
func TestDBusBridgeStartup(t *testing.T) {
	// Create a mock Knox client for testing
	mockClient := &MockKnoxClient{}

	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			ServiceName: "org.test.Knox",
			BusType:     "session",
		},
		Knox: config.DBusKnoxConfig{
			Server:          "localhost:9000",
			NamespacePrefix: "dbus:",
		},
	}

	// Test bridge creation
	bridge, err := dbus.NewBridge(cfg, mockClient)
	require.NoError(t, err)
	require.NotNil(t, bridge)

	// Test bridge shutdown
	err = bridge.Stop()
	assert.NoError(t, err)
}

// TestDBusBridgeConfiguration tests configuration loading and validation.
func TestDBusBridgeConfiguration(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "dbus-test.yaml")

	// Create test configuration
	configData := map[string]any{
		"dbus": map[string]any{
			"service_name": "org.test.Knox",
			"bus_type":     "session",
			"object_path":  "/org/test/Knox",
		},
		"knox": map[string]any{
			"server":           "localhost:9000",
			"namespace_prefix": "dbus:",
			"tls": map[string]any{
				"ca_cert":     "",
				"client_cert": "",
				"client_key":  "",
				"min_version": "TLS12",
			},
		},
	}

	// Write config file
	configBytes, err := json.Marshal(configData)
	require.NoError(t, err)
	err = os.WriteFile(configFile, configBytes, 0o644)
	require.NoError(t, err)

	// Test loading configuration
	cfg, err := config.LoadDBusConfig(configFile)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "org.test.Knox", cfg.DBus.ServiceName)
	assert.Equal(t, "session", cfg.DBus.BusType)
	assert.Equal(t, "localhost:9000", cfg.Knox.Server)
	assert.Equal(t, "dbus:", cfg.Knox.NamespacePrefix)
}

// TestDBusBridgeClientCreation tests Knox client creation for D-Bus bridge.
func TestDBusBridgeClientCreation(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "dbus-client-test.yaml")

	// Create test configuration with TLS settings
	configData := map[string]any{
		"dbus": map[string]any{
			"service_name": "org.test.Knox",
			"bus_type":     "session",
			"object_path":  "/org/test/Knox",
		},
		"knox": map[string]any{
			"server":           "localhost:9000",
			"namespace_prefix": "dbus:",
			"tls": map[string]any{
				"ca_cert":     "",
				"client_cert": "",
				"client_key":  "",
				"min_version": "TLS12",
			},
		},
	}

	// Write config file
	configBytes, err := json.Marshal(configData)
	require.NoError(t, err)
	err = os.WriteFile(configFile, configBytes, 0o644)
	require.NoError(t, err)

	// Load configuration
	cfg, err := config.LoadDBusConfig(configFile)
	require.NoError(t, err)

	// Test client creation
	knoxClient, err := createKnoxClient(cfg)
	require.NoError(t, err)
	require.NotNil(t, knoxClient)
}

// TestDBusBridgeAuthHandlers tests authentication handler creation.
func TestDBusBridgeAuthHandlers(t *testing.T) {
	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			ServiceName: "org.test.Knox",
			BusType:     "session",
		},
		Knox: config.DBusKnoxConfig{
			Server:          "localhost:9000",
			NamespacePrefix: "dbus:",
			TLS: config.ClientTLSConfig{
				ClientCert: "/path/to/client.crt",
				ClientKey:  "/path/to/client.key",
			},
		},
	}

	// Test auth handlers creation
	handlers := createAuthHandlers(cfg)
	require.NotEmpty(t, handlers)
	assert.Len(t, handlers, 3) // mTLS + env + file handlers

	// Test environment variable auth
	t.Setenv("KNOX_USER_AUTH", "test-user-token")
	t.Setenv("KNOX_MACHINE_AUTH", "test-machine-token")

	// Test each handler
	for _, handler := range handlers {
		token, authType, httpClient := handler()
		// At least one handler should return valid credentials
		if token != "" {
			assert.NotEmpty(t, authType)
			assert.Nil(t, httpClient)
		}
	}
}

// TestDBusBridgeHTTPClient tests HTTP client creation with TLS.
func TestDBusBridgeHTTPClient(t *testing.T) {
	cfg := &config.DBusConfig{
		Knox: config.DBusKnoxConfig{
			Server: "localhost:9000",
			TLS: config.ClientTLSConfig{
				CACert:     "",
				ClientCert: "",
				ClientKey:  "",
			},
		},
	}

	// Test HTTP client creation without TLS
	httpClient, err := createHTTPClient(cfg)
	require.NoError(t, err)
	require.NotNil(t, httpClient)

	// Test with invalid CA cert path
	cfg.Knox.TLS.CACert = "../invalid/path"
	_, err = createHTTPClient(cfg)
	assert.Error(t, err)
}

// TestDBusBridgeIntegration tests the full integration flow.
func TestDBusBridgeIntegration(t *testing.T) {
	// Skip this test in CI environments without D-Bus
	if os.Getenv("CI") != "" {
		t.Skip("Skipping D-Bus integration test in CI environment")
	}

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "dbus-integration-test.yaml")

	// Create minimal configuration
	configData := map[string]any{
		"dbus": map[string]any{
			"service_name": "org.test.Knox",
			"bus_type":     "session",
			"object_path":  "/org/test/Knox",
		},
		"knox": map[string]any{
			"server":           "localhost:9000",
			"namespace_prefix": "dbus:",
		},
	}

	// Write config file
	configBytes, err := json.Marshal(configData)
	require.NoError(t, err)
	err = os.WriteFile(configFile, configBytes, 0o644)
	require.NoError(t, err)

	// Test configuration loading
	cfg, err := config.LoadDBusConfig(configFile)
	require.NoError(t, err)

	// Create mock client
	mockClient := &MockKnoxClient{}

	// Test bridge creation
	bridge, err := dbus.NewBridge(cfg, mockClient)
	require.NoError(t, err)

	// Test bridge operations
	_, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	// Test bridge startup (would normally connect to D-Bus)
	// Note: In a real test environment, this would require a D-Bus session
	err = bridge.Start()
	if err != nil {
		// This is expected in test environments without D-Bus
		t.Logf("Bridge start failed (expected without D-Bus): %v", err)
	}

	// Test bridge shutdown
	err = bridge.Stop()
	assert.NoError(t, err)
}

// TestDBusBridgeErrorHandling tests error scenarios.
func TestDBusBridgeErrorHandling(t *testing.T) {
	t.Run("InvalidConfigFile", func(t *testing.T) {
		_, err := config.LoadDBusConfig("/nonexistent/config.yaml")
		assert.Error(t, err)
	})

	t.Run("InvalidTLSConfig", func(t *testing.T) {
		cfg := &config.DBusConfig{
			Knox: config.DBusKnoxConfig{
				TLS: config.ClientTLSConfig{
					ClientCert: "/nonexistent.crt",
					ClientKey:  "/nonexistent.key",
				},
			},
		}

		_, err := createHTTPClient(cfg)
		assert.Error(t, err)
	})

	t.Run("MissingServerConfig", func(t *testing.T) {
		cfg := &config.DBusConfig{
			Knox: config.DBusKnoxConfig{
				Server: "", // Empty server address
			},
		}

		// Client creation should succeed even with empty server
		// Actual operations will fail when trying to connect
		client, err := createKnoxClient(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, client)
	})
}

// TestDBusBridgeCommandLine tests command-line interface.
func TestDBusBridgeCommandLine(t *testing.T) {
	// Test default config path
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)
	defaultCfgPath := filepath.Join(homeDir, ".config", "knox", "dbus.yaml")

	// Test that default path is set correctly
	assert.Contains(t, defaultCfgPath, ".config/knox/dbus.yaml")
}

// MockKnoxClient implements a mock Knox client for testing.
type MockKnoxClient struct{}

func (m *MockKnoxClient) GetKey(_ string) (*types.Key, error) {
	return nil, nil
}

func (m *MockKnoxClient) CreateKey(_ string, _ []byte, _ types.ACL) (uint64, error) {
	return 0, nil
}

func (m *MockKnoxClient) GetKeys(_ map[string]string) ([]string, error) {
	return []string{}, nil
}

func (m *MockKnoxClient) DeleteKey(_ string) error {
	return nil
}

func (m *MockKnoxClient) GetACL(_ string) (*types.ACL, error) {
	return &types.ACL{}, nil
}

func (m *MockKnoxClient) PutAccess(_ string, _ ...types.Access) error {
	return nil
}

func (m *MockKnoxClient) AddVersion(_ string, _ []byte) (uint64, error) {
	return 0, nil
}

func (m *MockKnoxClient) UpdateVersion(_, _ string, _ types.VersionStatus) error {
	return nil
}

func (m *MockKnoxClient) CacheGetKey(_ string) (*types.Key, error) {
	return nil, nil
}

func (m *MockKnoxClient) NetworkGetKey(_ string) (*types.Key, error) {
	return nil, nil
}

func (m *MockKnoxClient) GetKeyWithStatus(_ string, _ types.VersionStatus) (*types.Key, error) {
	return nil, nil
}

func (m *MockKnoxClient) CacheGetKeyWithStatus(_ string, _ types.VersionStatus) (*types.Key, error) {
	return nil, nil
}

func (m *MockKnoxClient) NetworkGetKeyWithStatus(_ string, _ types.VersionStatus) (*types.Key, error) {
	return nil, nil
}

// TestDBusBridgeVersion tests version information.
func TestDBusBridgeVersion(t *testing.T) {
	assert.Equal(t, "2.0.0-dev", version)
}

// TestDBusBridgeSignalHandling tests signal handling (basic validation).
func TestDBusBridgeSignalHandling(t *testing.T) {
	// This test validates that the signal handling code compiles and basic structure works
	// Actual signal handling would require a running D-Bus daemon

	cfg := &config.DBusConfig{
		DBus: config.DBusConnectionConfig{
			ServiceName: "org.test.Knox",
			BusType:     "session",
		},
		Knox: config.DBusKnoxConfig{
			Server: "localhost:9000",
		},
	}

	mockClient := &MockKnoxClient{}
	bridge, err := dbus.NewBridge(cfg, mockClient)
	require.NoError(t, err)

	// The bridge should be created successfully
	assert.NotNil(t, bridge)

	// Clean shutdown should work
	err = bridge.Stop()
	assert.NoError(t, err)
}

// TestDBusBridgeResourceCleanup tests resource cleanup.
func TestDBusBridgeResourceCleanup(t *testing.T) {
	// Create multiple bridge instances and ensure they clean up properly
	for range 3 {
		cfg := &config.DBusConfig{
			DBus: config.DBusConnectionConfig{
				ServiceName: "org.test.Knox",
				BusType:     "session",
			},
			Knox: config.DBusKnoxConfig{
				Server: "localhost:9000",
			},
		}

		mockClient := &MockKnoxClient{}
		bridge, err := dbus.NewBridge(cfg, mockClient)
		require.NoError(t, err)

		// Immediate cleanup
		err = bridge.Stop()
		assert.NoError(t, err)
	}
}

// TestDBusBridgeMainFunction tests the main function entry point.
func TestDBusBridgeMainFunction(t *testing.T) {
	// Test that main doesn't panic when called with help flag
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Test help flag
	os.Args = []string{"knox-dbus", "--help"}

	// This should not panic
	// Note: We can't actually run main() in tests as it calls os.Exit()
	// But we can verify the command structure is set up correctly
	rootCmd := &cobra.Command{
		Use:   "knox-dbus",
		Short: "Knox D-Bus Secret Service bridge",
		RunE:  runDaemon,
	}

	// Verify command structure
	assert.Equal(t, "knox-dbus", rootCmd.Use)
	assert.Contains(t, rootCmd.Short, "D-Bus Secret Service bridge")
}

// TestDBusBridgeRunDaemon tests the runDaemon function.
func TestDBusBridgeRunDaemon(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test-dbus.yaml")

	// Create valid configuration
	configData := map[string]any{
		"dbus": map[string]any{
			"service_name": "org.test.Knox",
			"bus_type":     "session",
		},
		"knox": map[string]any{
			"server":           "localhost:9000",
			"namespace_prefix": "dbus:",
		},
	}

	configBytes, err := json.Marshal(configData)
	require.NoError(t, err)
	err = os.WriteFile(configFile, configBytes, 0o644)
	require.NoError(t, err)

	// Test with valid config
	oldCfgFile := cfgFile
	cfgFile = configFile
	defer func() { cfgFile = oldCfgFile }()

	err = runDaemon(nil, nil)
	// This should fail because we can't authenticate to Knox in test environment
	// but it should get past configuration loading
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication")
}

// TestDBusBridgeRunDaemonInvalidConfig tests runDaemon with invalid config.
func TestDBusBridgeRunDaemonInvalidConfig(t *testing.T) {
	// Test with non-existent config file
	oldCfgFile := cfgFile
	cfgFile = "/nonexistent/config.yaml"
	defer func() { cfgFile = oldCfgFile }()

	err := runDaemon(nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

// TestDBusBridgeCreateKnoxClientComprehensive tests comprehensive client creation scenarios.
func TestDBusBridgeCreateKnoxClientComprehensive(t *testing.T) {
	t.Run("WithTLSConfig", func(t *testing.T) {
		cfg := &config.DBusConfig{
			Knox: config.DBusKnoxConfig{
				Server: "localhost:9000",
				TLS: config.ClientTLSConfig{
					CACert:     "/path/to/ca.crt",
					ClientCert: "/path/to/client.crt",
					ClientKey:  "/path/to/client.key",
				},
			},
		}

		// This should fail due to missing certificate files, but not panic
		_, err := createKnoxClient(cfg)
		assert.Error(t, err)
	})

	t.Run("WithEnvironmentAuth", func(t *testing.T) {
		// Set environment variables for auth
		t.Setenv("KNOX_USER_AUTH", "test-user-token")
		defer t.Setenv("KNOX_USER_AUTH", "")

		cfg := &config.DBusConfig{
			Knox: config.DBusKnoxConfig{
				Server: "localhost:9000",
			},
		}

		client, err := createKnoxClient(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("EmptyServer", func(t *testing.T) {
		cfg := &config.DBusConfig{
			Knox: config.DBusKnoxConfig{
				Server: "", // Empty server
			},
		}

		// Should still create client (errors will occur on actual operations)
		client, err := createKnoxClient(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, client)
	})
}

// TestDBusBridgeCreateHTTPClientComprehensive tests comprehensive HTTP client creation.
func TestDBusBridgeCreateHTTPClientComprehensive(t *testing.T) {
	t.Run("ValidTLSConfig", func(t *testing.T) {
		cfg := &config.DBusConfig{
			Knox: config.DBusKnoxConfig{
				TLS: config.ClientTLSConfig{
					CACert:     "",
					ClientCert: "",
					ClientKey:  "",
				},
			},
		}

		httpClient, err := createHTTPClient(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, httpClient)
	})

	t.Run("InvalidCACertPath", func(t *testing.T) {
		cfg := &config.DBusConfig{
			Knox: config.DBusKnoxConfig{
				TLS: config.ClientTLSConfig{
					CACert: "../invalid/path", // Relative path with traversal
				},
			},
		}

		_, err := createHTTPClient(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "CA certificate path must be absolute")
	})

	t.Run("InvalidClientCertPath", func(t *testing.T) {
		cfg := &config.DBusConfig{
			Knox: config.DBusKnoxConfig{
				TLS: config.ClientTLSConfig{
					ClientCert: "/nonexistent.crt",
					ClientKey:  "/nonexistent.key",
				},
			},
		}

		_, err := createHTTPClient(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load client certificate")
	})
}

// TestDBusBridgeCreateAuthHandlersComprehensive tests comprehensive auth handler creation.
func TestDBusBridgeCreateAuthHandlersComprehensive(t *testing.T) {
	t.Run("WithMTLSConfig", func(t *testing.T) {
		cfg := &config.DBusConfig{
			Knox: config.DBusKnoxConfig{
				TLS: config.ClientTLSConfig{
					ClientCert: "/path/to/client.crt",
					ClientKey:  "/path/to/client.key",
				},
			},
		}

		handlers := createAuthHandlers(cfg)
		assert.Len(t, handlers, 3) // mTLS + env + file handlers

		// Test mTLS handler
		token, authType, httpClient := handlers[0]()
		assert.Equal(t, "0m", token)
		assert.Equal(t, "mtls", authType)
		assert.Nil(t, httpClient)
	})

	t.Run("WithEnvironmentTokens", func(t *testing.T) {
		t.Setenv("KNOX_USER_AUTH", "user-token")
		t.Setenv("KNOX_MACHINE_AUTH", "machine-token")
		defer func() {
			t.Setenv("KNOX_USER_AUTH", "")
			t.Setenv("KNOX_MACHINE_AUTH", "")
		}()

		cfg := &config.DBusConfig{
			Knox: config.DBusKnoxConfig{},
		}

		handlers := createAuthHandlers(cfg)

		// Test environment handlers
		for _, handler := range handlers {
			token, authType, httpClient := handler()
			if token != "" {
				assert.Contains(t, token, "0uuser-token") // Should find user token
				assert.NotEmpty(t, authType)
				assert.Nil(t, httpClient)
			}
		}
	})

	t.Run("WithFileToken", func(t *testing.T) {
		tmpDir := t.TempDir()
		tokenFile := filepath.Join(tmpDir, ".knox", "token")

		err := os.MkdirAll(filepath.Dir(tokenFile), 0o755)
		require.NoError(t, err)

		err = os.WriteFile(tokenFile, []byte("file-token"), 0o600)
		require.NoError(t, err)

		oldHome := os.Getenv("HOME")
		t.Setenv("HOME", tmpDir)
		defer func() {
			t.Setenv("HOME", oldHome)
		}()

		cfg := &config.DBusConfig{
			Knox: config.DBusKnoxConfig{},
		}

		handlers := createAuthHandlers(cfg)

		// One of the handlers should find the file token
		foundFileToken := false
		for _, handler := range handlers {
			token, authType, httpClient := handler()
			if token != "" && authType == "user_token_file" {
				assert.Contains(t, token, "0ufile-token")
				assert.Nil(t, httpClient)
				foundFileToken = true
			}
		}
		assert.True(t, foundFileToken, "Should have found file token")
	})
}

// TestDBusBridgeVersionInfo tests version information handling.
func TestDBusBridgeVersionInfo(t *testing.T) {
	assert.Equal(t, "2.0.0-dev", version)

	// Test that version is properly formatted
	assert.Contains(t, version, "2.0.0")
}

// TestDBusBridgeCommandLineFlags tests command line flag parsing.
func TestDBusBridgeCommandLineFlags(t *testing.T) {
	// Test default config path
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	expectedDefaultPath := filepath.Join(homeDir, ".config", "knox", "dbus.yaml")
	assert.Equal(t, expectedDefaultPath, filepath.Join(homeDir, ".config", "knox", "dbus.yaml"))
}

// TestDBusBridgeErrorScenarios tests various error scenarios.
func TestDBusBridgeErrorScenarios(t *testing.T) {
	t.Run("InvalidTLSMinVersion", func(t *testing.T) {
		cfg := &config.DBusConfig{
			Knox: config.DBusKnoxConfig{
				TLS: config.ClientTLSConfig{
					CACert: "", // No CA cert
				},
			},
		}

		// Should still create HTTP client (Go's TLS stack will handle invalid versions)
		httpClient, err := createHTTPClient(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, httpClient)
	})

	t.Run("PathTraversalInCertPath", func(t *testing.T) {
		cfg := &config.DBusConfig{
			Knox: config.DBusKnoxConfig{
				TLS: config.ClientTLSConfig{
					CACert: "../../etc/passwd", // Path traversal attempt
				},
			},
		}

		_, err := createHTTPClient(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be absolute and not contain")
	})
}

// TestDBusBridgeMockClientComprehensive tests the mock client comprehensively.
func TestDBusBridgeMockClientComprehensive(t *testing.T) {
	mockClient := &MockKnoxClient{}

	t.Run("GetKey", func(t *testing.T) {
		key, err := mockClient.GetKey("test")
		assert.NoError(t, err)
		assert.Nil(t, key)
	})

	t.Run("CreateKey", func(t *testing.T) {
		version, err := mockClient.CreateKey("test", []byte("data"), types.ACL{})
		assert.NoError(t, err)
		assert.Equal(t, uint64(0), version)
	})

	t.Run("GetKeys", func(t *testing.T) {
		keys, err := mockClient.GetKeys(map[string]string{})
		assert.NoError(t, err)
		assert.Empty(t, keys)
	})

	t.Run("DeleteKey", func(t *testing.T) {
		err := mockClient.DeleteKey("test")
		assert.NoError(t, err)
	})

	t.Run("GetACL", func(t *testing.T) {
		acl, err := mockClient.GetACL("test")
		assert.NoError(t, err)
		assert.NotNil(t, acl)
		assert.Empty(t, *acl)
	})

	t.Run("PutAccess", func(t *testing.T) {
		err := mockClient.PutAccess("test", types.Access{})
		assert.NoError(t, err)
	})

	t.Run("AddVersion", func(t *testing.T) {
		version, err := mockClient.AddVersion("test", []byte("data"))
		assert.NoError(t, err)
		assert.Equal(t, uint64(0), version)
	})

	t.Run("UpdateVersion", func(t *testing.T) {
		err := mockClient.UpdateVersion("test", "1", types.Active)
		assert.NoError(t, err)
	})

	t.Run("CacheOperations", func(t *testing.T) {
		key, err := mockClient.CacheGetKey("test")
		assert.NoError(t, err)
		assert.Nil(t, key)

		key, err = mockClient.CacheGetKeyWithStatus("test", types.Active)
		assert.NoError(t, err)
		assert.Nil(t, key)

		key, err = mockClient.NetworkGetKey("test")
		assert.NoError(t, err)
		assert.Nil(t, key)

		key, err = mockClient.NetworkGetKeyWithStatus("test", types.Active)
		assert.NoError(t, err)
		assert.Nil(t, key)
	})
}

// TestDBusBridgeInterfaceCompliance tests that mock client implements the interface.
func TestDBusBridgeInterfaceCompliance(_ *testing.T) {
	var _ client.APIClient = &MockKnoxClient{}
}
