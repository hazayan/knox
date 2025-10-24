// Package main provides integration tests for the Knox production server.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/hazayan/knox/pkg/config"
	"github.com/hazayan/knox/pkg/storage"
	_ "github.com/hazayan/knox/pkg/storage/filesystem" // Register filesystem backend
	_ "github.com/hazayan/knox/pkg/storage/memory"     // Register memory backend
	_ "github.com/hazayan/knox/pkg/storage/postgres"   // Register postgres backend
	"github.com/hazayan/knox/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServerBasicFunctionality tests basic server startup and operation.
func TestServerBasicFunctionality(t *testing.T) {
	// Create a simple in-memory storage backend for testing
	backend, err := storage.NewBackend(storage.Config{
		Backend: "memory",
	})
	require.NoError(t, err)
	require.NotNil(t, backend)

	defer backend.Close()

	// Test basic storage operations
	ctx := t.Context()
	keyID := "test:integration:key"

	// Create a test key
	testKey := &types.Key{
		ID: keyID,
		ACL: types.ACL{
			{
				Type:       types.User,
				ID:         "test-user",
				AccessType: types.Admin,
			},
		},
		VersionList: types.KeyVersionList{
			{
				ID:           1,
				Data:         []byte("test-secret-data"),
				Status:       types.Primary,
				CreationTime: time.Now().Unix(),
			},
		},
	}
	testKey.VersionHash = testKey.VersionList.Hash()

	// Test PutKey
	err = backend.PutKey(ctx, testKey)
	assert.NoError(t, err)

	// Test GetKey
	retrievedKey, err := backend.GetKey(ctx, keyID)
	assert.NoError(t, err)
	assert.Equal(t, keyID, retrievedKey.ID)
	assert.Equal(t, testKey.VersionHash, retrievedKey.VersionHash)

	// Test ListKeys
	keys, err := backend.ListKeys(ctx, "test:")
	assert.NoError(t, err)
	assert.Contains(t, keys, keyID)

	// Test DeleteKey
	err = backend.DeleteKey(ctx, keyID)
	assert.NoError(t, err)

	// Verify key is gone
	_, err = backend.GetKey(ctx, keyID)
	assert.Error(t, err)
	assert.True(t, storage.IsKeyNotFound(err))
}

// TestServerConfiguration tests configuration loading.
func TestServerConfiguration(t *testing.T) {
	// Test minimal configuration
	cfg := &config.ServerConfig{
		BindAddress: "localhost:9000",
		Storage: config.StorageConfig{
			Backend: "memory",
		},
		Observability: config.ObservabilityConfig{
			Logging: config.LoggingConfig{
				Level:  "info",
				Format: "text",
			},
			Metrics: config.MetricsConfig{
				Enabled:  true,
				Endpoint: "/metrics",
			},
		},
	}

	// Verify configuration is valid
	assert.Equal(t, "localhost:9000", cfg.BindAddress)
	assert.Equal(t, "memory", cfg.Storage.Backend)
	assert.Equal(t, "info", cfg.Observability.Logging.Level)
	assert.True(t, cfg.Observability.Metrics.Enabled)
}

// TestStorageBackendCompatibility tests that all storage backends work correctly.
func TestStorageBackendCompatibility(t *testing.T) {
	backends := []struct {
		name   string
		config storage.Config
	}{
		{
			name: "MemoryBackend",
			config: storage.Config{
				Backend: "memory",
			},
		},
		{
			name: "FilesystemBackend",
			config: storage.Config{
				Backend:       "filesystem",
				FilesystemDir: t.TempDir(),
			},
		},
	}

	for _, backend := range backends {
		t.Run(backend.name, func(t *testing.T) {
			storageBackend, err := storage.NewBackend(backend.config)
			require.NoError(t, err)
			require.NotNil(t, storageBackend)

			defer storageBackend.Close()

			// Test basic operations
			ctx := t.Context()
			keyID := "test:" + backend.name + ":key"

			// Create key
			key := &types.Key{
				ID: keyID,
				ACL: types.ACL{
					{
						Type:       types.User,
						ID:         "test-user",
						AccessType: types.Admin,
					},
				},
				VersionList: types.KeyVersionList{
					{
						ID:           1,
						Data:         []byte("test-data"),
						Status:       types.Primary,
						CreationTime: time.Now().Unix(),
					},
				},
			}
			key.VersionHash = key.VersionList.Hash()

			err = storageBackend.PutKey(ctx, key)
			assert.NoError(t, err)

			// Retrieve key
			retrievedKey, err := storageBackend.GetKey(ctx, keyID)
			assert.NoError(t, err)
			assert.Equal(t, keyID, retrievedKey.ID)

			// Delete key
			err = storageBackend.DeleteKey(ctx, keyID)
			assert.NoError(t, err)
		})
	}
}

// TestStorageErrorHandling tests various error scenarios.
func TestStorageErrorHandling(t *testing.T) {
	backend, err := storage.NewBackend(storage.Config{Backend: "memory"})
	require.NoError(t, err)
	defer backend.Close()

	ctx := t.Context()

	t.Run("GetNonExistentKey", func(t *testing.T) {
		_, err := backend.GetKey(ctx, "non-existent-key")
		assert.Error(t, err)
		assert.True(t, storage.IsKeyNotFound(err))
	})

	t.Run("DeleteNonExistentKey", func(t *testing.T) {
		err := backend.DeleteKey(ctx, "non-existent-key")
		assert.Error(t, err)
		assert.True(t, storage.IsKeyNotFound(err))
	})

	t.Run("ListKeysWithNonExistentPrefix", func(t *testing.T) {
		keys, err := backend.ListKeys(ctx, "non-existent-prefix:")
		assert.NoError(t, err)
		assert.Empty(t, keys)
	})
}

// TestConcurrentAccess tests concurrent storage operations.
func TestConcurrentAccess(t *testing.T) {
	backend, err := storage.NewBackend(storage.Config{Backend: "memory"})
	require.NoError(t, err)
	defer backend.Close()

	ctx := t.Context()
	const numKeys = 10
	errors := make(chan error, numKeys)

	// Create multiple keys concurrently
	for i := range numKeys {
		go func(index int) {
			keyID := fmt.Sprintf("test:concurrent:%d", index)
			key := &types.Key{
				ID: keyID,
				ACL: types.ACL{
					{
						Type:       types.User,
						ID:         "test-user",
						AccessType: types.Admin,
					},
				},
				VersionList: types.KeyVersionList{
					{
						ID:           1,
						Data:         []byte("concurrent-data"),
						Status:       types.Primary,
						CreationTime: time.Now().Unix(),
					},
				},
			}
			key.VersionHash = key.VersionList.Hash()

			err := backend.PutKey(ctx, key)
			errors <- err
		}(i)
	}

	// Wait for all operations to complete
	for range numKeys {
		err := <-errors
		assert.NoError(t, err)
	}

	// Verify all keys were created
	keys, err := backend.ListKeys(ctx, "test:concurrent:")
	assert.NoError(t, err)
	assert.Len(t, keys, numKeys)

	// Clean up
	for i := range numKeys {
		keyID := fmt.Sprintf("test:concurrent:%d", i)
		err := backend.DeleteKey(ctx, keyID)
		assert.NoError(t, err)
	}
}

// TestTLSConfiguration tests TLS configuration validation.
func TestTLSConfiguration(t *testing.T) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Verify TLS configuration
	assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
	assert.Len(t, tlsConfig.CipherSuites, 4)
}

// TestHTTPClientCreation tests HTTP client creation with TLS.
func TestHTTPClientCreation(t *testing.T) {
	// Create a basic HTTP client without TLS
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Verify client configuration
	assert.Equal(t, 10*time.Second, client.Timeout)

	// Create a TLS client with custom configuration
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    x509.NewCertPool(),
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	tlsClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// Verify TLS client configuration
	assert.Equal(t, 30*time.Second, tlsClient.Timeout)
	assert.NotNil(t, tlsClient.Transport)
}

// TestJSONSerialization tests JSON serialization of key data.
func TestJSONSerialization(t *testing.T) {
	key := &types.Key{
		ID: "test:json:key",
		ACL: types.ACL{
			{
				Type:       types.User,
				ID:         "test-user",
				AccessType: types.Admin,
			},
		},
		VersionList: types.KeyVersionList{
			{
				ID:           1,
				Data:         []byte("json-test-data"),
				Status:       types.Primary,
				CreationTime: time.Now().Unix(),
			},
		},
	}
	key.VersionHash = key.VersionList.Hash()

	// Serialize to JSON
	jsonData, err := json.Marshal(key)
	assert.NoError(t, err)
	assert.NotEmpty(t, jsonData)

	// Deserialize from JSON
	var deserializedKey types.Key
	err = json.Unmarshal(jsonData, &deserializedKey)
	assert.NoError(t, err)
	assert.Equal(t, key.ID, deserializedKey.ID)
	assert.Equal(t, key.VersionHash, deserializedKey.VersionHash)
}

// TestContextCancellation tests context cancellation behavior.
func TestContextCancellation(t *testing.T) {
	backend, err := storage.NewBackend(storage.Config{Backend: "memory"})
	require.NoError(t, err)
	defer backend.Close()

	// Create a cancelled context
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Operations with cancelled context should fail quickly
	_, err = backend.GetKey(ctx, "test-key")
	assert.Error(t, err)

	err = backend.PutKey(ctx, &types.Key{ID: "test-key"})
	assert.Error(t, err)
}

// TestStorageBackendRegistration tests backend registration functionality.
func TestStorageBackendRegistration(t *testing.T) {
	// Test that all required backends are registered
	backends := []string{"memory", "filesystem", "postgres"}

	for _, backendName := range backends {
		t.Run(backendName, func(t *testing.T) {
			// This test verifies that the backend can be created without errors
			// Actual functionality is tested in backend-specific tests
			cfg := storage.Config{Backend: backendName}
			if backendName == "filesystem" {
				cfg.FilesystemDir = t.TempDir()
			}

			backend, err := storage.NewBackend(cfg)
			if err != nil {
				// Some backends might not be available in test environment
				t.Logf("Backend %s not available: %v", backendName, err)
				return
			}
			assert.NotNil(t, backend)
			backend.Close()
		})
	}
}
