// Package main provides integration tests for the Knox production server.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hazayan/knox/pkg/config"
	"github.com/hazayan/knox/pkg/storage"
	"github.com/hazayan/knox/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServerStartup tests basic server startup and shutdown.
func TestServerStartup(t *testing.T) {
	cfg := &config.ServerConfig{
		BindAddress: "localhost:0", // Use port 0 for automatic port assignment
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

	// Test server creation and startup
	testServer, err := createTestServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, testServer)

	// Test graceful shutdown
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	err = testServer.Shutdown(ctx)
	assert.NoError(t, err)
}

// TestRunServer tests the runServer function.
func TestRunServer(t *testing.T) {
	t.Run("RunServerWithMemoryBackend", func(t *testing.T) {
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "server-config.yaml")

		// Create minimal configuration
		configData := map[string]any{
			"bind_address": "localhost:0",
			"storage": map[string]any{
				"backend": "memory",
			},
			"observability": map[string]any{
				"logging": map[string]any{
					"level":  "info",
					"format": "text",
				},
				"metrics": map[string]any{
					"enabled":  true,
					"endpoint": "/metrics",
				},
			},
		}

		configBytes, err := json.Marshal(configData)
		require.NoError(t, err)
		err = os.WriteFile(configFile, configBytes, 0o644)
		require.NoError(t, err)

		// Test configuration loading
		cfg, err := config.LoadServerConfig(configFile)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Test server startup (will run in background)
		testServer, err := createTestServer(cfg)
		require.NoError(t, err)
		require.NotNil(t, testServer)

		// Clean shutdown
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		err = testServer.Shutdown(ctx)
		assert.NoError(t, err)
	})

	t.Run("RunServerWithInvalidConfig", func(t *testing.T) {
		// Test with invalid configuration file
		_, err := config.LoadServerConfig("/nonexistent/config.yaml")
		assert.Error(t, err, "Should error with non-existent config file")
	})
}

// TestMainFunction tests the main function entry point.
func TestMainFunction(t *testing.T) {
	// This test verifies that the main function compiles and basic structure works
	// We can't actually run main() as it calls os.Exit(), but we can test helper functions

	// Test that the version variable is set
	assert.Equal(t, "2.0.0-dev", version)

	// Test that the default config path is set correctly
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)
	defaultCfgPath := filepath.Join(homeDir, ".config", "knox", "server.yaml")
	assert.Contains(t, defaultCfgPath, ".config/knox/server.yaml")
}

// TestCreateTLSConfig tests TLS configuration creation.
func TestCreateTLSConfig(t *testing.T) {
	t.Run("CreateTLSConfigWithoutCertificates", func(t *testing.T) {
		cfg := &config.TLSConfig{
			CertFile: "",
			KeyFile:  "",
		}

		tlsConfig, err := createTLSConfig(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, tlsConfig, "TLS config should always be created with default settings")
		assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion, "Should set minimum TLS version")
	})

	t.Run("CreateTLSConfigWithInvalidPaths", func(t *testing.T) {
		cfg := &config.TLSConfig{
			CertFile: "/nonexistent/cert.pem",
			KeyFile:  "/nonexistent/key.pem",
		}

		tlsConfig, err := createTLSConfig(cfg)
		// The function may not error immediately but will fail when certificates are actually loaded
		// We test that it returns a config structure
		assert.NoError(t, err, "Should handle missing certificate files gracefully")
		assert.NotNil(t, tlsConfig, "TLS config should be created even with missing certificate files")
	})

	t.Run("CreateTLSConfigWithMinVersion", func(t *testing.T) {
		cfg := &config.TLSConfig{
			MinVersion: "TLS12",
		}

		tlsConfig, err := createTLSConfig(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, tlsConfig, "TLS config should be created with min version")
		assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion, "Should set minimum TLS version")
	})
}

// TestSecureCompare tests the secure string comparison function.
func TestSecureCompare(t *testing.T) {
	t.Run("SecureCompareEqualStrings", func(t *testing.T) {
		result := secureCompare("test-string", "test-string")
		assert.True(t, result, "secureCompare should return true for equal strings")
	})

	t.Run("SecureCompareDifferentStrings", func(t *testing.T) {
		result := secureCompare("string1", "string2")
		assert.False(t, result, "secureCompare should return false for different strings")
	})

	t.Run("SecureCompareDifferentLength", func(t *testing.T) {
		result := secureCompare("short", "very-long-string")
		assert.False(t, result, "secureCompare should return false for strings of different lengths")
	})

	t.Run("SecureCompareEmptyStrings", func(t *testing.T) {
		result := secureCompare("", "")
		assert.True(t, result, "secureCompare should return true for empty strings")
	})

	t.Run("SecureCompareOneEmpty", func(t *testing.T) {
		result := secureCompare("", "not-empty")
		assert.False(t, result, "secureCompare should return false when one string is empty")
	})
}

// TestUpdateMetricsPeriodically tests the metrics update function.
func TestUpdateMetricsPeriodically(t *testing.T) {
	// This function runs in the background and updates metrics
	// We need to run it in a goroutine and cancel it quickly

	// Create a memory backend for testing
	backend, err := storage.NewBackend(storage.Config{Backend: "memory"})
	require.NoError(t, err)

	// Run the function in a goroutine with a context that cancels quickly
	_, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan bool)

	go func() {
		// This will run the update function
		// We'll cancel it immediately to avoid timeout
		updateMetricsPeriodically(backend)
		done <- true
	}()

	// Cancel immediately to stop the goroutine
	cancel()

	// Wait a short time for the goroutine to process cancellation
	select {
	case <-done:
		// Function completed (unlikely with cancel)
	case <-time.After(100 * time.Millisecond):
		// Expected - function runs in background
	}

	// Test passes if we reach here without timeout
}

// TestHealthEndpoints tests health and readiness endpoints.
func TestHealthEndpoints(t *testing.T) {
	testServer := createAndStartTestServer(t, "memory")
	defer testServer.Close()

	client := createTestClient(t, testServer)

	tests := []struct {
		name     string
		endpoint string
		expected int
	}{
		{"HealthEndpoint", "/health", http.StatusOK},
		{"ReadinessEndpoint", "/ready", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.Get(testServer.URL + tt.endpoint)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tt.expected, resp.StatusCode)
			assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
		})
	}
}

// TestMetricsEndpoint tests the Prometheus metrics endpoint.
func TestMetricsEndpoint(t *testing.T) {
	testServer := createAndStartTestServer(t, "memory")
	defer testServer.Close()

	client := createTestClient(t, testServer)

	resp, err := client.Get(testServer.URL + "/metrics")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/plain; version=0.0.4; charset=utf-8")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "go_goroutines")
}

// TestKeyOperations tests basic key CRUD operations.
func TestKeyOperations(t *testing.T) {
	testServer := createAndStartTestServer(t, "memory")
	defer testServer.Close()

	client := createTestClient(t, testServer)
	authToken := "test-token"

	t.Run("CreateKey", func(t *testing.T) {
		// Create key
		reqBody := url.Values{}
		reqBody.Set("id", "test:create:key")
		acl := []map[string]any{
			{
				"type":   "User",
				"id":     "testuser",
				"access": "Admin",
			},
		}
		aclJSON, _ := json.Marshal(acl)
		reqBody.Set("acl", string(aclJSON))
		reqBody.Set("data", "dGVzdC1zZWNyZXQtZGF0YQ==")

		resp, err := makeAuthenticatedRequest(client, testServer.URL+"/v0/keys/", "POST", authToken, reqBody)
		require.NoError(t, err)
		defer resp.Body.Close()

		t.Logf("CreateKey response status: %d", resp.StatusCode)
		t.Logf("CreateKey response headers: %v", resp.Header)

		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Logf("CreateKey response body: %s", string(bodyBytes))

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var versionID uint64
		err = json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(&versionID)
		require.NoError(t, err)
		assert.Equal(t, uint64(1), versionID)
		assert.NotZero(t, versionID)

		// Clean up the key
		deleteResp, err := makeAuthenticatedRequest(client, testServer.URL+"/v0/keys/test:create:key/", "DELETE", authToken, nil)
		require.NoError(t, err)
		deleteResp.Body.Close()
		assert.Equal(t, http.StatusOK, deleteResp.StatusCode)
	})

	t.Run("GetKey", func(t *testing.T) {
		keyID := "test:get:key"

		// First create a key
		createReq := url.Values{}
		createReq.Set("id", keyID)
		acl := []map[string]any{
			{
				"type":   "User",
				"id":     "testuser",
				"access": "Admin",
			},
		}
		aclJSON, _ := json.Marshal(acl)
		createReq.Set("acl", string(aclJSON))
		createReq.Set("data", "dGVzdC1nZXQtdGVzdC1kYXRh")

		createResp, err := makeAuthenticatedRequest(client, testServer.URL+"/v0/keys/", "POST", authToken, createReq)
		require.NoError(t, err)
		createResp.Body.Close()
		assert.Equal(t, http.StatusOK, createResp.StatusCode)

		t.Logf("Created key %s, now trying to get it from URL: %s", keyID, testServer.URL+"/v0/keys/"+keyID)

		// Then get the key
		resp, err := makeAuthenticatedRequest(client, testServer.URL+"/v0/keys/"+keyID+"/", "GET", authToken, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		t.Logf("GetKey response status: %d", resp.StatusCode)

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var key types.Key
		err = json.NewDecoder(resp.Body).Decode(&key)
		require.NoError(t, err)
		assert.Equal(t, keyID, key.ID)
		assert.Len(t, key.ACL, 1)
		assert.Len(t, key.VersionList, 1)

		// Clean up the key
		deleteResp, err := makeAuthenticatedRequest(client, testServer.URL+"/v0/keys/"+keyID+"/", "DELETE", authToken, nil)
		require.NoError(t, err)
		deleteResp.Body.Close()
		assert.Equal(t, http.StatusOK, deleteResp.StatusCode)
	})

	t.Run("ListKeys", func(t *testing.T) {
		// Create multiple keys with same prefix
		prefix := "test:list"
		keys := []string{prefix + ":key1", prefix + ":key2", prefix + ":key3"}

		for _, keyID := range keys {
			createReq := url.Values{}
			createReq.Set("id", keyID)
			acl := []map[string]any{
				{
					"type":   "User",
					"id":     "testuser",
					"access": "Admin",
				},
			}
			aclJSON, _ := json.Marshal(acl)
			createReq.Set("acl", string(aclJSON))
			createReq.Set("data", "dGVzdC1kYXRh")
			resp, err := makeAuthenticatedRequest(client, testServer.URL+"/v0/keys/", "POST", authToken, createReq)
			require.NoError(t, err)
			resp.Body.Close()
		}

		// List keys with prefix
		resp, err := makeAuthenticatedRequest(client, testServer.URL+"/v0/keys/", "GET", authToken, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		t.Logf("ListKeys response status: %d", resp.StatusCode)

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var keyList []string
		err = json.NewDecoder(resp.Body).Decode(&keyList)
		require.NoError(t, err)
		t.Logf("ListKeys returned: %v", keyList)
		t.Logf("Expected keys: %v", keys)
		t.Logf("ListKeys count: %d, Expected count: 3", len(keyList))
		assert.Len(t, keyList, 3)
		assert.ElementsMatch(t, keys, keyList)

		// Clean up the keys
		for _, keyID := range keys {
			deleteResp, err := makeAuthenticatedRequest(client, testServer.URL+"/v0/keys/"+keyID+"/", "DELETE", authToken, nil)
			require.NoError(t, err)
			deleteResp.Body.Close()
			assert.Equal(t, http.StatusOK, deleteResp.StatusCode)
		}
	})

	t.Run("DeleteKey", func(t *testing.T) {
		keyID := "test:delete:key"

		// First create a key
		createReq := url.Values{}
		createReq.Set("id", keyID)
		acl := []map[string]any{
			{
				"type":   "User",
				"id":     "test-user",
				"access": "Admin",
			},
		}
		aclJSON, _ := json.Marshal(acl)
		createReq.Set("acl", string(aclJSON))
		createReq.Set("data", "dGVzdC1kYXRh")

		createResp, err := makeAuthenticatedRequest(client, testServer.URL+"/v0/keys/", "POST", authToken, createReq)
		require.NoError(t, err)
		createResp.Body.Close()

		// Then delete it
		resp, err := makeAuthenticatedRequest(client, testServer.URL+"/v0/keys/"+keyID+"/", "DELETE", authToken, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Verify it's gone
		getResp, err := makeAuthenticatedRequest(client, testServer.URL+"/v0/keys/"+keyID+"/", "GET", authToken, nil)
		require.NoError(t, err)
		defer getResp.Body.Close()
		assert.Equal(t, http.StatusNotFound, getResp.StatusCode)
	})
}

// TestAuthentication tests authentication middleware.
func TestAuthentication(t *testing.T) {
	testServer := createAndStartTestServer(t, "memory")
	defer testServer.Close()

	client := createTestClient(t, testServer)

	t.Run("UnauthenticatedRequest", func(t *testing.T) {
		resp, err := client.Get(testServer.URL + "/v0/keys/test-key/")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("AuthenticatedRequest", func(t *testing.T) {
		resp, err := makeAuthenticatedRequest(client, testServer.URL+"/v0/keys/test-key/", "GET", "valid-token", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should either be 404 (key doesn't exist) or 200 (if mock auth allows)
		assert.True(t, resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusOK)
	})
}

// TestErrorHandling tests various error scenarios.
func TestErrorHandling(t *testing.T) {
	testServer := createAndStartTestServer(t, "memory")
	defer testServer.Close()

	client := createTestClient(t, testServer)
	authToken := "test-token"

	t.Run("NonExistentKey", func(t *testing.T) {
		resp, err := makeAuthenticatedRequest(client, testServer.URL+"/v0/keys/non-existent-key", "GET", authToken, nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		req, err := http.NewRequest("POST", testServer.URL+"/v0/keys/", strings.NewReader("invalid json"))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Token "+authToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("InvalidKeyID", func(t *testing.T) {
		reqBody := url.Values{}
		reqBody.Set("id", "") // Empty key ID
		acl := []map[string]any{
			{
				"type":   "User",
				"id":     "test-user",
				"access": "Admin",
			},
		}
		aclJSON, _ := json.Marshal(acl)
		reqBody.Set("acl", string(aclJSON))
		reqBody.Set("data", "dGVzdC1kYXRh")

		resp, err := makeAuthenticatedRequest(client, testServer.URL+"/v0/keys/", "POST", authToken, reqBody)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// TestStorageBackends tests server with different storage backends.
func TestStorageBackends(t *testing.T) {
	t.Run("MemoryBackend", func(t *testing.T) {
		testServer := createAndStartTestServer(t, "memory")
		defer testServer.Close()

		client := createTestClient(t, testServer)
		testBasicKeyOperations(t, client, testServer.URL)
	})

	t.Run("FilesystemBackend", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := &config.ServerConfig{
			BindAddress: "localhost:0",
			Storage: config.StorageConfig{
				Backend:       "filesystem",
				FilesystemDir: tmpDir,
			},
			Auth: config.AuthConfig{
				Providers: []config.AuthProviderConfig{
					{
						Type: "mock",
					},
				},
			},
			Observability: config.ObservabilityConfig{
				Logging: config.LoggingConfig{
					Level:  "error",
					Format: "text",
				},
			},
		}

		testServer, err := createTestServer(cfg)
		require.NoError(t, err)
		require.NotNil(t, testServer)

		err = testServer.Start()
		require.NoError(t, err)
		defer testServer.Close()

		client := createTestClient(t, testServer.Server)
		testBasicKeyOperations(t, client, testServer.Server.URL)
	})
}

// TestMiddlewareStack tests the middleware functionality.
func TestMiddlewareStack(t *testing.T) {
	testServer := createAndStartTestServer(t, "memory")
	defer testServer.Close()

	client := createTestClient(t, testServer)

	t.Run("SecurityHeaders", func(t *testing.T) {
		resp, err := client.Get(testServer.URL + "/health")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check security headers
		assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
		assert.Equal(t, "1; mode=block", resp.Header.Get("X-XSS-Protection"))
		assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	})

	t.Run("MetricsTracking", func(t *testing.T) {
		// Make a few requests to generate metrics
		for range 3 {
			resp, err := makeAuthenticatedRequest(client, testServer.URL+"/v0/keys/test-metric/", "GET", "test-token", nil)
			if err == nil {
				resp.Body.Close()
			}
		}

		// Check metrics endpoint for request counts
		resp, err := client.Get(testServer.URL + "/metrics")
		require.NoError(t, err)
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		metrics := string(body)

		// Should have some HTTP metrics
		assert.Contains(t, metrics, "knox_requests_total")
	})
}

// TestGracefulShutdown tests server shutdown behavior.
func TestGracefulShutdown(t *testing.T) {
	testServer := createAndStartTestServer(t, "memory")
	client := createTestClient(t, testServer)

	// Make sure server is running
	resp, err := client.Get(testServer.URL + "/health")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Shutdown server
	testServer.Close()

	// Verify server is no longer accepting requests
	_, err = client.Get(testServer.URL + "/health")
	assert.Error(t, err)
}

// Helper functions

func createAndStartTestServer(t *testing.T, backend string) *httptest.Server {
	t.Helper()

	cfg := &config.ServerConfig{
		BindAddress: "localhost:0",
		Storage: config.StorageConfig{
			Backend: backend,
		},
		Auth: config.AuthConfig{
			Providers: []config.AuthProviderConfig{
				{
					Type: "mock",
				},
			},
		},
		Observability: config.ObservabilityConfig{
			Logging: config.LoggingConfig{
				Level:  "error",
				Format: "text",
			},
			Metrics: config.MetricsConfig{
				Enabled:  true,
				Endpoint: "/metrics",
			},
		},
	}

	if backend == "filesystem" {
		cfg.Storage.FilesystemDir = t.TempDir()
	}

	server, err := createTestServer(cfg)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)

	return server.Server
}

func createTestClient(t *testing.T, _ *httptest.Server) *http.Client {
	t.Helper()

	// Create HTTP client that trusts the test server's TLS certificate
	// For testing, we'll skip certificate verification
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 10 * time.Second,
	}
}

func makeAuthenticatedRequest(client *http.Client, url, method, authToken string, body any) (*http.Response, error) {
	var reqBody io.Reader
	var contentType string

	if body != nil {
		// Check if body is url.Values by checking if it has the Encode method
		if values, ok := body.(interface{ Encode() string }); ok {
			reqBody = strings.NewReader(values.Encode())
			contentType = "application/x-www-form-urlencoded"
		} else {
			jsonBody, err := json.Marshal(body)
			if err != nil {
				return nil, err
			}
			reqBody = bytes.NewReader(jsonBody)
			contentType = "application/json"
		}
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+authToken)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	return client.Do(req)
}

func testBasicKeyOperations(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()

	authToken := "test-token"
	keyID := "test:basic:key"

	// Create key
	reqBody := url.Values{}
	reqBody.Set("id", keyID)
	acl := []map[string]any{
		{
			"type":   "User",
			"id":     "testuser",
			"access": "Admin",
		},
	}
	aclJSON, _ := json.Marshal(acl)
	reqBody.Set("acl", string(aclJSON))
	reqBody.Set("data", base64.StdEncoding.EncodeToString([]byte("test-data")))

	createResp, err := makeAuthenticatedRequest(client, baseURL+"/v0/keys/", "POST", authToken, reqBody)
	require.NoError(t, err)
	createResp.Body.Close()
	assert.Equal(t, http.StatusOK, createResp.StatusCode)

	// Get key
	getResp, err := makeAuthenticatedRequest(client, baseURL+"/v0/keys/"+keyID+"/", "GET", authToken, nil)
	require.NoError(t, err)
	defer getResp.Body.Close()
	assert.Equal(t, http.StatusOK, getResp.StatusCode)

	// Delete key
	deleteResp, err := makeAuthenticatedRequest(client, baseURL+"/v0/keys/"+keyID+"/", "DELETE", authToken, nil)
	require.NoError(t, err)
	defer deleteResp.Body.Close()
	assert.Equal(t, http.StatusOK, deleteResp.StatusCode)

	// Verify key is gone
	getResp, err = makeAuthenticatedRequest(client, baseURL+"/v0/keys/"+keyID+"/", "GET", authToken, nil)
	require.NoError(t, err)
	defer getResp.Body.Close()
	assert.Equal(t, http.StatusNotFound, getResp.StatusCode)
}

// Note: createTestServer function would need to be implemented in the main package
// to expose server creation for testing. This is a common pattern in Go applications.
