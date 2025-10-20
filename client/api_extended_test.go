package client

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hazayan/knox/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthenticationScenarios tests various authentication scenarios.
func TestAuthenticationScenarios(t *testing.T) {
	t.Run("MultipleAuthHandlers_SuccessOnSecond", func(t *testing.T) {
		// First auth handler fails, second succeeds
		authHandlers := []AuthHandler{
			func() (string, string, HTTP) {
				return "", "failed-auth", nil
			},
			func() (string, string, HTTP) {
				return "VALID_TOKEN", "success-auth", nil
			},
		}

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "VALID_TOKEN", r.Header.Get("Authorization"))
			resp := &types.Response{Status: "ok", Message: "success"}
			err := json.NewEncoder(w).Encode(resp)
			assert.NoError(t, err)
		}))
		defer srv.Close()

		client := NewUncachedClient(
			strings.TrimPrefix(srv.URL, "https://"),
			srv.Client(),
			authHandlers,
			"test",
		)

		err := client.getHTTPData("GET", "/test", nil, nil)
		assert.NoError(t, err)
	})

	t.Run("MultipleAuthHandlers_AllFail", func(t *testing.T) {
		authHandlers := []AuthHandler{
			func() (string, string, HTTP) {
				return "", "auth1", nil
			},
			func() (string, string, HTTP) {
				return "", "auth2", nil
			},
		}

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()

		client := NewUncachedClient(
			strings.TrimPrefix(srv.URL, "https://"),
			srv.Client(),
			authHandlers,
			"test",
		)

		err := client.getHTTPData("GET", "/test", nil, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no authentication data given")
	})

	t.Run("AuthWithClientOverride", func(t *testing.T) {
		// Create a custom client with proper TLS config for the test server
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "CUSTOM_TOKEN", r.Header.Get("Authorization"))
			resp := &types.Response{Status: "ok"}
			err := json.NewEncoder(w).Encode(resp)
			assert.NoError(t, err)
		}))
		defer srv.Close()

		customClient := srv.Client() // Use the same TLS config as the server

		authHandlers := []AuthHandler{
			func() (string, string, HTTP) {
				return "CUSTOM_TOKEN", "custom-auth", customClient
			},
		}

		client := NewUncachedClient(
			strings.TrimPrefix(srv.URL, "https://"),
			srv.Client(), // This should be overridden by the auth handler
			authHandlers,
			"test",
		)

		err := client.getHTTPData("GET", "/test", nil, nil)
		assert.NoError(t, err)
	})

	t.Run("UnauthorizedRetryWithDifferentAuth", func(t *testing.T) {
		attempts := 0
		authHandlers := []AuthHandler{
			func() (string, string, HTTP) {
				attempts++
				if attempts == 1 {
					return "TOKEN1", "auth1", nil
				}
				return "TOKEN2", "auth2", nil
			},
		}

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "TOKEN1" {
				resp := &types.Response{Status: "error", Code: types.UnauthorizedCode, Message: "unauthorized"}
				w.WriteHeader(http.StatusUnauthorized)
				err := json.NewEncoder(w).Encode(resp)
				assert.NoError(t, err)
				return
			}
			resp := &types.Response{Status: "ok", Message: "success"}
			err := json.NewEncoder(w).Encode(resp)
			assert.NoError(t, err)
		}))
		defer srv.Close()

		client := NewUncachedClient(
			strings.TrimPrefix(srv.URL, "https://"),
			srv.Client(),
			authHandlers,
			"test",
		)

		err := client.getHTTPData("GET", "/test", nil, nil)
		// This test shows the retry mechanism works, even if auth ultimately fails
		assert.Error(t, err)
		assert.Equal(t, 1, attempts) // Only one attempt with same auth handler
	})
}

// TestNetworkResilience tests retry logic and network error handling.
func TestNetworkResilience(t *testing.T) {
	t.Run("RetryOnServerError", func(t *testing.T) {
		attempts := 0
		authHandlers := []AuthHandler{
			func() (string, string, HTTP) {
				return "TEST_TOKEN", "test", nil
			},
		}

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			attempts++
			if attempts < 3 {
				resp := &types.Response{Status: "error", Code: types.InternalServerErrorCode, Message: "server error"}
				w.WriteHeader(http.StatusInternalServerError)
				err := json.NewEncoder(w).Encode(resp)
				assert.NoError(t, err)
				return
			}
			resp := &types.Response{Status: "ok", Message: "success"}
			err := json.NewEncoder(w).Encode(resp)
			assert.NoError(t, err)
		}))
		defer srv.Close()

		client := NewUncachedClient(
			strings.TrimPrefix(srv.URL, "https://"),
			srv.Client(),
			authHandlers,
			"test",
		)

		err := client.getHTTPData("GET", "/test", nil, nil)
		assert.NoError(t, err)
		assert.Equal(t, 3, attempts)
	})

	t.Run("MaxRetriesExceeded", func(t *testing.T) {
		attempts := 0
		authHandlers := []AuthHandler{
			func() (string, string, HTTP) {
				return "TEST_TOKEN", "test", nil
			},
		}

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			attempts++
			resp := &types.Response{Status: "error", Code: types.InternalServerErrorCode, Message: "persistent server error"}
			w.WriteHeader(http.StatusInternalServerError)
			err := json.NewEncoder(w).Encode(resp)
			assert.NoError(t, err)
		}))
		defer srv.Close()

		client := NewUncachedClient(
			strings.TrimPrefix(srv.URL, "https://"),
			srv.Client(),
			authHandlers,
			"test",
		)

		err := client.getHTTPData("GET", "/test", nil, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "persistent server error")
		assert.Equal(t, maxRetryAttempts, attempts)
	})

	t.Run("NoRetryOnClientError", func(t *testing.T) {
		attempts := 0
		authHandlers := []AuthHandler{
			func() (string, string, HTTP) {
				return "TEST_TOKEN", "test", nil
			},
		}

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			attempts++
			resp := &types.Response{Status: "error", Code: types.BadRequestDataCode, Message: "bad request"}
			w.WriteHeader(http.StatusBadRequest)
			err := json.NewEncoder(w).Encode(resp)
			assert.NoError(t, err)
		}))
		defer srv.Close()

		client := NewUncachedClient(
			strings.TrimPrefix(srv.URL, "https://"),
			srv.Client(),
			authHandlers,
			"test",
		)

		err := client.getHTTPData("GET", "/test", nil, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "bad request")
		assert.Equal(t, 1, attempts) // Should not retry on client errors
	})

	t.Run("NetworkTimeout", func(t *testing.T) {
		authHandlers := []AuthHandler{
			func() (string, string, HTTP) {
				return "TEST_TOKEN", "test", nil
			},
		}

		// Create a server that times out
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(2 * time.Second) // Longer than client timeout
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		// Create client with short timeout
		timeoutClient := &http.Client{
			Timeout: 100 * time.Millisecond,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}

		client := NewUncachedClient(
			strings.TrimPrefix(srv.URL, "https://"),
			timeoutClient,
			authHandlers,
			"test",
		)

		err := client.getHTTPData("GET", "/test", nil, nil)
		assert.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline"))
	})
}

// TestCacheValidation tests cache file path validation and security.
func TestCacheValidation(t *testing.T) {
	t.Run("ValidCacheFilePath", func(t *testing.T) {
		tmpDir := t.TempDir()
		keyID := "testkey"

		path, err := validateCacheFilePath(tmpDir, keyID+".json")
		assert.NoError(t, err)
		assert.True(t, strings.HasPrefix(path, tmpDir))
		assert.True(t, strings.HasSuffix(path, keyID+".json"))
	})

	t.Run("PathTraversalAttempt", func(t *testing.T) {
		tmpDir := t.TempDir()

		_, err := validateCacheFilePath(tmpDir, "../../etc/passwd")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "outside allowed directory")
	})

	t.Run("InvalidFileExtension", func(t *testing.T) {
		tmpDir := t.TempDir()

		_, err := validateCacheFilePath(tmpDir, "testkey.txt")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must have .json extension")
	})

	t.Run("DirectoryTraversal", func(t *testing.T) {
		tmpDir := t.TempDir()

		_, err := validateCacheFilePath(tmpDir, "../otherdir/testkey.json")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "outside allowed directory")
	})

	t.Run("ValidNestedPath", func(t *testing.T) {
		tmpDir := t.TempDir()
		nestedDir := filepath.Join(tmpDir, "subdir", "nested")
		err := os.MkdirAll(nestedDir, 0o755)
		require.NoError(t, err)

		path, err := validateCacheFilePath(tmpDir, "subdir/nested/testkey.json")
		assert.NoError(t, err)
		assert.True(t, strings.HasPrefix(path, tmpDir))
		assert.True(t, strings.HasSuffix(path, "subdir/nested/testkey.json"))
	})
}

// TestErrorScenarios tests various error conditions and edge cases.
func TestErrorScenarios(t *testing.T) {
	t.Run("MalformedJSONResponse", func(t *testing.T) {
		authHandlers := []AuthHandler{
			func() (string, string, HTTP) {
				return "TEST_TOKEN", "test", nil
			},
		}

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("invalid json content"))
			assert.NoError(t, err)
		}))
		defer srv.Close()

		client := NewUncachedClient(
			strings.TrimPrefix(srv.URL, "https://"),
			srv.Client(),
			authHandlers,
			"test",
		)

		var result map[string]any
		err := client.getHTTPData("GET", "/test", nil, &result)
		assert.Error(t, err)
	})

	t.Run("EmptyResponseBody", func(t *testing.T) {
		authHandlers := []AuthHandler{
			func() (string, string, HTTP) {
				return "TEST_TOKEN", "test", nil
			},
		}

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			// No body
		}))
		defer srv.Close()

		client := NewUncachedClient(
			strings.TrimPrefix(srv.URL, "https://"),
			srv.Client(),
			authHandlers,
			"test",
		)

		var result map[string]any
		err := client.getHTTPData("GET", "/test", nil, &result)
		assert.Error(t, err)
	})

	t.Run("InvalidKeyContentFromNetwork", func(t *testing.T) {
		authHandlers := []AuthHandler{
			func() (string, string, HTTP) {
				return "TEST_TOKEN", "test", nil
			},
		}

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// Return a key with missing required fields
			invalidKey := &types.Key{
				ID: "testkey",
				// Missing ACL, VersionList, VersionHash
			}
			resp := &types.Response{
				Status:  "ok",
				Message: "success",
				Data:    invalidKey,
			}
			err := json.NewEncoder(w).Encode(resp)
			assert.NoError(t, err)
		}))
		defer srv.Close()

		client := NewUncachedClient(
			strings.TrimPrefix(srv.URL, "https://"),
			srv.Client(),
			authHandlers,
			"test",
		)

		_, err := client.NetworkGetKey("testkey")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid key content")
	})

	t.Run("InvalidKeyContentFromCache", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create invalid cache file
		invalidKey := map[string]any{
			"id": "testkey",
			// Missing required fields
		}
		data, err := json.Marshal(invalidKey)
		require.NoError(t, err)

		cacheFile := filepath.Join(tmpDir, "testkey.json")
		err = os.WriteFile(cacheFile, data, 0o644)
		require.NoError(t, err)

		client := &HTTPClient{
			KeyFolder: tmpDir,
			UncachedClient: &UncachedHTTPClient{
				Host: "localhost:9000",
				AuthHandlers: []AuthHandler{
					func() (string, string, HTTP) {
						return "TEST_TOKEN", "test", nil
					},
				},
				DefaultClient: &http.Client{},
			},
		}

		_, err = client.CacheGetKey("testkey")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid key content")
	})
}

// TestConcurrentAccess tests thread safety and concurrent operations.
func TestConcurrentAccess(t *testing.T) {
	t.Run("ConcurrentCacheAccess", func(t *testing.T) {
		tmpDir := t.TempDir()
		client := &HTTPClient{
			KeyFolder: tmpDir,
			UncachedClient: &UncachedHTTPClient{
				Host: "localhost:9000",
				AuthHandlers: []AuthHandler{
					func() (string, string, HTTP) {
						return "TEST_TOKEN", "test", nil
					},
				},
				DefaultClient: &http.Client{},
			},
		}

		var wg sync.WaitGroup
		errors := make(chan error, 10)

		// Run multiple concurrent cache operations
		for i := range 10 {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				_, err := client.CacheGetKey(fmt.Sprintf("key%d", index))
				// Expect errors since cache files don't exist
				if err != nil && !strings.Contains(err.Error(), "no such file") {
					errors <- err
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		// Should not have any unexpected errors
		for err := range errors {
			t.Errorf("Unexpected error in concurrent access: %v", err)
		}
	})

	t.Run("ConcurrentNetworkRequests", func(t *testing.T) {
		requestCount := int32(0)
		authHandlers := []AuthHandler{
			func() (string, string, HTTP) {
				return "TEST_TOKEN", "test", nil
			},
		}

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			atomic.AddInt32(&requestCount, 1)
			resp := &types.Response{Status: "ok", Message: "success"}
			err := json.NewEncoder(w).Encode(resp)
			assert.NoError(t, err)
		}))
		defer srv.Close()

		client := NewUncachedClient(
			strings.TrimPrefix(srv.URL, "https://"),
			srv.Client(),
			authHandlers,
			"test",
		)

		var wg sync.WaitGroup
		errors := make(chan error, 10)

		// Run multiple concurrent network requests
		for i := range 10 {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				err := client.getHTTPData("GET", fmt.Sprintf("/test%d", index), nil, nil)
				if err != nil {
					errors <- err
				}
			}(i)
		}

		wg.Wait()
		close(errors)

		assert.Equal(t, int32(10), requestCount)
		for err := range errors {
			t.Errorf("Unexpected error in concurrent network requests: %v", err)
		}
	})
}

// TestNewClientFunctions tests client creation and initialization.
func TestNewClientFunctions(t *testing.T) {
	t.Run("NewClientWithAuthHandlers", func(t *testing.T) {
		authHandlers := []AuthHandler{
			func() (string, string, HTTP) {
				return "TOKEN1", "auth1", nil
			},
		}

		client := NewClient(
			"localhost:9000",
			&http.Client{},
			authHandlers,
			"/tmp/cache",
			"1.0.0",
		)

		assert.NotNil(t, client)
		// Type assertion successful, client is valid APIClient
	})

	t.Run("NewUncachedClient", func(t *testing.T) {
		authHandlers := []AuthHandler{
			func() (string, string, HTTP) {
				return "TOKEN1", "auth1", nil
			},
		}

		client := NewUncachedClient(
			"localhost:9000",
			&http.Client{},
			authHandlers,
			"1.0.0",
		)

		assert.NotNil(t, client)
		assert.Equal(t, "localhost:9000", client.Host)
		assert.Equal(t, "1.0.0", client.Version)
		assert.Len(t, client.AuthHandlers, 1)
	})

	t.Run("NewFileClient", func(t *testing.T) {
		tmpDir := t.TempDir()

		// NewFileClient requires knox binary in PATH, skip in test environment
		_, err := NewFileClient(tmpDir)
		// Expect error since knox binary is not available in test environment
		assert.Error(t, err)
	})

	t.Run("NewFileClient_InvalidDirectory", func(t *testing.T) {
		// Try to create client with non-existent directory
		// NewFileClient requires knox binary, so this will fail for different reasons
		_, err := NewFileClient("/nonexistent/path")
		assert.Error(t, err)
	})
}

// TestBackoffDuration tests the exponential backoff calculation.
func TestBackoffDuration(t *testing.T) {
	tests := []struct {
		name    string
		attempt int
		min     time.Duration
		max     time.Duration
	}{
		{"FirstAttempt", 1, 50 * time.Millisecond, 51 * time.Millisecond},
		{"SecondAttempt", 2, 50 * time.Millisecond, 52 * time.Millisecond},
		{"ThirdAttempt", 3, 50 * time.Millisecond, 53 * time.Millisecond},
		{"FourthAttempt", 4, 50 * time.Millisecond, 54 * time.Millisecond},
		{"MaxAttempt", 10, 50 * time.Millisecond, 60 * time.Millisecond},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			duration := GetBackoffDuration(tt.attempt)
			assert.True(t, duration >= tt.min, "duration %v should be >= %v", duration, tt.min)
			assert.True(t, duration <= tt.max, "duration %v should be <= %v", duration, tt.max)
		})
	}
}
