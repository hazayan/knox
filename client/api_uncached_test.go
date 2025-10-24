package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hazayan/knox/pkg/types"
)

// testHTTPClient is a custom HTTP client for testing that uses HTTP instead of HTTPS.
type testHTTPClient struct {
	*http.Client
}

// Do overrides the default HTTP client to use HTTP for testing.
func (c *testHTTPClient) Do(req *http.Request) (*http.Response, error) {
	// Replace https with http for test servers
	if req.URL.Scheme == "https" {
		req.URL.Scheme = "http"
	}
	return c.Client.Do(req)
}

// TestUncachedHTTPClient_CacheGetKey tests CacheGetKey method.
func TestUncachedHTTPClient_CacheGetKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v0/keys/test-key/" {
			t.Errorf("Unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		key := &types.Key{
			ID: "test-key",
			ACL: types.ACL{
				{Type: types.User, ID: "test-user", AccessType: types.Read},
			},
			VersionList: []types.KeyVersion{
				{ID: 1, Data: []byte("test-data"), Status: types.Primary},
			},
			VersionHash: "test-hash",
		}
		response := &types.Response{
			Status: "ok",
			Data:   key,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Mock auth handler that returns a test token
	mockAuthHandler := func() (string, string, HTTP) { return "test-auth-token", "test-type", nil }
	uncachedClient := NewUncachedClient(server.URL[7:], &testHTTPClient{&http.Client{}}, []AuthHandler{mockAuthHandler}, "test-version")

	key, err := uncachedClient.CacheGetKey("test-key")
	if err != nil {
		t.Fatalf("CacheGetKey failed: %v", err)
	}

	if key.ID != "test-key" {
		t.Errorf("Expected key ID 'test-key', got '%s'", key.ID)
	}
	if len(key.VersionList) != 1 {
		t.Errorf("Expected 1 version, got %d", len(key.VersionList))
	}
}

// TestUncachedHTTPClient_GetKey tests GetKey method.
func TestUncachedHTTPClient_GetKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v0/keys/test-key/" {
			t.Errorf("Unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		key := &types.Key{
			ID: "test-key",
			ACL: types.ACL{
				{Type: types.User, ID: "test-user", AccessType: types.Read},
			},
			VersionList: []types.KeyVersion{
				{ID: 1, Data: []byte("test-data"), Status: types.Primary},
			},
			VersionHash: "test-hash",
		}
		response := &types.Response{
			Status: "ok",
			Data:   key,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Mock auth handler that returns a test token
	mockAuthHandler := func() (string, string, HTTP) { return "test-auth-token", "test-type", nil }
	uncachedClient := NewUncachedClient(server.URL[7:], &testHTTPClient{&http.Client{}}, []AuthHandler{mockAuthHandler}, "test-version")

	key, err := uncachedClient.GetKey("test-key")
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if key.ID != "test-key" {
		t.Errorf("Expected key ID 'test-key', got '%s'", key.ID)
	}
}

// TestUncachedHTTPClient_CacheGetKeyWithStatus tests CacheGetKeyWithStatus method.
func TestUncachedHTTPClient_CacheGetKeyWithStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v0/keys/test-key/" {
			t.Errorf("Unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		key := &types.Key{
			ID: "test-key",
			ACL: types.ACL{
				{Type: types.User, ID: "test-user", AccessType: types.Read},
			},
			VersionList: []types.KeyVersion{
				{ID: 1, Data: []byte("test-data"), Status: types.Inactive},
			},
			VersionHash: "test-hash",
		}
		response := &types.Response{
			Status: "ok",
			Data:   key,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Mock auth handler that returns a test token
	mockAuthHandler := func() (string, string, HTTP) { return "test-auth-token", "test-type", nil }
	uncachedClient := NewUncachedClient(server.URL[7:], &testHTTPClient{&http.Client{}}, []AuthHandler{mockAuthHandler}, "test-version")

	key, err := uncachedClient.CacheGetKeyWithStatus("test-key", types.Inactive)
	if err != nil {
		t.Fatalf("CacheGetKeyWithStatus failed: %v", err)
	}

	if key.ID != "test-key" {
		t.Errorf("Expected key ID 'test-key', got '%s'", key.ID)
	}
	if len(key.VersionList) != 1 || key.VersionList[0].Status != types.Inactive {
		t.Errorf("Expected inactive version, got status: %v", key.VersionList[0].Status)
	}
}

// TestUncachedHTTPClient_NetworkGetKeyWithStatus tests NetworkGetKeyWithStatus method.
func TestUncachedHTTPClient_NetworkGetKeyWithStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v0/keys/test-key/" {
			t.Errorf("Unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if r.URL.RawQuery != "status=\"Inactive\"" {
			t.Errorf("Expected status query parameter, got: %s", r.URL.RawQuery)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		key := &types.Key{
			ID: "test-key",
			ACL: types.ACL{
				{Type: types.User, ID: "test-user", AccessType: types.Read},
			},
			VersionList: []types.KeyVersion{
				{ID: 1, Data: []byte("test-data"), Status: types.Inactive},
			},
			VersionHash: "test-hash",
		}
		response := &types.Response{
			Status: "ok",
			Data:   key,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Mock auth handler that returns a test token
	mockAuthHandler := func() (string, string, HTTP) { return "test-auth-token", "test-type", nil }
	uncachedClient := NewUncachedClient(server.URL[7:], &testHTTPClient{&http.Client{}}, []AuthHandler{mockAuthHandler}, "test-version")

	key, err := uncachedClient.NetworkGetKeyWithStatus("test-key", types.Inactive)
	if err != nil {
		t.Fatalf("NetworkGetKeyWithStatus failed: %v", err)
	}

	if key.ID != "test-key" {
		t.Errorf("Expected key ID 'test-key', got '%s'", key.ID)
	}
}

// TestUncachedHTTPClient_GetKeyWithStatus tests GetKeyWithStatus method.
func TestUncachedHTTPClient_GetKeyWithStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v0/keys/test-key/" {
			t.Errorf("Unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		key := &types.Key{
			ID: "test-key",
			ACL: types.ACL{
				{Type: types.User, ID: "test-user", AccessType: types.Read},
			},
			VersionList: []types.KeyVersion{
				{ID: 1, Data: []byte("test-data"), Status: types.Active},
			},
			VersionHash: "test-hash",
		}
		response := &types.Response{
			Status: "ok",
			Data:   key,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Mock auth handler that returns a test token
	mockAuthHandler := func() (string, string, HTTP) { return "test-auth-token", "test-type", nil }
	uncachedClient := NewUncachedClient(server.URL[7:], &testHTTPClient{&http.Client{}}, []AuthHandler{mockAuthHandler}, "test-version")

	key, err := uncachedClient.GetKeyWithStatus("test-key", types.Active)
	if err != nil {
		t.Fatalf("GetKeyWithStatus failed: %v", err)
	}

	if key.ID != "test-key" {
		t.Errorf("Expected key ID 'test-key', got '%s'", key.ID)
	}
}

// TestUncachedHTTPClient_CreateKey tests CreateKey method.
func TestUncachedHTTPClient_CreateKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v0/keys/" {
			t.Errorf("Unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if err := r.ParseForm(); err != nil {
			t.Errorf("Failed to parse form: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if r.Form.Get("id") != "new-key" {
			t.Errorf("Expected key ID 'new-key', got '%s'", r.Form.Get("id"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		response := &types.Response{
			Status: "ok",
			Data:   123,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Mock auth handler that returns a test token
	mockAuthHandler := func() (string, string, HTTP) { return "test-auth-token", "test-type", nil }
	uncachedClient := NewUncachedClient(server.URL[7:], &testHTTPClient{&http.Client{}}, []AuthHandler{mockAuthHandler}, "test-version")

	acl := types.ACL{
		{Type: types.User, ID: "test-user", AccessType: types.Read},
	}
	keyID, err := uncachedClient.CreateKey("new-key", []byte("key-data"), acl)
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	if keyID != 123 {
		t.Errorf("Expected key ID 123, got %d", keyID)
	}
}

// TestUncachedHTTPClient_GetKeys tests GetKeys method.
func TestUncachedHTTPClient_GetKeys(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v0/keys/" {
			t.Errorf("Unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		keys := []string{"key1", "key2", "key3"}
		response := &types.Response{
			Status: "ok",
			Data:   keys,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Mock auth handler that returns a test token
	mockAuthHandler := func() (string, string, HTTP) { return "test-auth-token", "test-type", nil }
	uncachedClient := NewUncachedClient(server.URL[7:], &testHTTPClient{&http.Client{}}, []AuthHandler{mockAuthHandler}, "test-version")

	keys, err := uncachedClient.GetKeys(nil)
	if err != nil {
		t.Fatalf("GetKeys failed: %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("Expected 3 keys, got %d", len(keys))
	}
	expectedKeys := []string{"key1", "key2", "key3"}
	for i, key := range keys {
		if key != expectedKeys[i] {
			t.Errorf("Expected key %s at position %d, got %s", expectedKeys[i], i, key)
		}
	}
}

// TestUncachedHTTPClient_DeleteKey tests DeleteKey method.
func TestUncachedHTTPClient_DeleteKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" || r.URL.Path != "/v0/keys/test-key/" {
			t.Errorf("Unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		response := &types.Response{
			Status: "ok",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Mock auth handler that returns a test token
	mockAuthHandler := func() (string, string, HTTP) { return "test-auth-token", "test-type", nil }
	uncachedClient := NewUncachedClient(server.URL[7:], &testHTTPClient{&http.Client{}}, []AuthHandler{mockAuthHandler}, "test-version")

	err := uncachedClient.DeleteKey("test-key")
	if err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}
}

// TestUncachedHTTPClient_GetACL tests GetACL method.
func TestUncachedHTTPClient_GetACL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v0/keys/test-key/access/" {
			t.Errorf("Unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		acl := types.ACL{
			{Type: types.User, ID: "user1", AccessType: types.Read},
			{Type: types.User, ID: "user2", AccessType: types.Write},
		}
		response := &types.Response{
			Status: "ok",
			Data:   acl,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Mock auth handler that returns a test token
	mockAuthHandler := func() (string, string, HTTP) { return "test-auth-token", "test-type", nil }
	uncachedClient := NewUncachedClient(server.URL[7:], &testHTTPClient{&http.Client{}}, []AuthHandler{mockAuthHandler}, "test-version")

	acl, err := uncachedClient.GetACL("test-key")
	if err != nil {
		t.Fatalf("GetACL failed: %v", err)
	}

	if len(*acl) != 2 {
		t.Errorf("Expected 2 ACL entries, got %d", len(*acl))
	}
}

// TestUncachedHTTPClient_PutAccess tests PutAccess method.
func TestUncachedHTTPClient_PutAccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" || r.URL.Path != "/v0/keys/test-key/access/" {
			t.Errorf("Unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if err := r.ParseForm(); err != nil {
			t.Errorf("Failed to parse form: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var acl []types.Access
		if err := json.Unmarshal([]byte(r.Form.Get("acl")), &acl); err != nil {
			t.Errorf("Failed to decode ACL: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if len(acl) != 1 || acl[0].ID != "new-user" {
			t.Errorf("Unexpected ACL data: %+v", acl)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		response := &types.Response{
			Status: "ok",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Mock auth handler that returns a test token
	mockAuthHandler := func() (string, string, HTTP) { return "test-auth-token", "test-type", nil }
	uncachedClient := NewUncachedClient(server.URL[7:], &testHTTPClient{&http.Client{}}, []AuthHandler{mockAuthHandler}, "test-version")

	access := types.Access{Type: types.User, ID: "new-user", AccessType: types.Read}
	err := uncachedClient.PutAccess("test-key", access)
	if err != nil {
		t.Fatalf("PutAccess failed: %v", err)
	}
}

// TestUncachedHTTPClient_AddVersion tests AddVersion method.
func TestUncachedHTTPClient_AddVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v0/keys/test-key/versions/" {
			t.Errorf("Unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if err := r.ParseForm(); err != nil {
			t.Errorf("Failed to parse form: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if r.Form.Get("data") != "dmVyc2lvbi1kYXRh" { // base64 of "version-data"
			t.Errorf("Unexpected data: %s", r.Form.Get("data"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		response := &types.Response{
			Status: "ok",
			Data:   456,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Mock auth handler that returns a test token
	mockAuthHandler := func() (string, string, HTTP) { return "test-auth-token", "test-type", nil }
	uncachedClient := NewUncachedClient(server.URL[7:], &testHTTPClient{&http.Client{}}, []AuthHandler{mockAuthHandler}, "test-version")

	versionID, err := uncachedClient.AddVersion("test-key", []byte("version-data"))
	if err != nil {
		t.Fatalf("AddVersion failed: %v", err)
	}

	if versionID != 456 {
		t.Errorf("Expected version ID 456, got %d", versionID)
	}
}

// TestUncachedHTTPClient_UpdateVersion tests UpdateVersion method.
func TestUncachedHTTPClient_UpdateVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" || r.URL.Path != "/v0/keys/test-key/versions/123/" {
			t.Errorf("Unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if err := r.ParseForm(); err != nil {
			t.Errorf("Failed to parse form: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if r.Form.Get("status") != "\"Active\"" {
			t.Errorf("Expected status 'Active', got '%s'", r.Form.Get("status"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		response := &types.Response{
			Status: "ok",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Mock auth handler that returns a test token
	mockAuthHandler := func() (string, string, HTTP) { return "test-auth-token", "test-type", nil }
	uncachedClient := NewUncachedClient(server.URL[7:], &testHTTPClient{&http.Client{}}, []AuthHandler{mockAuthHandler}, "test-version")

	err := uncachedClient.UpdateVersion("test-key", "123", types.Active)
	if err != nil {
		t.Fatalf("UpdateVersion failed: %v", err)
	}
}

// TestUncachedHTTPClient_ErrorHandling tests error handling.
func TestUncachedHTTPClient_ErrorHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := &types.Response{
			Status: "error",
			Code:   types.InternalServerErrorCode,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Mock auth handler that returns a test token
	mockAuthHandler := func() (string, string, HTTP) { return "test-auth-token", "test-type", nil }
	uncachedClient := NewUncachedClient(server.URL[7:], &testHTTPClient{&http.Client{}}, []AuthHandler{mockAuthHandler}, "test-version")

	// Test GetKey error
	_, err := uncachedClient.GetKey("test-key")
	if err == nil {
		t.Error("Expected error from GetKey, got nil")
	}

	// Test CreateKey error
	_, err = uncachedClient.CreateKey("test-key", []byte("data"), types.ACL{})
	if err == nil {
		t.Error("Expected error from CreateKey, got nil")
	}

	// Test DeleteKey error
	err = uncachedClient.DeleteKey("test-key")
	if err == nil {
		t.Error("Expected error from DeleteKey, got nil")
	}
}

// TestUncachedHTTPClient_NetworkErrors tests network error scenarios.
func TestUncachedHTTPClient_NetworkErrors(t *testing.T) {
	// Create client with invalid URL to simulate network errors
	// Mock auth handler that returns a test token
	mockAuthHandler := func() (string, string, HTTP) { return "test-auth-token", "test-type", nil }
	uncachedClient := NewUncachedClient("http://invalid-server:9999", &testHTTPClient{&http.Client{}}, []AuthHandler{mockAuthHandler}, "test-version")

	_, err := uncachedClient.GetKey("test-key")
	if err == nil {
		t.Error("Expected network error from GetKey, got nil")
	}
}

// TestUncachedHTTPClient_JSONError tests JSON parsing errors.
func TestUncachedHTTPClient_JSONError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("invalid json data"))
	}))
	defer server.Close()

	// Mock auth handler that returns a test token
	mockAuthHandler := func() (string, string, HTTP) { return "test-auth-token", "test-type", nil }
	uncachedClient := NewUncachedClient(server.URL[7:], &testHTTPClient{&http.Client{}}, []AuthHandler{mockAuthHandler}, "test-version")

	_, err := uncachedClient.GetKey("test-key")
	if err == nil {
		t.Error("Expected JSON parsing error from GetKey, got nil")
	}
}
