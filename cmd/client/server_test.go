package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hazayan/knox/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerHealthCmd(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/health", r.URL.Path)
		_, _ = w.Write([]byte("healthy"))
	}))
	defer testServer.Close()

	withTestClientConfig(t, testServer.URL)
	cmd := newServerHealthCmd()

	var out strings.Builder
	cmd.SetOut(&out)

	err := cmd.Execute()
	require.NoError(t, err)
	assert.Equal(t, "ok: healthy\n", out.String())
}

func TestServerReadyCmdReturnsErrorOnNonOK(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/ready", r.URL.Path)
		http.Error(w, "not ready", http.StatusServiceUnavailable)
	}))
	defer testServer.Close()

	withTestClientConfig(t, testServer.URL)
	cmd := newServerReadyCmd()

	var out strings.Builder
	cmd.SetOut(&out)

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "/ready returned failed")
	assert.Contains(t, out.String(), "failed: not ready")
}

func TestServerInfoCmdJSON(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			_, _ = w.Write([]byte("healthy"))
		case "/ready":
			_, _ = w.Write([]byte("ready"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer testServer.Close()

	withTestClientConfig(t, testServer.URL)
	jsonOutput = true
	defer func() { jsonOutput = false }()

	cmd := newServerInfoCmd()
	var out strings.Builder
	cmd.SetOut(&out)

	err := cmd.Execute()
	require.NoError(t, err)

	var result map[string]any
	require.NoError(t, json.Unmarshal([]byte(out.String()), &result))
	assert.Equal(t, "test", result["profile"])
	assert.Equal(t, testServer.URL, result["server"])
	assert.Equal(t, testServer.URL, result["base_url"])
	assert.Equal(t, false, result["tls"])
}

func TestServerBaseURL(t *testing.T) {
	assert.Equal(t, "http://localhost:9000", serverBaseURL(&config.ClientProfile{Server: "localhost:9000"}))
	assert.Equal(t, "http://127.0.0.1:9000", serverBaseURL(&config.ClientProfile{Server: "http://127.0.0.1:9000/"}))
	assert.Equal(t, "https://localhost:9000", serverBaseURL(&config.ClientProfile{
		Server: "localhost:9000",
		TLS: config.ClientTLSConfig{
			CACert: "/tmp/ca.pem",
		},
	}))
}

func withTestClientConfig(t *testing.T, serverURL string) {
	t.Helper()

	previousCfg := cfg
	t.Cleanup(func() {
		cfg = previousCfg
	})

	cfg = &config.ClientConfig{
		CurrentProfile: "test",
		Profiles: map[string]config.ClientProfile{
			"test": {
				Server: serverURL,
				Cache: config.CacheConfig{
					Enabled: false,
				},
			},
		},
	}
}
