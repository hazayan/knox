// Package main provides the Knox production HTTP server.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/hazayan/knox/pkg/config"
	"github.com/hazayan/knox/pkg/crypto"
	"github.com/hazayan/knox/pkg/observability/logging"
	"github.com/hazayan/knox/pkg/observability/metrics"
	"github.com/hazayan/knox/pkg/storage"
	_ "github.com/hazayan/knox/pkg/storage/filesystem" // Register filesystem backend
	_ "github.com/hazayan/knox/pkg/storage/memory"     // Register memory backend
	_ "github.com/hazayan/knox/pkg/storage/postgres"   // Register postgres backend
	_ "github.com/hazayan/knox/pkg/storage/etcd"       // Register etcd backend
	"github.com/hazayan/knox/pkg/types"
	"github.com/hazayan/knox/server"
	"github.com/hazayan/knox/server/auth"
	pkgauth "github.com/hazayan/knox/pkg/auth"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"golang.org/x/time/rate"
)

var (
	cfgFile string
	version = "2.0.0-dev"
)

// TestServer wraps httptest.Server with Knox-specific functionality.
type TestServer struct {
	*httptest.Server
	storageBackend storage.Backend
}

// Start starts the test server.
func (ts *TestServer) Start() error {
	// httptest.Server starts automatically
	return nil
}

// Shutdown gracefully shuts down the test server.
func (ts *TestServer) Shutdown(_ context.Context) error {
	if ts.storageBackend != nil {
		return ts.storageBackend.Close()
	}
	return nil
}

// createTestServer creates a test server instance for integration testing
// This function is exported for use in test files.
func createTestServer(cfg *config.ServerConfig) (*TestServer, error) {
	// Initialize logging
	if err := logging.Initialize(logging.Config{
		Level:  cfg.Observability.Logging.Level,
		Format: cfg.Observability.Logging.Format,
	}); err != nil {
		return nil, fmt.Errorf("failed to initialize logging: %w", err)
	}

	// Initialize storage backend
	storageCfg := storage.Config{
		Backend: cfg.Storage.Backend,
	}

	switch cfg.Storage.Backend {
	case "filesystem":
		storageCfg.FilesystemDir = cfg.Storage.FilesystemDir
	case "postgres":
		storageCfg.PostgresConnectionString = cfg.Storage.PostgresConnectionString
		storageCfg.PostgresMaxConnections = cfg.Storage.PostgresMaxConnections
	}

	backend, err := storage.NewBackend(storageCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage backend: %w", err)
	}
	logging.Infof("Created storage backend: %s", cfg.Storage.Backend)

	// Create router and server
	router := createRouter(backend, cfg)

	// Create test server
	logging.Infof("Starting test server on %s", cfg.BindAddress)
	testServer := httptest.NewTLSServer(router)

	return &TestServer{
		Server:         testServer,
		storageBackend: backend,
	}, nil
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "knox-server",
		Short: "Knox production server",
		Long:  `Knox is a service for storing and rotating secrets, keys, and passwords.`,
		RunE:  runServer,
	}

	rootCmd.Flags().StringVarP(&cfgFile, "config", "c", "/etc/knox/server.yaml", "Path to configuration file")
	rootCmd.Flags().String("version", "", "Print version and exit")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// createRouter creates the HTTP router with all middleware and routes
// This function is exported for use in test files.
func createRouter(backend storage.Backend, cfg *config.ServerConfig) *mux.Router {
	router := mux.NewRouter()

	// Apply middleware stack - convert HandlerFunc middleware to mux.MiddlewareFunc
	router.Use(convertToMuxMiddleware(loggingMiddleware))
	router.Use(convertToMuxMiddleware(metricsMiddleware))
	router.Use(convertToMuxMiddleware(securityHeadersMiddleware))

	// Setup auth providers and apply auth middleware
	authProviders := setupAuthProviders(cfg)
	router.Use(convertToMuxMiddleware(authMiddleware(authProviders)))

	// Setup rate limiting and apply rate limit middleware
	router.Use(convertToMuxMiddleware(rateLimitMiddleware(100))) // Default: 100 requests per second

	// Register routes
	registerRoutes(router, backend)

	// Add health and metrics endpoints with backend context
	router.HandleFunc("/health", healthHandler(backend)).Methods("GET")
	router.HandleFunc("/ready", readinessHandler(backend)).Methods("GET")
	router.Handle("/metrics", secureMetricsHandler(promhttp.Handler())).Methods("GET")

	return router
}

// convertToMuxMiddleware converts a HandlerFunc middleware to mux.MiddlewareFunc.
func convertToMuxMiddleware(middleware func(http.HandlerFunc) http.HandlerFunc) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			middleware(next.ServeHTTP)(w, r)
		})
	}
}

// registerRoutes registers all Knox API routes.
func registerRoutes(router *mux.Router, backend storage.Backend) {
	// Basic test routes for integration testing
	router.HandleFunc("/v0/keys/", func(w http.ResponseWriter, r *http.Request) {
		// List keys endpoint
		if r.Method == "GET" {
			keys, err := backend.ListKeys(r.Context(), r.URL.Query().Get("prefix"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(keys); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		}

		// Create key endpoint
		if r.Method == "POST" {
			if err := r.ParseForm(); err != nil {
				logging.Errorf("Failed to parse form data: %v", err)
				http.Error(w, "Invalid form data", http.StatusBadRequest)
				return
			}
			keyID := r.Form.Get("id")
			dataStr := r.Form.Get("data")
			aclStr := r.Form.Get("acl")

			if keyID == "" {
				http.Error(w, "Missing key ID", http.StatusBadRequest)
				return
			}

			data, err := base64.StdEncoding.DecodeString(dataStr)
			if err != nil {
				http.Error(w, "Invalid data encoding", http.StatusBadRequest)
				return
			}

			var acl types.ACL
			if aclStr != "" {
				if err := json.Unmarshal([]byte(aclStr), &acl); err != nil {
					logging.Errorf("Failed to parse ACL JSON: %v", err)
					http.Error(w, "Invalid ACL format", http.StatusBadRequest)
					return
				}

				// Validate ACL before using it
				if err := acl.Validate(); err != nil {
					logging.Errorf("ACL validation failed: %v", err)
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
			} else {
				// Default ACL if not provided
				acl = types.ACL{
					{
						Type:       types.User,
						ID:         "test-user",
						AccessType: types.Admin,
					},
				}
			}

			key := &types.Key{
				ID:  keyID,
				ACL: acl,
				VersionList: types.KeyVersionList{
					{
						ID:     1,
						Data:   data,
						Status: types.Primary,
					},
				},
			}
			key.VersionHash = key.VersionList.Hash()

			// Validate the key before storing
			if err := key.Validate(); err != nil {
				logging.Errorf("Key validation failed for %s: %v", keyID, err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			if err := backend.PutKey(r.Context(), key); err != nil {
				logging.Errorf("Failed to store key %s: %v", keyID, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(uint64(1)); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		}

		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}).Methods("GET", "POST")

	router.HandleFunc("/v0/keys/{keyID}/", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		keyID := vars["keyID"]

		if r.Method == "GET" {
			key, err := backend.GetKey(r.Context(), keyID)
			if err != nil {
				if storage.IsKeyNotFound(err) {
					http.Error(w, "Key not found", http.StatusNotFound)
				} else {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
				return
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(key); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		}

		if r.Method == "DELETE" {
			if err := backend.DeleteKey(r.Context(), keyID); err != nil {
				if storage.IsKeyNotFound(err) {
					http.Error(w, "Key not found", http.StatusNotFound)
				} else {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
				return
			}

			w.WriteHeader(http.StatusOK)
			return
		}

		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}).Methods("GET", "DELETE")
}

func runServer(_ *cobra.Command, _ []string) error {
	// Load configuration
	cfg, err := config.LoadServerConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize logging
	if err := logging.Initialize(logging.Config{
		Level:  cfg.Observability.Logging.Level,
		Format: cfg.Observability.Logging.Format,
	}); err != nil {
		return fmt.Errorf("failed to initialize logging: %w", err)
	}

	// Initialize audit logging
	if err := logging.InitializeAudit(logging.AuditConfig{
		Enabled: cfg.Observability.Audit.Enabled,
		Output:  cfg.Observability.Audit.Output,
	}); err != nil {
		return fmt.Errorf("failed to initialize audit logging: %w", err)
	}

	logging.Infof("Knox server %s starting...", version)
	logging.Infof("Configuration: %s", cfgFile)

	// Initialize storage backend
	storageBackend, err := storage.NewBackend(cfg.Storage.ToStorageConfig())
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}
	defer storageBackend.Close()

	logging.Infof("Storage backend: %s", cfg.Storage.Backend)

	// Test storage connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := storageBackend.Ping(ctx); err != nil {
		return fmt.Errorf("storage backend health check failed: %w", err)
	}
	logging.Info("Storage backend health check passed")

	// Load master encryption key
	masterKey, err := crypto.LoadMasterKey()
	if err != nil {
		return fmt.Errorf("failed to load master key: %w (set KNOX_MASTER_KEY env var)", err)
	}
	logging.Info("Master encryption key loaded successfully")

	// Create cryptor (for encrypting keys at rest)
	cryptor, err := crypto.NewAESCryptor(masterKey)
	if err != nil {
		return fmt.Errorf("failed to create cryptor: %w", err)
	}
	logging.Info("AES-256-GCM cryptor initialized")

	// Clear master key from memory
	for i := range masterKey {
		masterKey[i] = 0
	}

	// Create key database using storage backend adapter
	db := storage.NewDBAdapter(storageBackend, cryptor)
	logging.Infof("Storage backend adapter initialized (using %s)", cfg.Storage.Backend)

	// Setup authentication providers
	authProviders := setupAuthProviders(cfg)
	logging.Infof("Configured %d authentication provider(s)", len(authProviders))

	// Create decorators (middleware)
	decorators := []func(http.HandlerFunc) http.HandlerFunc{
		securityHeadersMiddleware,
		loggingMiddleware,
		metricsMiddleware,
		authMiddleware(authProviders),
		rateLimitMiddleware(cfg.Limits.RateLimitPerPrincipal),
	}

	// Create router
	router, err := server.GetRouter(cryptor, db, decorators, nil)
	if err != nil {
		return fmt.Errorf("failed to create router: %w", err)
	}

	// Add metrics endpoint if enabled
	if cfg.Observability.Metrics.Enabled {
		// Wrap metrics handler with basic auth
		metricsHandler := secureMetricsHandler(promhttp.Handler())
		router.HandleFunc(cfg.Observability.Metrics.Endpoint, metricsHandler).Methods("GET")
		logging.Infof("Metrics endpoint: %s (secured with basic auth)", cfg.Observability.Metrics.Endpoint)
	}

	// Add health check endpoints
	router.HandleFunc("/health", healthHandler(storageBackend)).Methods("GET")
	router.HandleFunc("/ready", readinessHandler(storageBackend)).Methods("GET")
	logging.Info("Health check endpoints: /health, /ready")

	// Create HTTP server
	srv := &http.Server{
		Addr:         cfg.BindAddress,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Configure TLS if specified
	if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
		tlsConfig, err := createTLSConfig(&cfg.TLS)
		if err != nil {
			return fmt.Errorf("failed to create TLS config: %w", err)
		}
		srv.TLSConfig = tlsConfig
		logging.Infof("TLS enabled with cert: %s", cfg.TLS.CertFile)
	}

	// Start background tasks
	go updateMetricsPeriodically(storageBackend)

	// Start server in a goroutine
	serverErrors := make(chan error, 1)
	go func() {
		logging.Infof("Knox server listening on %s", cfg.BindAddress)
		if srv.TLSConfig != nil {
			serverErrors <- srv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			serverErrors <- srv.ListenAndServe()
		}
	}()

	// Wait for interrupt signal or server error
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		return fmt.Errorf("server error: %w", err)
	case sig := <-shutdown:
		logging.Infof("Received signal: %v, shutting down gracefully...", sig)

		// Graceful shutdown with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			logging.Errorf("Error during shutdown: %v", err)
			return err
		}

		logging.Info("Server stopped gracefully")
	}

	return nil
}

// setupAuthProviders creates authentication providers based on configuration.
func setupAuthProviders(cfg *config.ServerConfig) []auth.Provider {
	var providers []auth.Provider

	logging.Debugf("Auth config: providers=%+v", cfg.Auth.Providers)
	for _, providerCfg := range cfg.Auth.Providers {
		switch providerCfg.Type {
		case "spiffe":
			// Load CA pool for SPIFFE auth provider
			caPool, err := loadCAPool(providerCfg.CAFile)
			if err != nil {
				logging.Errorf("Failed to load CA pool for SPIFFE provider (CA file: %s): %v", providerCfg.CAFile, err)
				continue
			}
			provider := auth.NewSpiffeAuthProvider(caPool)
			providers = append(providers, provider)
			logging.Debugf("Added SPIFFE auth provider to list")
			logging.Infof("✓ Configured SPIFFE auth provider (trust domain: %s)", providerCfg.TrustDomain)

		case "mtls":
			// Load CA pool to validate CA file exists (still used for TLS config)
			_, err := loadCAPool(providerCfg.CAFile)
			if err != nil {
				logging.Errorf("Failed to load CA pool for mTLS provider (CA file: %s): %v", providerCfg.CAFile, err)
				continue
			}
			provider := pkgauth.NewMTLSProvider()
			providers = append(providers, provider)
			logging.Debugf("Added mTLS auth provider to list")
			logging.Infof("✓ Configured mTLS auth provider (CA: %s)", providerCfg.CAFile)

		case "github":
			// Create GitHub OAuth token auth provider
			provider := auth.NewGitHubProvider(10 * time.Second)
			providers = append(providers, provider)
			logging.Debugf("Added GitHub auth provider to list")
			logging.Info("✓ Configured GitHub OAuth auth provider")

		case "mock":
			// Create mock auth provider for testing
			provider := auth.MockGitHubProvider()
			providers = append(providers, provider)
			logging.Debugf("Added mock auth provider to list")
			logging.Info("✓ Configured mock auth provider for testing")

		default:
			logging.Warnf("Unknown auth provider type: %s", providerCfg.Type)
		}
	}

	logging.Debugf("Total providers configured: %d", len(providers))
	if len(providers) == 0 {
		logging.Error("CRITICAL: No authentication providers configured - server will reject all requests!")
		logging.Error("Configure at least one auth provider in config file")
	}

	return providers
}

// loadCAPool loads a CA certificate pool from a file.
func loadCAPool(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, errors.New("CA file path is empty")
	}

	// Check if file exists and is readable
	if info, err := os.Stat(caFile); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("CA certificate file does not exist: %s", caFile)
		}
		if os.IsPermission(err) {
			return nil, fmt.Errorf("permission denied reading CA certificate file: %s", caFile)
		}
		return nil, fmt.Errorf("cannot access CA certificate file %s: %w", caFile, err)
	} else if info.IsDir() {
		return nil, fmt.Errorf("CA certificate path is a directory, not a file: %s", caFile)
	}

	// Read CA certificate file
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate file %s: %w", caFile, err)
	}

	// Check if file is empty
	if len(caCert) == 0 {
		return nil, fmt.Errorf("CA certificate file is empty: %s", caFile)
	}

	// Create certificate pool
	caCertPool := x509.NewCertPool()

	// First try to parse as PEM format
	if caCertPool.AppendCertsFromPEM(caCert) {
		return caCertPool, nil
	}

	// If PEM parsing failed, try to parse as a single DER certificate
	derCert, err := x509.ParseCertificate(caCert)
	if err != nil {
		// Neither PEM nor single DER worked - provide detailed analysis
		formatHint := analyzeCertificateFormat(caCert)
		return nil, fmt.Errorf("failed to parse CA certificate file %s: invalid certificate format%s", caFile, formatHint)
	}

	// Successfully parsed as single DER certificate
	caCertPool.AddCert(derCert)
	return caCertPool, nil
}

// analyzeCertificateFormat analyzes certificate bytes and returns a helpful error hint.
func analyzeCertificateFormat(data []byte) string {
	if len(data) == 0 {
		return " (file is empty)"
	}

	// Check for PEM format markers
	dataStr := string(data)
	if strings.Contains(dataStr, "-----BEGIN") {
		if !strings.Contains(dataStr, "-----END") {
			return " (PEM format detected but missing END marker)"
		}
		// Check for common PEM types
		if strings.Contains(dataStr, "CERTIFICATE") {
			return " (PEM CERTIFICATE detected but parsing failed - may be corrupt or unsupported format)"
		}
		if strings.Contains(dataStr, "RSA PRIVATE KEY") {
			return " (file appears to be a private key, not a CA certificate)"
		}
		return " (PEM format detected but unknown type)"
	}

	// Check if it looks like binary/DER
	isLikelyBinary := false
	if len(data) > 0 {
		// DER certificates typically start with 0x30 (SEQUENCE)
		if data[0] == 0x30 && len(data) > 4 {
			isLikelyBinary = true
		}
		// Also check for common ASN.1 tags
		if len(data) > 1 && (data[0] == 0x30 || data[0] == 0x31 || data[0] == 0x32) {
			isLikelyBinary = true
		}
	}

	if isLikelyBinary {
		return " (DER/binary format detected but parsing failed - may be corrupt or unsupported)"
	}

	// Check if it looks like plain text but not PEM
	if len(data) < 1024 && strings.Contains(dataStr, "\n") {
		// Might be base64 without PEM headers
		if _, err := base64.StdEncoding.DecodeString(strings.TrimSpace(dataStr)); err == nil {
			return " (file appears to be base64-encoded without PEM headers)"
		}
		return " (text format detected but not valid PEM)"
	}

	b1 := byte(0)
	b2 := byte(0)
	b3 := byte(0)
	if len(data) > 1 {
		b1 = data[1]
	}
	if len(data) > 2 {
		b2 = data[2]
	}
	if len(data) > 3 {
		b3 = data[3]
	}
	return fmt.Sprintf(" (file size: %d bytes, first bytes: %02x %02x %02x %02x)",
		len(data), data[0], b1, b2, b3)
}

// createTLSConfig creates TLS configuration for the server.
func createTLSConfig(cfg *config.TLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			// TLS 1.3 cipher suites
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			// TLS 1.2 cipher suites (fallback)
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		PreferServerCipherSuites: true,
	}

	// Set minimum TLS version if specified
	if cfg.MinVersion == "TLS1.3" {
		tlsConfig.MinVersion = tls.VersionTLS13
	}

	// Load client CA if specified (for mTLS)
	if cfg.ClientCA != "" {
		caCert, err := os.ReadFile(cfg.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("failed to read client CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to parse client CA certificate")
		}

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

		logging.Infof("Client CA configured: %s (mTLS enabled)", cfg.ClientCA)
	}

	return tlsConfig, nil
}

// Middleware functions

// securityHeadersMiddleware adds security headers to HTTP responses.
func securityHeadersMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Security headers to prevent common web vulnerabilities
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		next(w, r)
	}
}

func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create response writer wrapper to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next(wrapped, r)

		duration := time.Since(start)
		logging.WithFields(map[string]any{
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      wrapped.statusCode,
			"duration_ms": duration.Milliseconds(),
			"remote_addr": r.RemoteAddr,
		}).Info("HTTP request")
	}
}

func metricsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next(wrapped, r)

		duration := time.Since(start).Seconds()
		metrics.RecordRequest(r.Method, r.URL.Path, strconv.Itoa(wrapped.statusCode), duration)
	}
}

// authMiddleware enforces authentication using the configured providers.
func authMiddleware(providers []auth.Provider) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for health check and metrics endpoints
			if r.URL.Path == "/health" || r.URL.Path == "/ready" || r.URL.Path == "/metrics" {
				next(w, r)
				return
			}

			// Extract authentication token from request
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				logging.Warn("Request missing Authorization header")
				logging.AuditAuthAttempt("", "", "", "denied_no_token", map[string]any{
					"path":        r.URL.Path,
					"remote_addr": r.RemoteAddr,
				})
				server.WriteErr(&server.HTTPError{Subcode: types.UnauthenticatedCode, Message: "User or machine is not authenticated"})(w, r)
				return
			}

			// Try each auth provider
			var principal types.Principal
			var err error
			var providerName string

			for _, provider := range providers {
				principal, err = provider.Authenticate(authHeader, r)
				if err == nil {
					providerName = provider.Name()
					break
				}
			}

			if principal == nil {
				logging.Warnf("Authentication failed: principal is nil")
				logging.AuditAuthAttempt("", "", providerName, "denied_invalid_token", map[string]any{
					"path":        r.URL.Path,
					"remote_addr": r.RemoteAddr,
					"error":       "principal is nil",
				})
				server.WriteErr(&server.HTTPError{Subcode: types.UnauthenticatedCode, Message: "User or machine is not authenticated"})(w, r)
				return
			}
			if err != nil {
				logging.Warnf("Authentication failed: %v", err)
				logging.AuditAuthAttempt("", "", providerName, "denied_invalid_token", map[string]any{
					"path":        r.URL.Path,
					"remote_addr": r.RemoteAddr,
					"error":       err.Error(),
				})
				server.WriteErr(&server.HTTPError{Subcode: types.UnauthenticatedCode, Message: "User or machine is not authenticated"})(w, r)
				return
			}

			// Log successful authentication
			logging.AuditAuthAttempt(
				principal.GetID(),
				principal.Type(),
				providerName,
				"success",
				map[string]any{
					"path":        r.URL.Path,
					"remote_addr": r.RemoteAddr,
				},
			)

			// Store principal in request using Knox's decorator system
			server.SetPrincipal(r, principal)
			next(w, r)
		}
	}
}

// rateLimiter holds rate limiters per client IP/principal.
type rateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	limit    rate.Limit
	burst    int
}

func newRateLimiter(requestsPerSecond int) *rateLimiter {
	return &rateLimiter{
		limiters: make(map[string]*rate.Limiter),
		limit:    rate.Limit(requestsPerSecond),
		burst:    requestsPerSecond * 2, // Allow bursts up to 2x the rate
	}
}

func (rl *rateLimiter) getLimiter(key string) *rate.Limiter {
	rl.mu.RLock()
	limiter, exists := rl.limiters[key]
	rl.mu.RUnlock()

	if exists {
		return limiter
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Check again in case another goroutine created it
	if limiter, exists := rl.limiters[key]; exists {
		return limiter
	}

	limiter = rate.NewLimiter(rl.limit, rl.burst)
	rl.limiters[key] = limiter
	return limiter
}

func rateLimitMiddleware(requestsPerSecond int) func(http.HandlerFunc) http.HandlerFunc {
	if requestsPerSecond <= 0 {
		requestsPerSecond = 100 // Default: 100 requests per second per principal
	}

	limiter := newRateLimiter(requestsPerSecond)

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Use principal ID as rate limit key if available, otherwise use IP
			key := r.RemoteAddr
			if principal := server.GetPrincipal(r); principal != nil {
				key = principal.GetID()
			}

			// Check rate limit
			if !limiter.getLimiter(key).Allow() {
				logging.Warnf("Rate limit exceeded for %s", key)
				metrics.RecordRequest(r.Method, r.URL.Path, "429", 0)
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next(w, r)
		}
	}
}

// secureMetricsHandler wraps a metrics handler with basic authentication.
func secureMetricsHandler(handler http.Handler) http.HandlerFunc {
	// Get credentials from environment
	username := os.Getenv("KNOX_METRICS_USERNAME")
	password := os.Getenv("KNOX_METRICS_PASSWORD")

	// If no credentials configured, allow access (backward compatibility)
	// but log a warning
	if username == "" || password == "" {
		logging.Warn("Metrics endpoint not secured - set KNOX_METRICS_USERNAME and KNOX_METRICS_PASSWORD")
		return handler.ServeHTTP
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract basic auth credentials
		user, pass, ok := r.BasicAuth()

		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Knox Metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Constant-time comparison to prevent timing attacks
		if !secureCompare(user, username) || !secureCompare(pass, password) {
			logging.Warnf("Failed metrics authentication attempt from %s", r.RemoteAddr)
			w.Header().Set("WWW-Authenticate", `Basic realm="Knox Metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Authenticated successfully
		handler.ServeHTTP(w, r)
	})
}

// secureCompare performs constant-time string comparison to prevent timing attacks.
func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	result := 0
	for i := range len(a) {
		result |= int(a[i]) ^ int(b[i])
	}

	return result == 0
}

// Health check handlers

func healthHandler(backend storage.Backend) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		if err := backend.Ping(ctx); err != nil {
			// Log the actual error for debugging
			logging.Errorf("Health check failed: %v", err)

			// Return generic error to client (don't leak internal details)
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, "unhealthy")
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "healthy")
	}
}

func readinessHandler(backend storage.Backend) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		if err := backend.Ping(ctx); err != nil {
			// Log the actual error for debugging
			logging.Errorf("Readiness check failed: %v", err)

			// Return generic error to client (don't leak internal details)
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, "not ready")
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ready")
	}
}

// updateMetricsPeriodically updates metrics from storage backend.
func updateMetricsPeriodically(backend storage.Backend) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if statsProvider, ok := backend.(storage.StatsProvider); ok {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			stats, err := statsProvider.Stats(ctx)
			cancel()

			if err == nil {
				metrics.SetKeysTotal(stats.TotalKeys)
			}
		}
	}
}

// responseWriter wraps http.ResponseWriter to capture status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
