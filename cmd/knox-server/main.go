// Package main provides the production Knox server.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"golang.org/x/time/rate"

	"github.com/pinterest/knox"
	knoxauth "github.com/pinterest/knox/pkg/auth"
	"github.com/pinterest/knox/pkg/config"
	"github.com/pinterest/knox/pkg/crypto"
	"github.com/pinterest/knox/pkg/observability/logging"
	"github.com/pinterest/knox/pkg/observability/metrics"
	"github.com/pinterest/knox/pkg/storage"
	_ "github.com/pinterest/knox/pkg/storage/filesystem" // Register filesystem backend
	_ "github.com/pinterest/knox/pkg/storage/memory"     // Register memory backend
	_ "github.com/pinterest/knox/pkg/storage/postgres"   // Register postgres backend
	"github.com/pinterest/knox/server"
	"github.com/pinterest/knox/server/auth"
)

var (
	cfgFile string
	version = "2.0.0-dev"
)

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

func runServer(cmd *cobra.Command, args []string) error {
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

	// Set up authentication providers
	authProviders := setupAuthProviders(cfg.Auth)
	logging.Infof("Configured %d authentication provider(s)", len(authProviders))

	// Create decorators (middleware)
	decorators := []func(http.HandlerFunc) http.HandlerFunc{
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
		tlsConfig, err := createTLSConfig(cfg.TLS)
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
func setupAuthProviders(cfg config.AuthConfig) []auth.Provider {
	var providers []auth.Provider

	for _, providerCfg := range cfg.Providers {
		switch providerCfg.Type {
		case "spiffe":
			// Create SPIFFE auth provider
			provider := knoxauth.NewSPIFFEProvider(providerCfg.TrustDomain)
			providers = append(providers, provider)
			logging.Infof("✓ Configured SPIFFE auth provider (trust domain: %s)", providerCfg.TrustDomain)

		case "mtls":
			// Create mTLS auth provider
			provider := knoxauth.NewMTLSProvider()
			providers = append(providers, provider)
			logging.Infof("✓ Configured mTLS auth provider (CA: %s)", providerCfg.CAFile)

		default:
			logging.Warnf("Unknown auth provider type: %s", providerCfg.Type)
		}
	}

	if len(providers) == 0 {
		logging.Error("CRITICAL: No authentication providers configured - server will reject all requests!")
		logging.Error("Configure at least one auth provider in config file")
	}

	return providers
}

// createTLSConfig creates a TLS configuration from config.
func createTLSConfig(cfg config.TLSConfig) (*tls.Config, error) {
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
			return nil, fmt.Errorf("failed to parse client CA certificate")
		}

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

		logging.Infof("Client CA configured: %s (mTLS enabled)", cfg.ClientCA)
	}

	return tlsConfig, nil
}

// Middleware functions

func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create response writer wrapper to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next(wrapped, r)

		duration := time.Since(start)
		logging.WithFields(map[string]interface{}{
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
		metrics.RecordRequest(r.Method, r.URL.Path, fmt.Sprintf("%d", wrapped.statusCode), duration)
	}
}

// authMiddleware enforces authentication using the configured providers.
func authMiddleware(providers []auth.Provider) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for health check endpoints
			if r.URL.Path == "/health" || r.URL.Path == "/ready" {
				next(w, r)
				return
			}

			// Extract authentication token from request
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				logging.Warn("Request missing Authorization header")
				logging.AuditAuthAttempt("", "", "", "denied_no_token", map[string]interface{}{
					"path":        r.URL.Path,
					"remote_addr": r.RemoteAddr,
				})
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			// Try each auth provider
			var principal knox.Principal
			var err error
			var providerName string

			for _, provider := range providers {
				principal, err = provider.Authenticate(authHeader, r)
				if err == nil {
					providerName = provider.Name()
					break
				}
			}

			if principal == nil || err != nil {
				logging.Warnf("Authentication failed: %v", err)
				logging.AuditAuthAttempt("", "", providerName, "denied_invalid_token", map[string]interface{}{
					"path":        r.URL.Path,
					"remote_addr": r.RemoteAddr,
					"error":       err.Error(),
				})
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			// Log successful authentication
			logging.AuditAuthAttempt(
				principal.GetID(),
				principal.Type(),
				providerName,
				"success",
				map[string]interface{}{
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

// rateLimiter holds rate limiters per client IP/principal
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

	return func(w http.ResponseWriter, r *http.Request) {
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
	}
}

// secureCompare performs constant-time string comparison to prevent timing attacks.
func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	result := 0
	for i := 0; i < len(a); i++ {
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
