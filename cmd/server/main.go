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

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/mux"
	pkgauth "github.com/hazayan/knox/pkg/auth"
	"github.com/hazayan/knox/pkg/config"
	"github.com/hazayan/knox/pkg/crypto"
	"github.com/hazayan/knox/pkg/observability/logging"
	"github.com/hazayan/knox/pkg/observability/metrics"
	"github.com/hazayan/knox/pkg/storage"
	_ "github.com/hazayan/knox/pkg/storage/etcd"       // Register etcd backend
	_ "github.com/hazayan/knox/pkg/storage/filesystem" // Register filesystem backend
	_ "github.com/hazayan/knox/pkg/storage/memory"     // Register memory backend
	_ "github.com/hazayan/knox/pkg/storage/orm"        // Register SQLite backend
	"github.com/hazayan/knox/pkg/types"
	"github.com/hazayan/knox/server"
	"github.com/hazayan/knox/server/auth"
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
	masterKey, err := crypto.GenerateMasterKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate test master key: %w", err)
	}
	defer func() {
		for i := range masterKey {
			masterKey[i] = 0
		}
	}()

	return createTestServerWithMasterKey(cfg, masterKey)
}

func createTestServerWithMasterKey(cfg *config.ServerConfig, masterKey []byte) (*TestServer, error) {
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
	case "sqlite":
		storageCfg.SQLitePath = cfg.Storage.SQLitePath
	case "etcd":
		storageCfg.EtcdEndpoints = cfg.Storage.EtcdEndpoints
		storageCfg.EtcdPrefix = cfg.Storage.EtcdPrefix
	}

	backend, err := storage.NewBackend(storageCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage backend: %w", err)
	}
	logging.Infof("Created storage backend: %s", cfg.Storage.Backend)

	cryptor, err := crypto.NewAESCryptor(masterKey)
	if err != nil {
		_ = backend.Close()
		return nil, fmt.Errorf("failed to create test cryptor: %w", err)
	}

	db := storage.NewDBAdapter(backend, cryptor)
	authProviders := setupAuthProviders(cfg)
	decorators := []func(http.HandlerFunc) http.HandlerFunc{
		securityHeadersMiddleware,
		loggingMiddleware,
		metricsMiddleware,
		authMiddleware(authProviders),
		rateLimitMiddleware(cfg.Limits.RateLimitPerPrincipal),
	}

	router, err := server.GetRouter(cryptor, db, decorators, nil)
	if err != nil {
		_ = backend.Close()
		return nil, fmt.Errorf("failed to create test router: %w", err)
	}
	if err := registerFido2AuthRoutes(router, cfg, decorators); err != nil {
		_ = backend.Close()
		return nil, err
	}
	if cfg.Observability.Metrics.Enabled {
		router.HandleFunc(cfg.Observability.Metrics.Endpoint, secureMetricsHandler(promhttp.Handler())).Methods("GET")
	}
	router.HandleFunc("/health", publicOperationalMiddleware(healthHandler())).Methods("GET")
	router.HandleFunc("/ready", publicOperationalMiddleware(readinessHandler(backend))).Methods("GET")

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
	rootCmd.AddCommand(newInitCommand())
	rootCmd.AddCommand(newKeyCommand())
	rootCmd.AddCommand(newAuthCommand())

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "/etc/knox/server.yaml", "Path to configuration file")
	rootCmd.Flags().String("version", "", "Print version and exit")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newInitCommand() *cobra.Command {
	var principalType string
	var subject string
	var groups []string

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize Knox with the first global administrator",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(principalType) == "" || strings.TrimSpace(subject) == "" {
				return errors.New("principal type and subject are required")
			}
			cfg, err := config.LoadServerConfig(cfgFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			principal, err := rawPrincipal(principalType, subject)
			if err != nil {
				return err
			}
			var token string
			var expires time.Time
			if cfg.Auth.Fido2.Enabled {
				issuer, err := newFido2TokenIssuerFromConfig(cfg.Auth.Fido2)
				if err != nil {
					return err
				}
				token, expires, err = mintTokenForPrincipal(issuer, principalType, subject, groups)
				if err != nil {
					return err
				}
			}
			state, err := server.InitializeState(cfg.Initialization.StateFile, server.InitializationOptions{
				AdminPrincipal: principal,
				AdminGroups:    groups,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "initialized Knox at %s\n", state.InitializedAt.Format(time.RFC3339))
			fmt.Fprintf(cmd.ErrOrStderr(), "admin principal: %s:%s\n", principal.Type, principal.ID)
			if len(state.AdminGroups) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "admin groups: %s\n", strings.Join(state.AdminGroups, ","))
			}
			if cfg.Auth.Fido2.Enabled {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\n", token); err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "bootstrap token expires at %s\n", expires.Format(time.RFC3339))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&principalType, "principal-type", "user", "Knox principal type")
	cmd.Flags().StringVar(&subject, "subject", "", "Knox principal subject")
	cmd.Flags().StringSliceVar(&groups, "group", nil, "Group to attach to a user principal and grant global admin")
	return cmd
}

func newAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage local Knox server authentication bootstrap",
	}
	cmd.AddCommand(newAuthMintTokenCommand())
	return cmd
}

func newAuthMintTokenCommand() *cobra.Command {
	var principalType string
	var subject string
	var groups []string
	var breakGlass bool

	cmd := &cobra.Command{
		Use:   "mint-token",
		Short: "Mint an explicit break-glass FIDO2 Knox API token",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(principalType) == "" || strings.TrimSpace(subject) == "" {
				return errors.New("principal type and subject are required")
			}
			if !breakGlass {
				return errors.New("local token minting is a break-glass operation; pass --break-glass after confirming the target principal is an initialized Knox global admin")
			}
			cfg, err := config.LoadServerConfig(cfgFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			initState, err := server.LoadInitializationState(cfg.Initialization.StateFile)
			if err != nil {
				return err
			}
			principal, err := principalForToken(principalType, subject, groups)
			if err != nil {
				return err
			}
			if !initState.IsAdmin(principal) {
				return errors.New("break-glass token minting is restricted to initialized Knox global administrators")
			}
			issuer, err := newFido2TokenIssuerFromConfig(cfg.Auth.Fido2)
			if err != nil {
				return err
			}
			var token string
			var expires time.Time
			token, expires, err = mintTokenForPrincipal(issuer, principalType, subject, groups)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\n", token); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "token expires at %s\n", expires.Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&principalType, "principal-type", "user", "Knox principal type")
	cmd.Flags().StringVar(&subject, "subject", "", "Knox principal subject")
	cmd.Flags().StringSliceVar(&groups, "group", nil, "Group to attach to a user principal")
	cmd.Flags().BoolVar(&breakGlass, "break-glass", false, "Allow local emergency token minting for an initialized global administrator")
	return cmd
}

func mintTokenForPrincipal(issuer *auth.Fido2TokenIssuer, principalType, subject string, groups []string) (string, time.Time, error) {
	switch principalType {
	case "user":
		return issuer.MintUserToken(subject, compactStrings(groups))
	case "machine":
		return issuer.MintMachineToken(subject)
	default:
		return "", time.Time{}, errors.New("principal type must be user or machine")
	}
}

func rawPrincipal(principalType, subject string) (types.RawPrincipal, error) {
	switch principalType {
	case "user", "machine", "service":
		return types.RawPrincipal{Type: principalType, ID: subject}, nil
	default:
		return types.RawPrincipal{}, errors.New("principal type must be user, machine, or service")
	}
}

func principalForToken(principalType, subject string, groups []string) (types.Principal, error) {
	switch principalType {
	case "user":
		return auth.NewUser(subject, compactStrings(groups)), nil
	case "machine":
		return auth.NewMachine(subject), nil
	default:
		return nil, errors.New("principal type must be user or machine")
	}
}

func compactStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
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

	initState, err := server.LoadInitializationState(cfg.Initialization.StateFile)
	if err != nil {
		if errors.Is(err, server.ErrNotInitialized) {
			return fmt.Errorf("%w: run 'knox-server --config %s init --principal-type user --subject <admin>' before starting the server", err, cfgFile)
		}
		return err
	}
	logging.Infof("Initialization state loaded: %s", cfg.Initialization.StateFile)

	policyStore, err := server.NewACLPolicyStoreFromFile(cfg.AccessControl.PolicyFile)
	if err != nil {
		return err
	}
	server.SetACLPolicyResolver(policyStore.ACLForKey)
	logging.Infof("ACL policy store loaded: %s", cfg.AccessControl.PolicyFile)

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
	masterKey, err := crypto.LoadMasterKeyWithConfig(crypto.MasterKeyConfig{
		Backend:          cfg.MasterKey.Backend,
		EncryptedKeyFile: cfg.MasterKey.EncryptedKeyFile,
		MetadataFile:     cfg.MasterKey.MetadataFile,
		Device:           cfg.MasterKey.Device,
		PinFile:          cfg.MasterKey.PinFile,
	})
	if err != nil {
		return fmt.Errorf("failed to load master key with backend %q: %w", cfg.MasterKey.Backend, err)
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
	if err := registerFido2AuthRoutes(router, cfg, decorators); err != nil {
		return err
	}
	if err := registerFido2AdminRoutes(router, cfg, decorators, initState); err != nil {
		return err
	}
	registerPolicyRoutes(router, policyStore, decorators, initState)

	// Add metrics endpoint if enabled
	if cfg.Observability.Metrics.Enabled {
		// Wrap metrics handler with basic auth
		metricsHandler := secureMetricsHandler(promhttp.Handler())
		router.HandleFunc(cfg.Observability.Metrics.Endpoint, metricsHandler).Methods("GET")
		logging.Infof("Metrics endpoint: %s (secured with basic auth)", cfg.Observability.Metrics.Endpoint)
	}

	// Add health check endpoints
	router.HandleFunc("/health", publicOperationalMiddleware(healthHandler())).Methods("GET")
	router.HandleFunc("/ready", publicOperationalMiddleware(readinessHandler(storageBackend))).Methods("GET")
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

		case "fido2":
			provider, err := newFido2TokenProvider(cfg.Auth.Fido2)
			if err != nil {
				logging.Errorf("Failed to configure FIDO2 auth provider: %v", err)
				continue
			}
			providers = append(providers, provider)
			logging.Debugf("Added FIDO2 auth provider to list")
			logging.Info("✓ Configured FIDO2 auth provider")

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

func newFido2TokenProvider(cfg config.Fido2AuthConfig) (auth.Provider, error) {
	issuer, err := newFido2TokenIssuerFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	return auth.NewFido2TokenProvider(issuer), nil
}

func newFido2TokenIssuerFromConfig(cfg config.Fido2AuthConfig) (*auth.Fido2TokenIssuer, error) {
	if !cfg.Enabled {
		return nil, errors.New("auth.fido2.enabled must be true")
	}
	if cfg.TokenSigningKeyFile == "" {
		return nil, errors.New("auth.fido2.token_signing_key_file is required")
	}
	key, err := os.ReadFile(cfg.TokenSigningKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read FIDO2 token signing key: %w", err)
	}
	ttl, err := time.ParseDuration(cfg.TokenTTL)
	if err != nil {
		return nil, fmt.Errorf("invalid auth.fido2.token_ttl: %w", err)
	}
	return auth.NewFido2TokenIssuer(cfg.TokenIssuer, []byte(strings.TrimSpace(string(key))), ttl)
}

func registerFido2AuthRoutes(router *mux.Router, cfg *config.ServerConfig, decorators []func(http.HandlerFunc) http.HandlerFunc) error {
	if !cfg.Auth.Fido2.Enabled {
		return nil
	}
	if cfg.Auth.Fido2.CredentialsFile == "" {
		return errors.New("auth.fido2.credentials_file is required")
	}
	issuer, err := newFido2TokenIssuerFromConfig(cfg.Auth.Fido2)
	if err != nil {
		return err
	}
	store, err := server.NewWebAuthnPrincipalStoreFromFile(cfg.Auth.Fido2.CredentialsFile)
	if err != nil {
		return err
	}
	service, err := server.NewWebAuthnCeremonyService(&webauthn.Config{
		RPID:          cfg.Auth.Fido2.RPID,
		RPDisplayName: cfg.Auth.Fido2.RPName,
		RPOrigins:     cfg.Auth.Fido2.Origins,
	}, store, issuer)
	if err != nil {
		return fmt.Errorf("failed to configure FIDO2 WebAuthn service: %w", err)
	}
	server.RegisterFido2AuthRoutes(router, service)
	return nil
}

func registerFido2AdminRoutes(router *mux.Router, cfg *config.ServerConfig, decorators []func(http.HandlerFunc) http.HandlerFunc, initState *server.InitializationState) error {
	if !cfg.Auth.Fido2.Enabled {
		return nil
	}
	if cfg.Auth.Fido2.CredentialsFile == "" {
		return errors.New("auth.fido2.credentials_file is required")
	}
	issuer, err := newFido2TokenIssuerFromConfig(cfg.Auth.Fido2)
	if err != nil {
		return err
	}
	store, err := server.NewWebAuthnPrincipalStoreFromFile(cfg.Auth.Fido2.CredentialsFile)
	if err != nil {
		return err
	}
	service, err := server.NewWebAuthnCeremonyService(&webauthn.Config{
		RPID:          cfg.Auth.Fido2.RPID,
		RPDisplayName: cfg.Auth.Fido2.RPName,
		RPOrigins:     cfg.Auth.Fido2.Origins,
	}, store, issuer)
	if err != nil {
		return fmt.Errorf("failed to configure FIDO2 WebAuthn service: %w", err)
	}
	adminDecorators := append([]func(http.HandlerFunc) http.HandlerFunc{}, decorators...)
	adminDecorators = append(adminDecorators, globalAdminMiddleware(initState))
	server.RegisterFido2AdminRoutes(router, service, adminDecorators)
	return nil
}

func registerPolicyRoutes(router *mux.Router, store *server.ACLPolicyStore, decorators []func(http.HandlerFunc) http.HandlerFunc, initState *server.InitializationState) {
	decorator := func(f http.HandlerFunc) http.HandlerFunc { return f }
	adminDecorators := append([]func(http.HandlerFunc) http.HandlerFunc{}, decorators...)
	adminDecorators = append(adminDecorators, globalAdminMiddleware(initState))
	for i := range adminDecorators {
		j := len(adminDecorators) - i - 1
		decorator = combineDecorators(adminDecorators[j], decorator)
	}
	router.HandleFunc("/v0/policies/", decorator(listPoliciesHandler(store))).Methods(http.MethodGet)
	router.HandleFunc("/v0/policies/{name}", decorator(getPolicyHandler(store))).Methods(http.MethodGet)
	router.HandleFunc("/v0/policies/{name}", decorator(putPolicyHandler(store))).Methods(http.MethodPut)
	router.HandleFunc("/v0/policies/{name}", decorator(deletePolicyHandler(store))).Methods(http.MethodDelete)
}

func listPoliciesHandler(store *server.ACLPolicyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		server.WriteData(w, store.List())
	}
}

func getPolicyHandler(store *server.ACLPolicyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		policy, err := store.Get(mux.Vars(r)["name"])
		if err != nil {
			writePolicyError(w, r, err)
			return
		}
		server.WriteData(w, policy)
	}
}

func putPolicyHandler(store *server.ACLPolicyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var policy types.ACLPolicy
		if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
			server.WriteErr(&server.HTTPError{Subcode: types.BadRequestDataCode, Message: err.Error()})(w, r)
			return
		}
		name := mux.Vars(r)["name"]
		if policy.Name == "" {
			policy.Name = name
		}
		if policy.Name != name {
			server.WriteErr(&server.HTTPError{Subcode: types.BadRequestDataCode, Message: "policy name must match URL"})(w, r)
			return
		}
		if err := store.Put(policy); err != nil {
			writePolicyError(w, r, err)
			return
		}
		server.WriteData(w, policy)
	}
}

func deletePolicyHandler(store *server.ACLPolicyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := store.Delete(mux.Vars(r)["name"]); err != nil {
			writePolicyError(w, r, err)
			return
		}
		server.WriteData(w, nil)
	}
}

func writePolicyError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, server.ErrPolicyNotFound) {
		server.WriteErr(&server.HTTPError{Subcode: types.NotFoundCode, Message: err.Error()})(w, r)
		return
	}
	server.WriteErr(&server.HTTPError{Subcode: types.BadRequestDataCode, Message: err.Error()})(w, r)
}

func combineDecorators(f, g func(http.HandlerFunc) http.HandlerFunc) func(http.HandlerFunc) http.HandlerFunc {
	return func(h http.HandlerFunc) http.HandlerFunc {
		return f(g(h))
	}
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

func publicOperationalMiddleware(handler http.HandlerFunc) http.HandlerFunc {
	return securityHeadersMiddleware(loggingMiddleware(metricsMiddleware(handler)))
}

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

		auditRouteOperation(
			server.GetRouteID(r),
			server.GetPrincipal(r),
			server.GetParams(r),
			server.GetAPIError(r),
			wrapped.statusCode,
			r.URL.Path,
		)
	}
}

func auditRouteOperation(routeID string, principal types.Principal, params map[string]string, apiErr *server.HTTPError, statusCode int, path string) {
	keyID, ok := auditKeyID(routeID, params)
	if !ok {
		return
	}

	principalID := ""
	principalType := ""
	if principal != nil {
		principalID = principal.GetID()
		principalType = principal.Type()
	}

	metadata := map[string]any{
		"route_id":    routeID,
		"path":        path,
		"status_code": statusCode,
		"result":      auditResult(apiErr),
	}
	if versionID := params["versionID"]; versionID != "" {
		metadata["version_id"] = versionID
	}

	switch routeID {
	case "getkey":
		logging.AuditKeyAccess(keyID, principalID, principalType, "read", auditResult(apiErr), metadata)
	case "getaccess":
		logging.AuditKeyAccess(keyID, principalID, principalType, "get_acl", auditResult(apiErr), metadata)
	case "postkeys":
		logging.AuditKeyCreate(keyID, principalID, principalType, metadata)
	case "deletekey":
		logging.AuditKeyDelete(keyID, principalID, principalType, metadata)
	case "putaccess":
		logging.AuditACLChange(keyID, principalID, principalType, "update", metadata)
	case "postversion":
		logging.AuditKeyAccess(keyID, principalID, principalType, "add_version", auditResult(apiErr), metadata)
	case "putversion":
		logging.AuditKeyAccess(keyID, principalID, principalType, "update_version", auditResult(apiErr), metadata)
	}
}

func auditKeyID(routeID string, params map[string]string) (string, bool) {
	if params == nil {
		return "", false
	}
	switch routeID {
	case "postkeys":
		keyID := params["id"]
		return keyID, keyID != ""
	case "getkey", "getaccess", "deletekey", "putaccess", "postversion", "putversion":
		keyID := params["keyID"]
		return keyID, keyID != ""
	default:
		return "", false
	}
}

func auditResult(apiErr *server.HTTPError) string {
	if apiErr == nil {
		return "success"
	}
	switch apiErr.Subcode {
	case types.UnauthenticatedCode:
		return "unauthenticated"
	case types.UnauthorizedCode:
		return "denied"
	default:
		return "error"
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
				payload := authHeader
				if len(authHeader) > 2 && authHeader[0] == provider.Version() && authHeader[1] == provider.Type() {
					payload = authHeader[2:]
				}
				principal, err = provider.Authenticate(payload, r)
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

func globalAdminMiddleware(initState *server.InitializationState) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if initState == nil {
				server.WriteErr(&server.HTTPError{Subcode: types.UnauthorizedCode, Message: "Knox is not initialized"})(w, r)
				return
			}
			principal := server.GetPrincipal(r)
			if !initState.IsAdmin(principal) {
				principalID := ""
				if principal != nil {
					principalID = principal.GetID()
				}
				logging.AuditAuthAttempt(principalID, "admin", "init-state", "denied_not_global_admin", map[string]any{
					"path":        r.URL.Path,
					"remote_addr": r.RemoteAddr,
				})
				server.WriteErr(&server.HTTPError{Subcode: types.UnauthorizedCode, Message: "Principal is not a Knox global administrator"})(w, r)
				return
			}
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

func healthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeOperationalStatus(w, http.StatusOK, "healthy")
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
			writeOperationalStatus(w, http.StatusServiceUnavailable, "not ready")
			return
		}

		writeOperationalStatus(w, http.StatusOK, "ready")
	}
}

func writeOperationalStatus(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprint(w, body)
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
