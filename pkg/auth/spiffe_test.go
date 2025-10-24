// Package auth provides tests for the SPIFFE authentication provider.
package auth

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"testing"

	knoxauth "github.com/hazayan/knox/server/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSPIFFEProvider tests the SPIFFE authentication provider.
func TestSPIFFEProvider(t *testing.T) {
	t.Run("NewSPIFFEProvider", func(t *testing.T) {
		provider := NewSPIFFEProvider("example.com")
		require.NotNil(t, provider)

		assert.Equal(t, "spiffe", provider.Name())
		assert.Equal(t, byte(0x01), provider.Version())
		assert.Equal(t, byte(0x02), provider.Type())

		// Verify interface compliance
		var _ knoxauth.Provider = (*SPIFFEProvider)(nil)
	})

	t.Run("Authenticate_Success", func(t *testing.T) {
		provider := NewSPIFFEProvider("example.com")

		// Create a mock request with TLS and SPIFFE certificate
		req := &http.Request{
			TLS: &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{
					{
						URIs: []*url.URL{
							mustParseURL("spiffe://example.com/ns/production/sa/web-server"),
						},
					},
				},
			},
		}

		principal, err := provider.Authenticate("", req)
		assert.NoError(t, err)
		assert.NotNil(t, principal)
		assert.Equal(t, "ns/production/sa/web-server", principal.GetID())
	})

	t.Run("Authenticate_NoTLS", func(t *testing.T) {
		provider := NewSPIFFEProvider("example.com")

		// Create request without TLS
		req := &http.Request{}

		principal, err := provider.Authenticate("", req)
		assert.Error(t, err)
		assert.Nil(t, principal)
		assert.Contains(t, err.Error(), "TLS not enabled")
	})

	t.Run("Authenticate_NoCertificates", func(t *testing.T) {
		provider := NewSPIFFEProvider("example.com")

		// Create request with TLS but no certificates
		req := &http.Request{
			TLS: &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{},
			},
		}

		principal, err := provider.Authenticate("", req)
		assert.Error(t, err)
		assert.Nil(t, principal)
		assert.Contains(t, err.Error(), "no client certificates provided")
	})

	t.Run("Authenticate_NoSPIFFEID", func(t *testing.T) {
		provider := NewSPIFFEProvider("example.com")

		// Create request with TLS but no SPIFFE URI
		req := &http.Request{
			TLS: &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{
					{
						URIs: []*url.URL{
							mustParseURL("https://example.com"),
						},
					},
				},
			},
		}

		principal, err := provider.Authenticate("", req)
		assert.Error(t, err)
		assert.Nil(t, principal)
		assert.Contains(t, err.Error(), "no SPIFFE ID found")
	})

	t.Run("Authenticate_TrustDomainValidation", func(t *testing.T) {
		provider := NewSPIFFEProvider("example.com")

		// Create request with SPIFFE ID from different trust domain
		req := &http.Request{
			TLS: &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{
					{
						URIs: []*url.URL{
							mustParseURL("spiffe://other.com/ns/production/sa/web-server"),
						},
					},
				},
			},
		}

		principal, err := provider.Authenticate("", req)
		assert.Error(t, err)
		assert.Nil(t, principal)
		assert.Contains(t, err.Error(), "trust domain mismatch")
	})

	t.Run("Authenticate_EmptyTrustDomain", func(t *testing.T) {
		// Provider with empty trust domain (accepts any)
		provider := NewSPIFFEProvider("")

		req := &http.Request{
			TLS: &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{
					{
						URIs: []*url.URL{
							mustParseURL("spiffe://any-domain.com/workload/service"),
						},
					},
				},
			},
		}

		principal, err := provider.Authenticate("", req)
		assert.NoError(t, err)
		assert.NotNil(t, principal)
		assert.Equal(t, "workload/service", principal.GetID())
	})

	t.Run("Authenticate_EmptyWorkloadIdentity", func(t *testing.T) {
		provider := NewSPIFFEProvider("example.com")

		// Create request with SPIFFE ID that has empty path
		req := &http.Request{
			TLS: &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{
					{
						URIs: []*url.URL{
							mustParseURL("spiffe://example.com/"),
						},
					},
				},
			},
		}

		principal, err := provider.Authenticate("", req)
		assert.Error(t, err)
		assert.Nil(t, principal)
		assert.Contains(t, err.Error(), "cannot extract workload identity")
	})

	t.Run("Authenticate_MultipleURIs", func(t *testing.T) {
		provider := NewSPIFFEProvider("example.com")

		// Create request with multiple URIs, including SPIFFE
		req := &http.Request{
			TLS: &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{
					{
						URIs: []*url.URL{
							mustParseURL("https://example.com"),
							mustParseURL("spiffe://example.com/service/api"),
							mustParseURL("mailto:user@example.com"),
						},
					},
				},
			},
		}

		principal, err := provider.Authenticate("", req)
		assert.NoError(t, err)
		assert.NotNil(t, principal)
		assert.Equal(t, "service/api", principal.GetID())
	})
}

// TestExtractSPIFFEID tests the SPIFFE ID extraction function.
func TestExtractSPIFFEID(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cert := &x509.Certificate{
			URIs: []*url.URL{
				mustParseURL("spiffe://example.com/ns/production/sa/web-server"),
			},
		}

		spiffeID, err := extractSPIFFEID(cert)
		assert.NoError(t, err)
		assert.Equal(t, "spiffe", spiffeID.Scheme)
		assert.Equal(t, "example.com", spiffeID.Host)
		assert.Equal(t, "/ns/production/sa/web-server", spiffeID.Path)
	})

	t.Run("NoSPIFFEURI", func(t *testing.T) {
		cert := &x509.Certificate{
			URIs: []*url.URL{
				mustParseURL("https://example.com"),
				mustParseURL("mailto:user@example.com"),
			},
		}

		spiffeID, err := extractSPIFFEID(cert)
		assert.Error(t, err)
		assert.Nil(t, spiffeID)
		assert.Contains(t, err.Error(), "no SPIFFE ID found")
	})

	t.Run("NoURIs", func(t *testing.T) {
		cert := &x509.Certificate{
			URIs: []*url.URL{},
		}

		spiffeID, err := extractSPIFFEID(cert)
		assert.Error(t, err)
		assert.Nil(t, spiffeID)
		assert.Contains(t, err.Error(), "no SPIFFE ID found")
	})

	t.Run("MultipleSPIFFEURIs", func(t *testing.T) {
		cert := &x509.Certificate{
			URIs: []*url.URL{
				mustParseURL("spiffe://example.com/first"),
				mustParseURL("spiffe://example.com/second"),
			},
		}

		spiffeID, err := extractSPIFFEID(cert)
		assert.NoError(t, err)
		// Should return the first SPIFFE URI found
		assert.Equal(t, "/first", spiffeID.Path)
	})
}

// TestValidateTrustDomain tests the trust domain validation function.
func TestValidateTrustDomain(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := NewSPIFFEProvider("example.com")
		spiffeID := mustParseURL("spiffe://example.com/service/api")

		err := provider.validateTrustDomain(spiffeID)
		assert.NoError(t, err)
	})

	t.Run("Mismatch", func(t *testing.T) {
		provider := NewSPIFFEProvider("example.com")
		spiffeID := mustParseURL("spiffe://other.com/service/api")

		err := provider.validateTrustDomain(spiffeID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "trust domain mismatch")
	})

	t.Run("EmptyTrustDomain", func(t *testing.T) {
		provider := NewSPIFFEProvider("")
		spiffeID := mustParseURL("spiffe://any-domain.com/service/api")

		// Empty trust domain should not validate
		err := provider.validateTrustDomain(spiffeID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "trust domain mismatch")
	})
}

// TestExtractWorkloadIdentity tests the workload identity extraction function.
func TestExtractWorkloadIdentity(t *testing.T) {
	testCases := []struct {
		name        string
		spiffeID    string
		expected    string
		description string
	}{
		{
			name:        "NamespaceServiceAccount",
			spiffeID:    "spiffe://example.com/ns/production/sa/web-server",
			expected:    "ns/production/sa/web-server",
			description: "Standard Kubernetes namespace/service account pattern",
		},
		{
			name:        "WorkloadPattern",
			spiffeID:    "spiffe://example.com/workload/api-service",
			expected:    "workload/api-service",
			description: "Workload-based identity pattern",
		},
		{
			name:        "ServicePattern",
			spiffeID:    "spiffe://example.com/service/database",
			expected:    "service/database",
			description: "Service-based identity pattern",
		},
		{
			name:        "SimplePath",
			spiffeID:    "spiffe://example.com/my-service",
			expected:    "my-service",
			description: "Simple service name pattern",
		},
		{
			name:        "NestedPath",
			spiffeID:    "spiffe://example.com/team/project/service",
			expected:    "team/project/service",
			description: "Nested organizational path",
		},
		{
			name:        "RootPath",
			spiffeID:    "spiffe://example.com/",
			expected:    "",
			description: "Root path results in empty identity",
		},
		{
			name:        "EmptyPath",
			spiffeID:    "spiffe://example.com",
			expected:    "",
			description: "No path results in empty identity",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			spiffeID := mustParseURL(tc.spiffeID)
			identity := extractWorkloadIdentity(spiffeID)
			assert.Equal(t, tc.expected, identity, tc.description)
		})
	}
}

// TestParseSPIFFEID tests the SPIFFE ID parsing function.
func TestParseSPIFFEID(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		trustDomain, path, err := ParseSPIFFEID("spiffe://example.com/ns/production/sa/web-server")
		assert.NoError(t, err)
		assert.Equal(t, "example.com", trustDomain)
		assert.Equal(t, "ns/production/sa/web-server", path)
	})

	t.Run("InvalidURL", func(t *testing.T) {
		trustDomain, path, err := ParseSPIFFEID(":invalid:url:")
		assert.Error(t, err)
		assert.Empty(t, trustDomain)
		assert.Empty(t, path)
		assert.Contains(t, err.Error(), "invalid SPIFFE ID")
	})

	t.Run("WrongScheme", func(t *testing.T) {
		trustDomain, path, err := ParseSPIFFEID("https://example.com/service")
		assert.Error(t, err)
		assert.Empty(t, trustDomain)
		assert.Empty(t, path)
		assert.Contains(t, err.Error(), "invalid SPIFFE ID scheme")
	})

	t.Run("MissingTrustDomain", func(t *testing.T) {
		trustDomain, path, err := ParseSPIFFEID("spiffe:///service")
		assert.Error(t, err)
		assert.Empty(t, trustDomain)
		assert.Empty(t, path)
		assert.Contains(t, err.Error(), "missing trust domain")
	})

	t.Run("EmptyPath", func(t *testing.T) {
		trustDomain, path, err := ParseSPIFFEID("spiffe://example.com")
		assert.NoError(t, err)
		assert.Equal(t, "example.com", trustDomain)
		assert.Equal(t, "", path)
	})

	t.Run("RootPath", func(t *testing.T) {
		trustDomain, path, err := ParseSPIFFEID("spiffe://example.com/")
		assert.NoError(t, err)
		assert.Equal(t, "example.com", trustDomain)
		assert.Equal(t, "", path)
	})
}

// TestSPIFFEProvider_Integration tests integration scenarios.
func TestSPIFFEProvider_Integration(t *testing.T) {
	t.Run("DifferentWorkloadPatterns", func(t *testing.T) {
		provider := NewSPIFFEProvider("example.com")

		testCases := []struct {
			spiffeID   string
			expectedID string
		}{
			{
				spiffeID:   "spiffe://example.com/ns/default/sa/default",
				expectedID: "ns/default/sa/default",
			},
			{
				spiffeID:   "spiffe://example.com/workload/frontend",
				expectedID: "workload/frontend",
			},
			{
				spiffeID:   "spiffe://example.com/service/backend",
				expectedID: "service/backend",
			},
			{
				spiffeID:   "spiffe://example.com/app/user-service/v1",
				expectedID: "app/user-service/v1",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.spiffeID, func(t *testing.T) {
				req := &http.Request{
					TLS: &tls.ConnectionState{
						PeerCertificates: []*x509.Certificate{
							{
								URIs: []*url.URL{
									mustParseURL(tc.spiffeID),
								},
							},
						},
					},
				}

				principal, err := provider.Authenticate("", req)
				assert.NoError(t, err)
				assert.NotNil(t, principal)
				assert.Equal(t, tc.expectedID, principal.GetID())
				assert.Equal(t, "machine", principal.Type())
			})
		}
	})

	t.Run("CertificateValidation", func(t *testing.T) {
		provider := NewSPIFFEProvider("prod.example.com")

		// Test with valid production trust domain
		validReq := &http.Request{
			TLS: &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{
					{
						URIs: []*url.URL{
							mustParseURL("spiffe://prod.example.com/service/api"),
						},
					},
				},
			},
		}

		principal, err := provider.Authenticate("", validReq)
		assert.NoError(t, err)
		assert.NotNil(t, principal)

		// Test with invalid staging trust domain
		invalidReq := &http.Request{
			TLS: &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{
					{
						URIs: []*url.URL{
							mustParseURL("spiffe://staging.example.com/service/api"),
						},
					},
				},
			},
		}

		principal, err = provider.Authenticate("", invalidReq)
		assert.Error(t, err)
		assert.Nil(t, principal)
	})
}

// Helper function to parse URL without error handling for tests.
func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}
