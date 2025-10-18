package auth

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hazayan/knox/pkg/types"
	knoxauth "github.com/hazayan/knox/server/auth"
)

// SPIFFEProvider authenticates clients using SPIFFE identities.
// SPIFFE (Secure Production Identity Framework For Everyone) provides
// workload identity using X.509 certificates with SPIFFE IDs in URI SANs.
type SPIFFEProvider struct {
	name        string
	trustDomain string
}

// NewSPIFFEProvider creates a new SPIFFE authentication provider.
func NewSPIFFEProvider(trustDomain string) *SPIFFEProvider {
	return &SPIFFEProvider{
		name:        "spiffe",
		trustDomain: trustDomain,
	}
}

// Name returns the provider name.
func (p *SPIFFEProvider) Name() string {
	return p.name
}

// Authenticate authenticates a request using SPIFFE identities.
func (p *SPIFFEProvider) Authenticate(token string, r *http.Request) (types.Principal, error) {
	// Check if TLS is used
	if r.TLS == nil {
		return nil, fmt.Errorf("TLS not enabled")
	}

	// Check if client provided certificates
	if len(r.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no client certificates provided")
	}

	// Get the client certificate
	cert := r.TLS.PeerCertificates[0]

	// Extract SPIFFE ID from URI SANs
	spiffeID, err := extractSPIFFEID(cert)
	if err != nil {
		return nil, fmt.Errorf("invalid SPIFFE certificate: %w", err)
	}

	// Validate trust domain
	if p.trustDomain != "" {
		if err := p.validateTrustDomain(spiffeID); err != nil {
			return nil, fmt.Errorf("trust domain validation failed: %w", err)
		}
	}

	// Extract workload identity from SPIFFE ID
	identity := extractWorkloadIdentity(spiffeID)
	if identity == "" {
		return nil, fmt.Errorf("cannot extract workload identity from SPIFFE ID")
	}

	// SPIFFE identities are typically for machines/services
	return knoxauth.NewMachine(identity), nil
}

// Version returns the provider version byte.
func (p *SPIFFEProvider) Version() byte {
	return 0x01
}

// Type returns the provider type byte.
func (p *SPIFFEProvider) Type() byte {
	return 0x02
}

// extractSPIFFEID extracts the SPIFFE ID from certificate URI SANs.
func extractSPIFFEID(cert *x509.Certificate) (*url.URL, error) {
	// Look for SPIFFE ID in URI SANs
	for _, uri := range cert.URIs {
		if uri.Scheme == "spiffe" {
			return uri, nil
		}
	}

	return nil, fmt.Errorf("no SPIFFE ID found in certificate")
}

// validateTrustDomain validates that the SPIFFE ID is from the expected trust domain.
func (p *SPIFFEProvider) validateTrustDomain(spiffeID *url.URL) error {
	// SPIFFE ID format: spiffe://trust-domain/path
	if spiffeID.Host != p.trustDomain {
		return fmt.Errorf("trust domain mismatch: expected %s, got %s", p.trustDomain, spiffeID.Host)
	}
	return nil
}

// extractWorkloadIdentity extracts the workload identity from SPIFFE ID path.
// Example: spiffe://example.com/ns/production/sa/web-server -> production/web-server
func extractWorkloadIdentity(spiffeID *url.URL) string {
	// Remove leading slash
	path := strings.TrimPrefix(spiffeID.Path, "/")

	// The path typically follows patterns like:
	// /ns/<namespace>/sa/<service-account>
	// /workload/<name>
	// /service/<name>

	// For now, use the entire path as identity
	// In production, you might want to parse this more carefully
	return path
}

// ParseSPIFFEID parses a SPIFFE ID string into its components.
func ParseSPIFFEID(spiffeIDStr string) (trustDomain string, path string, err error) {
	u, err := url.Parse(spiffeIDStr)
	if err != nil {
		return "", "", fmt.Errorf("invalid SPIFFE ID: %w", err)
	}

	if u.Scheme != "spiffe" {
		return "", "", fmt.Errorf("invalid SPIFFE ID scheme: %s", u.Scheme)
	}

	if u.Host == "" {
		return "", "", fmt.Errorf("SPIFFE ID missing trust domain")
	}

	return u.Host, strings.TrimPrefix(u.Path, "/"), nil
}

// Verify interface compliance
var _ knoxauth.Provider = (*SPIFFEProvider)(nil)
