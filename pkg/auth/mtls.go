// Package auth provides authentication providers for Knox.
package auth

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"

	"github.com/pinterest/knox"
	knoxauth "github.com/pinterest/knox/server/auth"
)

// MTLSProvider authenticates clients using TLS client certificates.
type MTLSProvider struct {
	name string
}

// NewMTLSProvider creates a new mTLS authentication provider.
func NewMTLSProvider() *MTLSProvider {
	return &MTLSProvider{
		name: "mtls",
	}
}

// Name returns the provider name.
func (p *MTLSProvider) Name() string {
	return p.name
}

// Authenticate authenticates a request using TLS client certificates.
func (p *MTLSProvider) Authenticate(token string, r *http.Request) (knox.Principal, error) {
	// Check if TLS is used
	if r.TLS == nil {
		return nil, fmt.Errorf("TLS not enabled")
	}

	// Check if client provided certificates
	if len(r.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no client certificates provided")
	}

	// Get the client certificate (first in chain)
	cert := r.TLS.PeerCertificates[0]

	// Verify the certificate was validated by TLS
	if !r.TLS.HandshakeComplete {
		return nil, fmt.Errorf("TLS handshake not complete")
	}

	// Extract identity from certificate
	identity := extractIdentity(cert)
	if identity == "" {
		return nil, fmt.Errorf("cannot extract identity from certificate")
	}

	// Determine principal type
	principalType := determinePrincipalType(cert)

	// Create and return principal
	switch principalType {
	case knox.Machine:
		return knoxauth.NewMachine(identity), nil
	case knox.User:
		return knoxauth.NewUser(identity, []string{}), nil
	default:
		return nil, fmt.Errorf("unknown principal type")
	}
}

// Version returns the provider version byte.
func (p *MTLSProvider) Version() byte {
	return 0x01
}

// Type returns the provider type byte.
func (p *MTLSProvider) Type() byte {
	return 0x01
}

// extractIdentity extracts the identity from a certificate.
// Priority: SAN DNS > SAN URI > CN
func extractIdentity(cert *x509.Certificate) string {
	// Try DNS SANs first (for machines)
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}

	// Try URI SANs (for SPIFFE)
	if len(cert.URIs) > 0 {
		return cert.URIs[0].String()
	}

	// Fall back to Common Name
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}

	return ""
}

// determinePrincipalType determines if this is a machine or user certificate.
func determinePrincipalType(cert *x509.Certificate) knox.PrincipalType {
	// If it has DNS SANs or EmailAddresses, likely a machine
	if len(cert.DNSNames) > 0 {
		return knox.Machine
	}

	// If it has email addresses, likely a user
	if len(cert.EmailAddresses) > 0 {
		return knox.User
	}

	// Check CN format
	cn := cert.Subject.CommonName

	// If CN looks like a hostname (contains dots or dashes), treat as machine
	if strings.Contains(cn, ".") || strings.Contains(cn, "-") {
		return knox.Machine
	}

	// Default to user
	return knox.User
}

// Verify interface compliance
var _ knoxauth.Provider = (*MTLSProvider)(nil)
