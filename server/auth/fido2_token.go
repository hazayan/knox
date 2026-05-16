package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hazayan/knox/pkg/types"
)

const (
	fido2TokenVersion = 1
	minTokenKeyLen    = 32
)

var (
	errInvalidTokenSigningKey = errors.New("fido2 token signing key must contain at least 32 bytes")
	errInvalidFido2Token      = errors.New("invalid fido2 token")
	errExpiredFido2Token      = errors.New("expired fido2 token")
)

type tokenClock func() time.Time

// Fido2TokenIssuer mints and validates Knox API tokens after a successful
// WebAuthn/FIDO2 ceremony.
type Fido2TokenIssuer struct {
	issuer string
	key    []byte
	ttl    time.Duration
	now    tokenClock
}

type fido2TokenClaims struct {
	Version       int      `json:"version"`
	Issuer        string   `json:"issuer"`
	Subject       string   `json:"subject"`
	PrincipalType string   `json:"principal_type"`
	Groups        []string `json:"groups,omitempty"`
	IssuedAt      int64    `json:"issued_at"`
	ExpiresAt     int64    `json:"expires_at"`
}

// NewFido2TokenIssuer creates an HMAC-backed token issuer.
func NewFido2TokenIssuer(issuer string, key []byte, ttl time.Duration) (*Fido2TokenIssuer, error) {
	if len(key) < minTokenKeyLen {
		return nil, errInvalidTokenSigningKey
	}
	if issuer == "" {
		return nil, errors.New("fido2 token issuer must not be empty")
	}
	if ttl <= 0 {
		return nil, errors.New("fido2 token ttl must be positive")
	}

	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return &Fido2TokenIssuer{
		issuer: issuer,
		key:    keyCopy,
		ttl:    ttl,
		now:    time.Now,
	}, nil
}

// MintUserToken mints a token for a Knox user principal.
func (i *Fido2TokenIssuer) MintUserToken(subject string, groups []string) (string, time.Time, error) {
	return i.mintToken(subject, "user", groups)
}

// MintMachineToken mints a token for a Knox machine principal.
func (i *Fido2TokenIssuer) MintMachineToken(subject string) (string, time.Time, error) {
	return i.mintToken(subject, "machine", nil)
}

func (i *Fido2TokenIssuer) mintToken(subject, principalType string, groups []string) (string, time.Time, error) {
	if subject == "" {
		return "", time.Time{}, errors.New("fido2 token subject must not be empty")
	}
	now := i.now().UTC()
	expires := now.Add(i.ttl)
	claims := fido2TokenClaims{
		Version:       fido2TokenVersion,
		Issuer:        i.issuer,
		Subject:       subject,
		PrincipalType: principalType,
		Groups:        append([]string(nil), groups...),
		IssuedAt:      now.Unix(),
		ExpiresAt:     expires.Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to encode fido2 token claims: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	signature := i.sign(payloadB64)
	return payloadB64 + "." + signature, expires, nil
}

func (i *Fido2TokenIssuer) authenticate(token string) (types.Principal, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, errInvalidFido2Token
	}
	if !hmac.Equal([]byte(i.sign(parts[0])), []byte(parts[1])) {
		return nil, errInvalidFido2Token
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errInvalidFido2Token
	}
	var claims fido2TokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errInvalidFido2Token
	}
	if claims.Version != fido2TokenVersion || claims.Issuer != i.issuer || claims.Subject == "" {
		return nil, errInvalidFido2Token
	}
	if i.now().UTC().Unix() >= claims.ExpiresAt {
		return nil, errExpiredFido2Token
	}
	switch claims.PrincipalType {
	case "user":
		return NewUser(claims.Subject, claims.Groups), nil
	case "machine":
		return NewMachine(claims.Subject), nil
	default:
		return nil, errInvalidFido2Token
	}
}

func (i *Fido2TokenIssuer) sign(payload string) string {
	mac := hmac.New(sha256.New, i.key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Fido2TokenProvider validates FIDO2-minted Knox API tokens.
type Fido2TokenProvider struct {
	issuer *Fido2TokenIssuer
}

// NewFido2TokenProvider creates a provider backed by a token issuer.
func NewFido2TokenProvider(issuer *Fido2TokenIssuer) *Fido2TokenProvider {
	return &Fido2TokenProvider{issuer: issuer}
}

func (p *Fido2TokenProvider) Name() string {
	return "fido2"
}

func (p *Fido2TokenProvider) Version() byte {
	return '0'
}

func (p *Fido2TokenProvider) Type() byte {
	return 'u'
}

func (p *Fido2TokenProvider) Authenticate(token string, _ *http.Request) (types.Principal, error) {
	if p.issuer == nil {
		return nil, errors.New("fido2 token provider is not configured")
	}
	return p.issuer.authenticate(token)
}
