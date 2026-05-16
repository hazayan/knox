package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/hazayan/knox/server/auth"
)

// WebAuthnPrincipal stores the Knox identity and registered WebAuthn
// credentials needed to run a login ceremony.
type WebAuthnPrincipal struct {
	PrincipalType string
	Subject       string
	DisplayName   string
	Groups        []string
	UserHandle    []byte
	Credentials   []webauthn.Credential
}

type webAuthnPrincipalFileRecord struct {
	PrincipalType string                `json:"principal_type"`
	Subject       string                `json:"subject"`
	DisplayName   string                `json:"display_name,omitempty"`
	Groups        []string              `json:"groups,omitempty"`
	UserHandle    string                `json:"user_handle,omitempty"`
	Credentials   []webauthn.Credential `json:"credentials"`
}

// WebAuthnPrincipalStore resolves principals for WebAuthn login.
type WebAuthnPrincipalStore interface {
	LookupWebAuthnPrincipal(principalType, subject string) (WebAuthnPrincipal, error)
}

type WebAuthnPrincipalWriter interface {
	WebAuthnPrincipalStore
	SaveWebAuthnPrincipal(principal WebAuthnPrincipal) error
}

// InMemoryWebAuthnPrincipalStore stores WebAuthn principals in memory. It can
// optionally persist the complete principal set to a JSON file.
type InMemoryWebAuthnPrincipalStore struct {
	mu         sync.RWMutex
	path       string
	principals map[string]WebAuthnPrincipal
}

func NewInMemoryWebAuthnPrincipalStore() *InMemoryWebAuthnPrincipalStore {
	return &InMemoryWebAuthnPrincipalStore{
		principals: map[string]WebAuthnPrincipal{},
	}
}

func NewWebAuthnPrincipalStoreFromFile(path string) (*InMemoryWebAuthnPrincipalStore, error) {
	store := NewInMemoryWebAuthnPrincipalStore()
	store.path = path
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return store, nil
		}
		return nil, fmt.Errorf("failed to read webauthn principal file: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return store, nil
	}
	var records []webAuthnPrincipalFileRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("failed to parse webauthn principal file: %w", err)
	}
	for _, record := range records {
		principal, err := record.toPrincipal()
		if err != nil {
			return nil, err
		}
		store.Put(principal)
	}
	return store, nil
}

func (r webAuthnPrincipalFileRecord) toPrincipal() (WebAuthnPrincipal, error) {
	if r.PrincipalType != "user" && r.PrincipalType != "machine" {
		return WebAuthnPrincipal{}, errors.New("webauthn principal type must be user or machine")
	}
	if r.Subject == "" {
		return WebAuthnPrincipal{}, errors.New("webauthn principal subject must not be empty")
	}
	var userHandle []byte
	if r.UserHandle != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(r.UserHandle)
		if err != nil {
			return WebAuthnPrincipal{}, fmt.Errorf("invalid webauthn user handle: %w", err)
		}
		userHandle = decoded
	}
	return WebAuthnPrincipal{
		PrincipalType: r.PrincipalType,
		Subject:       r.Subject,
		DisplayName:   r.DisplayName,
		Groups:        append([]string(nil), r.Groups...),
		UserHandle:    userHandle,
		Credentials:   append([]webauthn.Credential(nil), r.Credentials...),
	}, nil
}

func (s *InMemoryWebAuthnPrincipalStore) Put(principal WebAuthnPrincipal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.principals[principalKey(principal.PrincipalType, principal.Subject)] = principal
}

func (s *InMemoryWebAuthnPrincipalStore) SaveWebAuthnPrincipal(principal WebAuthnPrincipal) error {
	if err := principal.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.principals[principalKey(principal.PrincipalType, principal.Subject)] = cloneWebAuthnPrincipal(principal)
	if s.path == "" {
		return nil
	}
	return s.writeLocked()
}

func (s *InMemoryWebAuthnPrincipalStore) LookupWebAuthnPrincipal(principalType, subject string) (WebAuthnPrincipal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	principal, ok := s.principals[principalKey(principalType, subject)]
	if !ok {
		return WebAuthnPrincipal{}, errors.New("webauthn principal not found")
	}
	return cloneWebAuthnPrincipal(principal), nil
}

func (s *InMemoryWebAuthnPrincipalStore) writeLocked() error {
	records := make([]webAuthnPrincipalFileRecord, 0, len(s.principals))
	keys := make([]string, 0, len(s.principals))
	for key := range s.principals {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		principal := s.principals[key]
		record, err := principal.toFileRecord()
		if err != nil {
			return err
		}
		records = append(records, record)
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode webauthn principal file: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("failed to create webauthn principal directory: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("failed to write webauthn principal file: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("failed to replace webauthn principal file: %w", err)
	}
	return nil
}

type webAuthnLoginSession struct {
	PrincipalType string
	Subject       string
	Session       webauthn.SessionData
}

type webAuthnRegistrationSession struct {
	Principal WebAuthnPrincipal
	Session   webauthn.SessionData
}

// WebAuthnCeremonyService implements FIDO2 login using go-webauthn.
type WebAuthnCeremonyService struct {
	rp       *webauthn.WebAuthn
	store    WebAuthnPrincipalStore
	writer   WebAuthnPrincipalWriter
	issuer   *auth.Fido2TokenIssuer
	mu       sync.Mutex
	sessions map[string]webAuthnLoginSession
	registry map[string]webAuthnRegistrationSession
}

func NewWebAuthnCeremonyService(
	cfg *webauthn.Config,
	store WebAuthnPrincipalStore,
	issuer *auth.Fido2TokenIssuer,
) (*WebAuthnCeremonyService, error) {
	if store == nil {
		return nil, errors.New("webauthn principal store is required")
	}
	if issuer == nil {
		return nil, errors.New("fido2 token issuer is required")
	}
	rp, err := webauthn.New(cfg)
	if err != nil {
		return nil, err
	}
	return &WebAuthnCeremonyService{
		rp:       rp,
		store:    store,
		writer:   principalWriter(store),
		issuer:   issuer,
		sessions: map[string]webAuthnLoginSession{},
		registry: map[string]webAuthnRegistrationSession{},
	}, nil
}

func (s *WebAuthnCeremonyService) BeginLogin(req Fido2BeginLoginRequest) (*Fido2BeginLoginResponse, error) {
	principal, err := s.store.LookupWebAuthnPrincipal(req.PrincipalType, req.Subject)
	if err != nil {
		return nil, err
	}
	user := principal.toWebAuthnUser()
	assertion, session, err := s.rp.BeginLogin(user)
	if err != nil {
		return nil, err
	}
	sessionID, err := randomSessionID()
	if err != nil {
		return nil, err
	}
	options, err := json.Marshal(assertion)
	if err != nil {
		return nil, fmt.Errorf("failed to encode webauthn assertion options: %w", err)
	}
	s.mu.Lock()
	s.sessions[sessionID] = webAuthnLoginSession{
		PrincipalType: req.PrincipalType,
		Subject:       req.Subject,
		Session:       *session,
	}
	s.mu.Unlock()
	return &Fido2BeginLoginResponse{
		SessionID: sessionID,
		Options:   options,
	}, nil
}

func (s *WebAuthnCeremonyService) FinishLogin(req Fido2FinishLoginRequest) (*Fido2FinishLoginResponse, error) {
	s.mu.Lock()
	session, ok := s.sessions[req.SessionID]
	if ok {
		delete(s.sessions, req.SessionID)
	}
	s.mu.Unlock()
	if !ok {
		return nil, errors.New("unknown fido2 session")
	}
	principal, err := s.store.LookupWebAuthnPrincipal(session.PrincipalType, session.Subject)
	if err != nil {
		return nil, err
	}
	user := principal.toWebAuthnUser()
	httpReq := httptest.NewRequest("POST", "/v0/auth/fido2/login/finish", bytes.NewReader(req.Assertion))
	if _, err := s.rp.FinishLogin(user, session.Session, httpReq); err != nil {
		return nil, err
	}
	token, expires, err := s.mintToken(principal)
	if err != nil {
		return nil, err
	}
	return &Fido2FinishLoginResponse{
		Token:         token,
		ExpiresAt:     expires,
		PrincipalType: principal.PrincipalType,
		Subject:       principal.Subject,
	}, nil
}

func (s *WebAuthnCeremonyService) mintToken(principal WebAuthnPrincipal) (string, time.Time, error) {
	switch principal.PrincipalType {
	case "user":
		return s.issuer.MintUserToken(principal.Subject, principal.Groups)
	case "machine":
		return s.issuer.MintMachineToken(principal.Subject)
	default:
		return "", time.Time{}, errors.New("unsupported fido2 principal type")
	}
}

type webAuthnUser struct {
	principal WebAuthnPrincipal
}

func (p WebAuthnPrincipal) toWebAuthnUser() webAuthnUser {
	if len(p.UserHandle) == 0 {
		sum := sha256.Sum256([]byte(principalKey(p.PrincipalType, p.Subject)))
		p.UserHandle = sum[:]
	}
	return webAuthnUser{principal: p}
}

func (p WebAuthnPrincipal) Validate() error {
	if p.PrincipalType != "user" && p.PrincipalType != "machine" {
		return errors.New("webauthn principal type must be user or machine")
	}
	if p.Subject == "" {
		return errors.New("webauthn principal subject must not be empty")
	}
	return nil
}

func (p WebAuthnPrincipal) toFileRecord() (webAuthnPrincipalFileRecord, error) {
	if err := p.Validate(); err != nil {
		return webAuthnPrincipalFileRecord{}, err
	}
	return webAuthnPrincipalFileRecord{
		PrincipalType: p.PrincipalType,
		Subject:       p.Subject,
		DisplayName:   p.DisplayName,
		Groups:        append([]string(nil), p.Groups...),
		UserHandle:    base64.RawURLEncoding.EncodeToString(p.toWebAuthnUser().WebAuthnID()),
		Credentials:   append([]webauthn.Credential(nil), p.Credentials...),
	}, nil
}

func cloneWebAuthnPrincipal(principal WebAuthnPrincipal) WebAuthnPrincipal {
	return WebAuthnPrincipal{
		PrincipalType: principal.PrincipalType,
		Subject:       principal.Subject,
		DisplayName:   principal.DisplayName,
		Groups:        append([]string(nil), principal.Groups...),
		UserHandle:    append([]byte(nil), principal.UserHandle...),
		Credentials:   append([]webauthn.Credential(nil), principal.Credentials...),
	}
}

func principalWriter(store WebAuthnPrincipalStore) WebAuthnPrincipalWriter {
	writer, _ := store.(WebAuthnPrincipalWriter)
	return writer
}

func (u webAuthnUser) WebAuthnID() []byte {
	return u.principal.UserHandle
}

func (u webAuthnUser) WebAuthnName() string {
	return u.principal.Subject
}

func (u webAuthnUser) WebAuthnDisplayName() string {
	if u.principal.DisplayName != "" {
		return u.principal.DisplayName
	}
	return u.principal.Subject
}

func (u webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return append([]webauthn.Credential(nil), u.principal.Credentials...)
}

func randomSessionID() (string, error) {
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", fmt.Errorf("failed to generate fido2 session id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(id[:]), nil
}

func principalKey(principalType, subject string) string {
	return principalType + ":" + subject
}
