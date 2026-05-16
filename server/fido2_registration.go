package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/mux"
)

type Fido2RegistrationService interface {
	BeginRegistration(Fido2BeginRegistrationRequest) (*Fido2BeginRegistrationResponse, error)
	FinishRegistration(Fido2FinishRegistrationRequest) (*Fido2CredentialResponse, error)
	ImportCredential(Fido2ImportCredentialRequest) (*Fido2CredentialResponse, error)
}

type Fido2BeginRegistrationRequest struct {
	PrincipalType string   `json:"principal_type"`
	Subject       string   `json:"subject"`
	DisplayName   string   `json:"display_name,omitempty"`
	Groups        []string `json:"groups,omitempty"`
}

type Fido2BeginRegistrationResponse struct {
	SessionID string          `json:"session_id"`
	Options   json.RawMessage `json:"options"`
}

type Fido2FinishRegistrationRequest struct {
	SessionID  string          `json:"session_id"`
	Credential json.RawMessage `json:"credential"`
}

type Fido2ImportCredentialRequest struct {
	PrincipalType string              `json:"principal_type"`
	Subject       string              `json:"subject"`
	DisplayName   string              `json:"display_name,omitempty"`
	Groups        []string            `json:"groups,omitempty"`
	UserHandle    string              `json:"user_handle,omitempty"`
	Credential    webauthn.Credential `json:"credential"`
}

type Fido2CredentialResponse struct {
	PrincipalType string `json:"principal_type"`
	Subject       string `json:"subject"`
	CredentialID  string `json:"credential_id"`
}

func (s *WebAuthnCeremonyService) BeginRegistration(req Fido2BeginRegistrationRequest) (*Fido2BeginRegistrationResponse, error) {
	if s.writer == nil {
		return nil, errors.New("webauthn principal store is read-only")
	}
	principal := WebAuthnPrincipal{
		PrincipalType: req.PrincipalType,
		Subject:       req.Subject,
		DisplayName:   req.DisplayName,
		Groups:        append([]string(nil), req.Groups...),
	}
	existing, err := s.store.LookupWebAuthnPrincipal(req.PrincipalType, req.Subject)
	if err == nil {
		principal.UserHandle = existing.UserHandle
		principal.Credentials = existing.Credentials
		if principal.DisplayName == "" {
			principal.DisplayName = existing.DisplayName
		}
		if len(principal.Groups) == 0 {
			principal.Groups = existing.Groups
		}
	}
	if err := principal.Validate(); err != nil {
		return nil, err
	}
	creation, session, err := s.rp.BeginRegistration(principal.toWebAuthnUser())
	if err != nil {
		return nil, err
	}
	sessionID, err := randomSessionID()
	if err != nil {
		return nil, err
	}
	options, err := json.Marshal(creation)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.registry[sessionID] = webAuthnRegistrationSession{
		Principal: principal,
		Session:   *session,
	}
	s.mu.Unlock()
	return &Fido2BeginRegistrationResponse{
		SessionID: sessionID,
		Options:   options,
	}, nil
}

func (s *WebAuthnCeremonyService) FinishRegistration(req Fido2FinishRegistrationRequest) (*Fido2CredentialResponse, error) {
	if s.writer == nil {
		return nil, errors.New("webauthn principal store is read-only")
	}
	s.mu.Lock()
	session, ok := s.registry[req.SessionID]
	if ok {
		delete(s.registry, req.SessionID)
	}
	s.mu.Unlock()
	if !ok {
		return nil, errors.New("unknown fido2 registration session")
	}
	user := session.Principal.toWebAuthnUser()
	httpReq := httptest.NewRequest(http.MethodPost, "/v0/auth/fido2/credentials/finish", bytes.NewReader(req.Credential))
	credential, err := s.rp.FinishRegistration(user, session.Session, httpReq)
	if err != nil {
		return nil, err
	}
	principal := session.Principal
	principal.UserHandle = user.WebAuthnID()
	principal.Credentials = append(principal.Credentials, *credential)
	if err := s.writer.SaveWebAuthnPrincipal(principal); err != nil {
		return nil, err
	}
	return credentialResponse(principal, credential.ID), nil
}

func (s *WebAuthnCeremonyService) ImportCredential(req Fido2ImportCredentialRequest) (*Fido2CredentialResponse, error) {
	if s.writer == nil {
		return nil, errors.New("webauthn principal store is read-only")
	}
	principal := WebAuthnPrincipal{
		PrincipalType: req.PrincipalType,
		Subject:       req.Subject,
		DisplayName:   req.DisplayName,
		Groups:        append([]string(nil), req.Groups...),
		Credentials:   []webauthn.Credential{req.Credential},
	}
	if req.UserHandle != "" {
		userHandle, err := base64.RawURLEncoding.DecodeString(req.UserHandle)
		if err != nil {
			return nil, err
		}
		principal.UserHandle = userHandle
	}
	existing, err := s.store.LookupWebAuthnPrincipal(req.PrincipalType, req.Subject)
	if err == nil {
		principal.UserHandle = existing.UserHandle
		if req.UserHandle != "" {
			userHandle, err := base64.RawURLEncoding.DecodeString(req.UserHandle)
			if err != nil {
				return nil, err
			}
			principal.UserHandle = userHandle
		}
		if principal.DisplayName == "" {
			principal.DisplayName = existing.DisplayName
		}
		if len(principal.Groups) == 0 {
			principal.Groups = existing.Groups
		}
		principal.Credentials = append(existing.Credentials, req.Credential)
	}
	if len(req.Credential.ID) == 0 || len(req.Credential.PublicKey) == 0 {
		return nil, errors.New("webauthn credential id and public key are required")
	}
	if err := principal.Validate(); err != nil {
		return nil, err
	}
	if err := s.writer.SaveWebAuthnPrincipal(principal); err != nil {
		return nil, err
	}
	return credentialResponse(principal, req.Credential.ID), nil
}

func RegisterFido2AdminRoutes(router *mux.Router, service Fido2RegistrationService, decorators []func(http.HandlerFunc) http.HandlerFunc) {
	handler := fido2RegistrationHandler{service: service}
	decorator := func(f http.HandlerFunc) http.HandlerFunc { return f }
	for i := range decorators {
		j := len(decorators) - i - 1
		decorator = combine(decorators[j], decorator)
	}
	router.HandleFunc("/v0/auth/fido2/credentials/begin", decorator(handler.beginRegistration)).Methods(http.MethodPost)
	router.HandleFunc("/v0/auth/fido2/credentials/finish", decorator(handler.finishRegistration)).Methods(http.MethodPost)
	router.HandleFunc("/v0/auth/fido2/credentials/import", decorator(handler.importCredential)).Methods(http.MethodPost)
}

type fido2RegistrationHandler struct {
	service Fido2RegistrationService
}

func (h fido2RegistrationHandler) beginRegistration(w http.ResponseWriter, r *http.Request) {
	var req Fido2BeginRegistrationRequest
	if err := decodeJSONRequest(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	resp, err := h.service.BeginRegistration(req)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h fido2RegistrationHandler) finishRegistration(w http.ResponseWriter, r *http.Request) {
	var req Fido2FinishRegistrationRequest
	if err := decodeJSONRequest(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	resp, err := h.service.FinishRegistration(req)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h fido2RegistrationHandler) importCredential(w http.ResponseWriter, r *http.Request) {
	var req Fido2ImportCredentialRequest
	if err := decodeJSONRequest(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	resp, err := h.service.ImportCredential(req)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func credentialResponse(principal WebAuthnPrincipal, credentialID []byte) *Fido2CredentialResponse {
	return &Fido2CredentialResponse{
		PrincipalType: principal.PrincipalType,
		Subject:       principal.Subject,
		CredentialID:  base64.RawURLEncoding.EncodeToString(credentialID),
	}
}
