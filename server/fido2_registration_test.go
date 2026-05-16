package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/mux"
	"github.com/hazayan/knox/server/auth"
)

type fakeFido2Registration struct {
	beginErr  error
	finishErr error
	importErr error
}

func (f fakeFido2Registration) BeginRegistration(req Fido2BeginRegistrationRequest) (*Fido2BeginRegistrationResponse, error) {
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	if req.PrincipalType != "user" || req.Subject != "alice" {
		return nil, errors.New("unexpected begin request")
	}
	return &Fido2BeginRegistrationResponse{
		SessionID: "registration-session-1",
		Options:   json.RawMessage(`{"publicKey":{"challenge":"challenge-1"}}`),
	}, nil
}

func (f fakeFido2Registration) FinishRegistration(req Fido2FinishRegistrationRequest) (*Fido2CredentialResponse, error) {
	if f.finishErr != nil {
		return nil, f.finishErr
	}
	if req.SessionID != "registration-session-1" {
		return nil, errors.New("unexpected registration session")
	}
	return &Fido2CredentialResponse{
		PrincipalType: "user",
		Subject:       "alice",
		CredentialID:  "Y3JlZGVudGlhbC0x",
	}, nil
}

func (f fakeFido2Registration) ImportCredential(req Fido2ImportCredentialRequest) (*Fido2CredentialResponse, error) {
	if f.importErr != nil {
		return nil, f.importErr
	}
	if req.PrincipalType != "user" || req.Subject != "alice" {
		return nil, errors.New("unexpected import request")
	}
	return &Fido2CredentialResponse{
		PrincipalType: "user",
		Subject:       "alice",
		CredentialID:  "Y3JlZGVudGlhbC0x",
	}, nil
}

func TestFido2AdminRoutesUseDecorators(t *testing.T) {
	router := mux.NewRouter()
	decoratorCalled := false
	RegisterFido2AdminRoutes(router, fakeFido2Registration{}, []func(http.HandlerFunc) http.HandlerFunc{
		func(next http.HandlerFunc) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				decoratorCalled = true
				next(w, r)
			}
		},
	})

	body := bytes.NewBufferString(`{"principal_type":"user","subject":"alice"}`)
	req := httptest.NewRequest(http.MethodPost, "/v0/auth/fido2/credentials/begin", body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d %s", rec.Code, rec.Body.String())
	}
	if !decoratorCalled {
		t.Fatal("expected admin route decorator to run")
	}
	var resp Fido2BeginRegistrationResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.SessionID != "registration-session-1" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestFido2AdminImportRoute(t *testing.T) {
	router := mux.NewRouter()
	RegisterFido2AdminRoutes(router, fakeFido2Registration{}, nil)

	body := bytes.NewBufferString(`{
		"principal_type":"user",
		"subject":"alice",
		"credential":{"id":"Y3JlZGVudGlhbC0x","publicKey":"cHVibGljLWtleQ=="}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/v0/auth/fido2/credentials/import", body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d %s", rec.Code, rec.Body.String())
	}
	var resp Fido2CredentialResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.CredentialID != "Y3JlZGVudGlhbC0x" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestWebAuthnImportCredentialPersistsToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "principals.json")
	store, err := NewWebAuthnPrincipalStoreFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := auth.NewFido2TokenIssuer("knox-test", []byte("0123456789abcdef0123456789abcdef"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewWebAuthnCeremonyService(&webauthn.Config{
		RPID:          "knox.example.net",
		RPDisplayName: "Knox",
		RPOrigins:     []string{"https://knox.example.net"},
	}, store, issuer)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := service.ImportCredential(Fido2ImportCredentialRequest{
		PrincipalType: "user",
		Subject:       "alice",
		DisplayName:   "Alice",
		Groups:        []string{"operators"},
		Credential: webauthn.Credential{
			ID:        []byte("credential-1"),
			PublicKey: []byte("public-key"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.CredentialID != "Y3JlZGVudGlhbC0x" {
		t.Fatalf("unexpected response: %+v", resp)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Fatalf("persisted credentials are not valid JSON: %s", string(data))
	}

	reloaded, err := NewWebAuthnPrincipalStoreFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := reloaded.LookupWebAuthnPrincipal("user", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if principal.DisplayName != "Alice" || len(principal.Credentials) != 1 || string(principal.Credentials[0].ID) != "credential-1" {
		t.Fatalf("unexpected principal: %+v", principal)
	}
}
