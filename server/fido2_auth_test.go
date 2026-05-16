package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

type fakeFido2Ceremony struct {
	beginErr  error
	finishErr error
}

func (f fakeFido2Ceremony) BeginLogin(req Fido2BeginLoginRequest) (*Fido2BeginLoginResponse, error) {
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	if req.PrincipalType != "user" || req.Subject != "alice" {
		return nil, errors.New("unexpected begin request")
	}
	return &Fido2BeginLoginResponse{
		SessionID: "session-1",
		Options:   json.RawMessage(`{"challenge":"challenge-1"}`),
	}, nil
}

func (f fakeFido2Ceremony) FinishLogin(req Fido2FinishLoginRequest) (*Fido2FinishLoginResponse, error) {
	if f.finishErr != nil {
		return nil, f.finishErr
	}
	if req.SessionID != "session-1" {
		return nil, errors.New("unexpected session")
	}
	return &Fido2FinishLoginResponse{
		Token:         "token-value",
		ExpiresAt:     time.Unix(1000, 0).UTC(),
		PrincipalType: "user",
		Subject:       "alice",
	}, nil
}

func TestFido2BeginLoginRoute(t *testing.T) {
	router := mux.NewRouter()
	RegisterFido2AuthRoutes(router, fakeFido2Ceremony{})

	body := bytes.NewBufferString(`{"principal_type":"user","subject":"alice"}`)
	req := httptest.NewRequest(http.MethodPost, "/v0/auth/fido2/login/begin", body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d %s", rec.Code, rec.Body.String())
	}
	var resp Fido2BeginLoginResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.SessionID != "session-1" || !bytes.Contains(resp.Options, []byte("challenge-1")) {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestFido2FinishLoginRoute(t *testing.T) {
	router := mux.NewRouter()
	RegisterFido2AuthRoutes(router, fakeFido2Ceremony{})

	body := bytes.NewBufferString(`{"session_id":"session-1","assertion":{"id":"credential-1"}}`)
	req := httptest.NewRequest(http.MethodPost, "/v0/auth/fido2/login/finish", body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d %s", rec.Code, rec.Body.String())
	}
	var resp Fido2FinishLoginResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Token != "token-value" || resp.Subject != "alice" || resp.PrincipalType != "user" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestFido2RouteRejectsBadJSON(t *testing.T) {
	router := mux.NewRouter()
	RegisterFido2AuthRoutes(router, fakeFido2Ceremony{})

	req := httptest.NewRequest(http.MethodPost, "/v0/auth/fido2/login/begin", bytes.NewBufferString(`{`))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
}
