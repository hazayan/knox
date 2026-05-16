package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

// Fido2CeremonyService owns the WebAuthn ceremony. Production implementations
// validate assertions before minting a short-lived Knox API token.
type Fido2CeremonyService interface {
	BeginLogin(Fido2BeginLoginRequest) (*Fido2BeginLoginResponse, error)
	FinishLogin(Fido2FinishLoginRequest) (*Fido2FinishLoginResponse, error)
}

type Fido2BeginLoginRequest struct {
	PrincipalType string `json:"principal_type"`
	Subject       string `json:"subject"`
}

type Fido2BeginLoginResponse struct {
	SessionID string          `json:"session_id"`
	Options   json.RawMessage `json:"options"`
}

type Fido2FinishLoginRequest struct {
	SessionID string          `json:"session_id"`
	Assertion json.RawMessage `json:"assertion"`
}

type Fido2FinishLoginResponse struct {
	Token         string    `json:"token"`
	ExpiresAt     time.Time `json:"expires_at"`
	PrincipalType string    `json:"principal_type"`
	Subject       string    `json:"subject"`
}

// RegisterFido2AuthRoutes registers public FIDO2 login ceremony routes.
func RegisterFido2AuthRoutes(router *mux.Router, service Fido2CeremonyService) {
	handler := fido2AuthHandler{service: service}
	router.HandleFunc("/v0/auth/fido2/login/begin", handler.beginLogin).Methods(http.MethodPost)
	router.HandleFunc("/v0/auth/fido2/login/finish", handler.finishLogin).Methods(http.MethodPost)
}

type fido2AuthHandler struct {
	service Fido2CeremonyService
}

func (h fido2AuthHandler) beginLogin(w http.ResponseWriter, r *http.Request) {
	var req Fido2BeginLoginRequest
	if err := decodeJSONRequest(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	resp, err := h.service.BeginLogin(req)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h fido2AuthHandler) finishLogin(w http.ResponseWriter, r *http.Request) {
	var req Fido2FinishLoginRequest
	if err := decodeJSONRequest(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	resp, err := h.service.FinishLogin(req)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func decodeJSONRequest(r *http.Request, out any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeJSONError(w http.ResponseWriter, status int, err error) {
	if err == nil {
		err = errors.New("request failed")
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
