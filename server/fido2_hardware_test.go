//go:build fido2hardware && libfido2 && cgo

package server

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/hazayan/knox/pkg/config"
	"github.com/hazayan/knox/pkg/types"
	"github.com/hazayan/knox/server/auth"
	"github.com/hazayan/knox/server/keydb"
	"gopkg.in/yaml.v2"
)

const fido2HardwareOrigin = "https://knox.example"

func TestFido2HardwareLoginReadsKeyAndRejectsBadTokens(t *testing.T) {
	devicePath := resolveHardwareFido2Device(t)
	pin := readHardwareFido2PIN(t)
	rpID := "knox.example"
	subject := "alice"

	cfg := &webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "Knox hardware validation",
		RPOrigins:     []string{fido2HardwareOrigin},
	}
	wa, err := webauthn.New(cfg)
	if err != nil {
		t.Fatalf("new webauthn: %v", err)
	}

	store := NewInMemoryWebAuthnPrincipalStore()
	principal := WebAuthnPrincipal{
		PrincipalType: "user",
		Subject:       subject,
		DisplayName:   "Alice",
		Groups:        []string{"operators"},
	}
	user := principal.toWebAuthnUser()

	_, registrationSession, err := wa.BeginRegistration(user, webauthn.WithConveyancePreference(protocol.PreferNoAttestation))
	if err != nil {
		t.Fatalf("begin registration: %v", err)
	}
	clientData := hardwareClientData(t, protocol.CreateCeremony, registrationSession.Challenge)
	hardwareCredential, err := hardwareFido2MakeCredential(devicePath, rpID, cfg.RPDisplayName, pin, user.WebAuthnID(), user.WebAuthnName(), user.WebAuthnDisplayName(), clientData)
	if err != nil {
		t.Fatalf("%v", err)
	}
	attestationObject := noneAttestationObject(t, hardwareCredential.AuthData)
	registrationResponse := credentialCreationResponse(t, hardwareCredential.CredentialID, clientData, attestationObject)
	registrationRequest := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(registrationResponse))
	credential, err := wa.FinishRegistration(user, *registrationSession, registrationRequest)
	if err != nil {
		t.Fatalf("finish registration: %v", err)
	}
	principal.Credentials = []webauthn.Credential{*credential}
	store.Put(principal)

	signingKey := make([]byte, 32)
	if _, err := rand.Read(signingKey); err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	issuer, err := auth.NewFido2TokenIssuer("knox-hardware-drill", signingKey, time.Second)
	if err != nil {
		t.Fatalf("new token issuer: %v", err)
	}
	service, err := NewWebAuthnCeremonyService(cfg, store, issuer)
	if err != nil {
		t.Fatalf("new webauthn service: %v", err)
	}

	server := hardwareRouter(t, issuer, service)
	defer server.Close()

	token := fido2LoginWithCLI(t, server, devicePath, subject)

	keyID := "fido2-hardware-drill"
	secret := []byte("hardware-backed-login-read")
	createKeyWithToken(t, server, token, keyID, secret)
	readSecret := readKeyWithToken(t, server, token, keyID)
	if !bytes.Equal(secret, readSecret) {
		t.Fatalf("read secret mismatch: got %q want %q", readSecret, secret)
	}

	tampered := token[:len(token)-1] + "x"
	expectUnauthorizedRead(t, server, tampered, keyID)

	time.Sleep(1200 * time.Millisecond)
	expectUnauthorizedRead(t, server, token, keyID)
}

func hardwareRouter(t *testing.T, issuer *auth.Fido2TokenIssuer, service Fido2CeremonyService) *httptest.Server {
	t.Helper()
	cryptor := keydb.NewAESGCMCryptor(0, []byte("testtesttesttest"))
	db := keydb.NewTempDB()
	decorators := []func(http.HandlerFunc) http.HandlerFunc{
		AddHeader("Content-Type", "application/json"),
		AddHeader("X-Content-Type-Options", "nosniff"),
		Authentication([]auth.Provider{auth.NewFido2TokenProvider(issuer)}, nil),
	}
	router, err := GetRouter(cryptor, db, decorators, nil)
	if err != nil {
		t.Fatalf("get router: %v", err)
	}
	RegisterFido2AuthRoutes(router, service)
	return httptest.NewServer(router)
}

func resolveHardwareFido2Device(t *testing.T) string {
	t.Helper()
	if device := strings.TrimSpace(os.Getenv("KNOX_FIDO2_DEVICE")); device != "" && device != "auto" {
		return device
	}
	device, err := hardwareFido2FirstDevicePath()
	if err != nil {
		t.Fatalf("%v", err)
	}
	return device
}

func readHardwareFido2PIN(t *testing.T) string {
	t.Helper()
	path := strings.TrimSpace(os.Getenv("KNOX_FIDO2_PIN_FILE"))
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read FIDO2 pin file: %v", err)
	}
	pin := strings.TrimRight(string(data), "\r\n")
	if pin == "" {
		t.Fatal("FIDO2 pin file is empty")
	}
	return pin
}

func hardwareClientData(t *testing.T, ceremony protocol.CeremonyType, challenge string) []byte {
	t.Helper()
	data, err := json.Marshal(protocol.CollectedClientData{
		Type:      ceremony,
		Challenge: challenge,
		Origin:    fido2HardwareOrigin,
	})
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}
	return data
}

func noneAttestationObject(t *testing.T, authData []byte) []byte {
	t.Helper()
	enc, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("create cbor encoder: %v", err)
	}
	obj, err := enc.Marshal(map[string]any{
		"fmt":      "none",
		"authData": authData,
		"attStmt":  map[string]any{},
	})
	if err != nil {
		t.Fatalf("marshal attestation object: %v", err)
	}
	return obj
}

func credentialCreationResponse(t *testing.T, credentialID, clientData, attestationObject []byte) []byte {
	t.Helper()
	id := base64.RawURLEncoding.EncodeToString(credentialID)
	resp, err := json.Marshal(map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"attestationObject": base64.RawURLEncoding.EncodeToString(attestationObject),
		},
		"authenticatorAttachment": "cross-platform",
	})
	if err != nil {
		t.Fatalf("marshal credential creation response: %v", err)
	}
	return resp
}

func credentialAssertionResponse(t *testing.T, credentialID, clientData []byte, assertion hardwareFido2Assertion, userHandle []byte) []byte {
	t.Helper()
	id := base64.RawURLEncoding.EncodeToString(credentialID)
	resp, err := json.Marshal(map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(assertion.AuthData),
			"signature":         base64.RawURLEncoding.EncodeToString(assertion.Signature),
			"userHandle":        base64.RawURLEncoding.EncodeToString(userHandle),
		},
		"authenticatorAttachment": "cross-platform",
	})
	if err != nil {
		t.Fatalf("marshal assertion response: %v", err)
	}
	return resp
}

func fido2BeginLogin(t *testing.T, server *httptest.Server, subject string) Fido2BeginLoginResponse {
	t.Helper()
	body := strings.NewReader(fmt.Sprintf(`{"principal_type":"user","subject":%q}`, subject))
	req, err := http.NewRequest(http.MethodPost, server.URL+"/v0/auth/fido2/login/begin", body)
	if err != nil {
		t.Fatalf("new begin request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp := doRequest(t, req, http.StatusOK)
	defer resp.Body.Close()
	var begin Fido2BeginLoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&begin); err != nil {
		t.Fatalf("decode begin response: %v", err)
	}
	return begin
}

func fido2LoginWithCLI(t *testing.T, server *httptest.Server, devicePath string, subject string) string {
	t.Helper()
	tempDir := t.TempDir()

	configFile := filepath.Join(tempDir, "client.yaml")
	serverURL, err := neturl.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	clientCfg := config.ClientConfig{
		CurrentProfile: "hardware-drill",
		Profiles: map[string]config.ClientProfile{
			"hardware-drill": {
				Server: serverURL.Host,
				Scheme: serverURL.Scheme,
				TLS:    config.ClientTLSConfig{},
				Cache: config.CacheConfig{
					Enabled: false,
				},
			},
		},
	}
	configData, err := yaml.Marshal(clientCfg)
	if err != nil {
		t.Fatalf("marshal client config: %v", err)
	}
	if err := os.WriteFile(configFile, configData, 0o600); err != nil {
		t.Fatalf("write client config: %v", err)
	}

	cmd := exec.Command(
		"go", "run", "-tags", "libfido2", "../cmd/client",
		"--config", configFile,
		"auth", "fido2", "login",
		"--principal-type", "user",
		"--subject", subject,
		"--device", devicePath,
		"--pin-file", os.Getenv("KNOX_FIDO2_PIN_FILE"),
		"--origin", fido2HardwareOrigin,
	)
	cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+tempDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run knox auth fido2 login: %v: %s", err, strings.TrimSpace(string(output)))
	}

	tokenFile := filepath.Join(tempDir, "knox", "token")
	tokenData, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("read CLI token file: %v", err)
	}
	token := strings.TrimSpace(string(tokenData))
	if token == "" {
		t.Fatal("CLI token file is empty")
	}
	return token
}

func createKeyWithToken(t *testing.T, server *httptest.Server, token string, keyID string, secret []byte) {
	t.Helper()
	form := url.Values{}
	form.Set("id", keyID)
	form.Set("data", base64.StdEncoding.EncodeToString(secret))
	req, err := http.NewRequest(http.MethodPost, server.URL+"/v0/keys/", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new create key request: %v", err)
	}
	req.Header.Set("Authorization", "0u"+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := doRequest(t, req, http.StatusOK)
	resp.Body.Close()
}

func readKeyWithToken(t *testing.T, server *httptest.Server, token string, keyID string) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, server.URL+"/v0/keys/"+keyID+"/", nil)
	if err != nil {
		t.Fatalf("new read key request: %v", err)
	}
	req.Header.Set("Authorization", "0u"+token)
	resp := doRequest(t, req, http.StatusOK)
	defer resp.Body.Close()
	var body types.Response
	var key types.Key
	body.Data = &key
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode key response: %v", err)
	}
	if len(key.VersionList) == 0 {
		t.Fatal("key response has no versions")
	}
	return key.VersionList[0].Data
}

func expectUnauthorizedRead(t *testing.T, server *httptest.Server, token string, keyID string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, server.URL+"/v0/keys/"+keyID+"/", nil)
	if err != nil {
		t.Fatalf("new unauthorized read request: %v", err)
	}
	req.Header.Set("Authorization", "0u"+token)
	resp := doRequest(t, req, http.StatusUnauthorized)
	resp.Body.Close()
}

func doRequest(t *testing.T, req *http.Request, expectedStatus int) *http.Response {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	if resp.StatusCode != expectedStatus {
		defer resp.Body.Close()
		t.Fatalf("%s %s returned %d, want %d", req.Method, req.URL.Path, resp.StatusCode, expectedStatus)
	}
	return resp
}
