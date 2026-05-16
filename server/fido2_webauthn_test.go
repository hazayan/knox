package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/hazayan/knox/server/auth"
)

func TestWebAuthnCeremonyBeginLogin(t *testing.T) {
	issuer, err := auth.NewFido2TokenIssuer("knox-test", []byte("0123456789abcdef0123456789abcdef"), 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	store := NewInMemoryWebAuthnPrincipalStore()
	store.Put(WebAuthnPrincipal{
		PrincipalType: "user",
		Subject:       "alice",
		DisplayName:   "Alice",
		Credentials: []webauthn.Credential{
			{ID: []byte("credential-1")},
		},
	})
	service, err := NewWebAuthnCeremonyService(&webauthn.Config{
		RPID:          "knox.example.net",
		RPDisplayName: "Knox",
		RPOrigins:     []string{"https://knox.example.net"},
	}, store, issuer)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := service.BeginLogin(Fido2BeginLoginRequest{
		PrincipalType: "user",
		Subject:       "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.SessionID == "" || len(resp.Options) == 0 {
		t.Fatalf("unexpected begin response: %+v", resp)
	}
}

func TestWebAuthnCeremonyFinishRejectsUnknownSession(t *testing.T) {
	issuer, err := auth.NewFido2TokenIssuer("knox-test", []byte("0123456789abcdef0123456789abcdef"), 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewWebAuthnCeremonyService(&webauthn.Config{
		RPID:          "knox.example.net",
		RPDisplayName: "Knox",
		RPOrigins:     []string{"https://knox.example.net"},
	}, NewInMemoryWebAuthnPrincipalStore(), issuer)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.FinishLogin(Fido2FinishLoginRequest{SessionID: "missing"})
	if err == nil {
		t.Fatal("expected unknown session to fail")
	}
}

func TestWebAuthnPrincipalStoreFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "principals.json")
	data := `[
  {
    "principal_type": "user",
    "subject": "alice",
    "display_name": "Alice",
    "groups": ["operators"],
    "user_handle": "AQID",
    "credentials": [{"id":"Y3JlZGVudGlhbC0x"}]
  }
]`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewWebAuthnPrincipalStoreFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := store.LookupWebAuthnPrincipal("user", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if principal.Subject != "alice" || len(principal.UserHandle) != 3 || len(principal.Credentials) != 1 {
		t.Fatalf("unexpected principal: %+v", principal)
	}
}
