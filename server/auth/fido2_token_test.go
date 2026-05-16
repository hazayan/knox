package auth

import (
	"strings"
	"testing"
	"time"
)

func testFido2Issuer(t *testing.T) *Fido2TokenIssuer {
	t.Helper()
	issuer, err := NewFido2TokenIssuer("knox-test", []byte("0123456789abcdef0123456789abcdef"), 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0).UTC()
	issuer.now = func() time.Time { return now }
	return issuer
}

func TestFido2TokenIssuerRejectsShortKey(t *testing.T) {
	_, err := NewFido2TokenIssuer("knox-test", []byte("short"), time.Minute)
	if err == nil {
		t.Fatal("expected short key to fail")
	}
}

func TestFido2TokenProviderAuthenticatesUserToken(t *testing.T) {
	issuer := testFido2Issuer(t)
	token, expires, err := issuer.MintUserToken("alice", []string{"operators"})
	if err != nil {
		t.Fatal(err)
	}
	if !expires.Equal(time.Unix(1000, 0).UTC().Add(15 * time.Minute)) {
		t.Fatalf("unexpected expiry: %s", expires)
	}

	provider := NewFido2TokenProvider(issuer)
	principal, err := provider.Authenticate(token, nil)
	if err != nil {
		t.Fatal(err)
	}
	if principal.GetID() != "alice" || principal.Type() != "user" {
		t.Fatalf("unexpected principal: %s %s", principal.Type(), principal.GetID())
	}
}

func TestFido2TokenProviderAuthenticatesMachineToken(t *testing.T) {
	issuer := testFido2Issuer(t)
	token, _, err := issuer.MintMachineToken("builder-node")
	if err != nil {
		t.Fatal(err)
	}

	principal, err := NewFido2TokenProvider(issuer).Authenticate(token, nil)
	if err != nil {
		t.Fatal(err)
	}
	if principal.GetID() != "builder-node" || principal.Type() != "machine" {
		t.Fatalf("unexpected principal: %s %s", principal.Type(), principal.GetID())
	}
}

func TestFido2TokenProviderRejectsTamperedToken(t *testing.T) {
	issuer := testFido2Issuer(t)
	token, _, err := issuer.MintUserToken("alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	parts[0] = strings.TrimRight(parts[0], "A") + "A"

	_, err = NewFido2TokenProvider(issuer).Authenticate(strings.Join(parts, "."), nil)
	if err == nil {
		t.Fatal("expected tampered token to fail")
	}
}

func TestFido2TokenProviderRejectsExpiredToken(t *testing.T) {
	issuer := testFido2Issuer(t)
	token, _, err := issuer.MintUserToken("alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	issuer.now = func() time.Time { return time.Unix(1000, 0).UTC().Add(16 * time.Minute) }

	_, err = NewFido2TokenProvider(issuer).Authenticate(token, nil)
	if err == nil {
		t.Fatal("expected expired token to fail")
	}
}
