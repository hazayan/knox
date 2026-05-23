package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/hazayan/knox/pkg/crypto"
)

func TestPeerUnlockServiceUnlocksFromConfiguredPeer(t *testing.T) {
	sharedKey := []byte("0123456789abcdef0123456789abcdef")
	masterKey, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatalf("generate master key: %v", err)
	}
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	source, err := NewPeerUnlockService(PeerUnlockConfig{
		Enabled:   true,
		NodeID:    "peer-a",
		SharedKey: sharedKey,
		TTL:       time.Minute,
		Peers:     []PeerUnlockPeer{{ID: "peer-b"}},
		Clock:     func() time.Time { return now },
		Nonce:     deterministicNonce,
	}, masterKey)
	if err != nil {
		t.Fatalf("source service: %v", err)
	}
	defer source.Close()

	router := mux.NewRouter()
	RegisterPeerUnlockRoutes(router, source)
	httpServer := httptest.NewServer(router)
	defer httpServer.Close()

	requester, err := NewPeerUnlockService(PeerUnlockConfig{
		Enabled:   true,
		NodeID:    "peer-b",
		SharedKey: sharedKey,
		TTL:       time.Minute,
		Peers:     []PeerUnlockPeer{{ID: "peer-a", URL: httpServer.URL}},
		Clock:     func() time.Time { return now },
		Nonce:     deterministicNonce,
	}, make([]byte, crypto.MasterKeyLen))
	if err != nil {
		t.Fatalf("requester service: %v", err)
	}
	defer requester.Close()

	unlocked, err := requester.UnlockFromPeers(context.Background())
	if err != nil {
		t.Fatalf("unlock from peer: %v", err)
	}
	defer clearBytes(unlocked)
	if string(unlocked) != string(masterKey) {
		t.Fatal("peer unlock returned the wrong master key")
	}
}

func TestPeerUnlockRejectsUnknownPeer(t *testing.T) {
	sharedKey := []byte("0123456789abcdef0123456789abcdef")
	masterKey, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatalf("generate master key: %v", err)
	}
	source, err := NewPeerUnlockService(PeerUnlockConfig{
		Enabled:   true,
		NodeID:    "peer-a",
		SharedKey: sharedKey,
		TTL:       time.Minute,
		Peers:     []PeerUnlockPeer{{ID: "peer-b"}},
	}, masterKey)
	if err != nil {
		t.Fatalf("source service: %v", err)
	}
	defer source.Close()

	request := PeerUnlockRequest{
		Version:   peerUnlockVersion,
		Requester: "peer-c",
		Nonce:     "nonce",
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Signature: "bad",
	}
	if err := source.validateRequest(request); err == nil {
		t.Fatal("expected unknown peer to be rejected")
	}
}

func TestPeerUnlockRejectsBadSignature(t *testing.T) {
	sharedKey := []byte("0123456789abcdef0123456789abcdef")
	masterKey, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatalf("generate master key: %v", err)
	}
	source, err := NewPeerUnlockService(PeerUnlockConfig{
		Enabled:   true,
		NodeID:    "peer-a",
		SharedKey: sharedKey,
		TTL:       time.Minute,
		Peers:     []PeerUnlockPeer{{ID: "peer-b"}},
	}, masterKey)
	if err != nil {
		t.Fatalf("source service: %v", err)
	}
	defer source.Close()

	request := PeerUnlockRequest{
		Version:   peerUnlockVersion,
		Requester: "peer-b",
		Nonce:     "nonce",
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Signature: "bad",
	}
	if err := source.validateRequest(request); err == nil {
		t.Fatal("expected bad signature to be rejected")
	}
}

func TestPeerUnlockRejectsReplay(t *testing.T) {
	sharedKey := []byte("0123456789abcdef0123456789abcdef")
	masterKey, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatalf("generate master key: %v", err)
	}
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	source, err := NewPeerUnlockService(PeerUnlockConfig{
		Enabled:   true,
		NodeID:    "peer-a",
		SharedKey: sharedKey,
		TTL:       time.Minute,
		Peers:     []PeerUnlockPeer{{ID: "peer-b"}},
		Clock:     func() time.Time { return now },
	}, masterKey)
	if err != nil {
		t.Fatalf("source service: %v", err)
	}
	defer source.Close()

	request := PeerUnlockRequest{
		Version:   peerUnlockVersion,
		Requester: "peer-b",
		Nonce:     "nonce",
		Timestamp: now.Format(time.RFC3339Nano),
	}
	request.Signature = source.signRequest(request)

	if err := source.validateRequest(request); err != nil {
		t.Fatalf("first request should pass: %v", err)
	}
	if err := source.validateRequest(request); err == nil {
		t.Fatal("expected replayed request to be rejected")
	}
}

func TestRegisterPeerUnlockRoutesSkipsNilService(t *testing.T) {
	router := mux.NewRouter()
	RegisterPeerUnlockRoutes(router, nil)
	req := httptest.NewRequest(http.MethodPost, "/v0/cluster/peer-unlock", nil)
	route := router.Match(req, &mux.RouteMatch{})
	if route {
		t.Fatal("nil peer unlock service should not register a route")
	}
}

func deterministicNonce(n int) ([]byte, error) {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i + 1)
	}
	return out, nil
}
