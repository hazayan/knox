package server

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/hazayan/knox/pkg/crypto"
)

const peerUnlockVersion = 1

type PeerUnlockPeer struct {
	ID  string
	URL string
}

type PeerUnlockConfig struct {
	Enabled    bool
	NodeID     string
	SharedKey  []byte
	TTL        time.Duration
	Peers      []PeerUnlockPeer
	HTTPClient *http.Client
	Clock      func() time.Time
	Nonce      func(int) ([]byte, error)
}

type PeerUnlockService struct {
	nodeID    string
	sharedKey []byte
	ttl       time.Duration
	peers     map[string]PeerUnlockPeer
	masterKey []byte
	client    *http.Client
	clock     func() time.Time
	nonce     func(int) ([]byte, error)
	seenMu    sync.Mutex
	seen      map[string]time.Time
}

type PeerUnlockRequest struct {
	Version   int    `json:"version"`
	Requester string `json:"requester"`
	Nonce     string `json:"nonce"`
	Timestamp string `json:"timestamp"`
	Signature string `json:"signature"`
}

type PeerUnlockResponse struct {
	Version          int    `json:"version"`
	Server           string `json:"server"`
	Requester        string `json:"requester"`
	RequestNonce     string `json:"request_nonce"`
	ResponseNonce    string `json:"response_nonce"`
	ExpiresAt        string `json:"expires_at"`
	WrappedMasterKey string `json:"wrapped_master_key"`
}

func NewPeerUnlockService(cfg PeerUnlockConfig, masterKey []byte) (*PeerUnlockService, error) {
	if !cfg.Enabled {
		return nil, errors.New("peer unlock is disabled")
	}
	nodeID := strings.TrimSpace(cfg.NodeID)
	if nodeID == "" {
		return nil, errors.New("peer unlock node_id is required")
	}
	if len(masterKey) != crypto.MasterKeyLen {
		return nil, fmt.Errorf("peer unlock master key must be %d bytes", crypto.MasterKeyLen)
	}
	if len(cfg.SharedKey) < 32 {
		return nil, errors.New("peer unlock shared key must contain at least 32 bytes")
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	peers := make(map[string]PeerUnlockPeer, len(cfg.Peers))
	for _, peer := range cfg.Peers {
		peer.ID = strings.TrimSpace(peer.ID)
		peer.URL = strings.TrimRight(strings.TrimSpace(peer.URL), "/")
		if peer.ID == "" {
			return nil, errors.New("peer unlock peer id is required")
		}
		if peer.ID == nodeID {
			continue
		}
		peers[peer.ID] = peer
	}
	if len(peers) == 0 {
		return nil, errors.New("peer unlock requires at least one peer")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	nonce := cfg.Nonce
	if nonce == nil {
		nonce = randomBytes
	}
	masterCopy := make([]byte, len(masterKey))
	copy(masterCopy, masterKey)
	sharedCopy := make([]byte, len(cfg.SharedKey))
	copy(sharedCopy, cfg.SharedKey)
	return &PeerUnlockService{
		nodeID:    nodeID,
		sharedKey: sharedCopy,
		ttl:       ttl,
		peers:     peers,
		masterKey: masterCopy,
		client:    client,
		clock:     clock,
		nonce:     nonce,
		seen:      map[string]time.Time{},
	}, nil
}

func (s *PeerUnlockService) Close() {
	clearBytes(s.masterKey)
	clearBytes(s.sharedKey)
}

func RegisterPeerUnlockRoutes(router *mux.Router, service *PeerUnlockService) {
	if service == nil {
		return
	}
	router.HandleFunc("/v0/cluster/peer-unlock", service.handlePeerUnlock).Methods(http.MethodPost)
}

func (s *PeerUnlockService) UnlockFromPeers(ctx context.Context) ([]byte, error) {
	var lastErr error
	for _, peer := range s.peers {
		if peer.URL == "" {
			continue
		}
		key, err := s.unlockFromPeer(ctx, peer)
		if err == nil {
			return key, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no peer unlock URLs configured")
	}
	return nil, lastErr
}

func (s *PeerUnlockService) unlockFromPeer(ctx context.Context, peer PeerUnlockPeer) ([]byte, error) {
	reqNonce, err := s.nonce(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate peer unlock nonce: %w", err)
	}
	timestamp := s.clock().UTC().Format(time.RFC3339Nano)
	request := PeerUnlockRequest{
		Version:   peerUnlockVersion,
		Requester: s.nodeID,
		Nonce:     base64.RawURLEncoding.EncodeToString(reqNonce),
		Timestamp: timestamp,
	}
	request.Signature = s.signRequest(request)
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, peer.URL+"/v0/cluster/peer-unlock", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("peer %s unlock request failed: %w", peer.ID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("peer %s refused unlock: status=%d body=%s", peer.ID, resp.StatusCode, strings.TrimSpace(string(limited)))
	}
	var response PeerUnlockResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode peer %s unlock response: %w", peer.ID, err)
	}
	return s.decryptResponse(request, response)
}

func (s *PeerUnlockService) handlePeerUnlock(w http.ResponseWriter, r *http.Request) {
	var req PeerUnlockRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "invalid peer unlock request", http.StatusBadRequest)
		return
	}
	if err := s.validateRequest(req); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	respNonce, err := s.nonce(12)
	if err != nil {
		http.Error(w, "failed to generate peer unlock response", http.StatusInternalServerError)
		return
	}
	expiresAt := s.clock().UTC().Add(s.ttl).Format(time.RFC3339Nano)
	ad := responseAAD(req.Requester, req.Nonce, expiresAt)
	wrapped, err := encryptForPeer(s.sharedKey, s.masterKey, respNonce, ad)
	if err != nil {
		http.Error(w, "failed to wrap peer unlock response", http.StatusInternalServerError)
		return
	}
	response := PeerUnlockResponse{
		Version:          peerUnlockVersion,
		Server:           s.nodeID,
		Requester:        req.Requester,
		RequestNonce:     req.Nonce,
		ResponseNonce:    base64.RawURLEncoding.EncodeToString(respNonce),
		ExpiresAt:        expiresAt,
		WrappedMasterKey: base64.RawURLEncoding.EncodeToString(wrapped),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (s *PeerUnlockService) validateRequest(req PeerUnlockRequest) error {
	if req.Version != peerUnlockVersion {
		return errors.New("unsupported peer unlock request version")
	}
	if _, ok := s.peers[req.Requester]; !ok {
		return errors.New("requester is not a configured peer")
	}
	if req.Nonce == "" || req.Timestamp == "" || req.Signature == "" {
		return errors.New("peer unlock request is incomplete")
	}
	ts, err := time.Parse(time.RFC3339Nano, req.Timestamp)
	if err != nil {
		return errors.New("peer unlock timestamp is invalid")
	}
	now := s.clock().UTC()
	if ts.Before(now.Add(-s.ttl)) || ts.After(now.Add(s.ttl)) {
		return errors.New("peer unlock timestamp is outside the allowed window")
	}
	expected := s.signRequest(req)
	if !hmac.Equal([]byte(expected), []byte(req.Signature)) {
		return errors.New("peer unlock signature is invalid")
	}
	if !s.markNonce(req.Requester, req.Nonce, now.Add(s.ttl)) {
		return errors.New("peer unlock request nonce was already used")
	}
	return nil
}

func (s *PeerUnlockService) markNonce(requester, nonce string, expiresAt time.Time) bool {
	key := requester + "\x00" + nonce
	s.seenMu.Lock()
	defer s.seenMu.Unlock()
	now := s.clock().UTC()
	for seen, expiry := range s.seen {
		if !now.Before(expiry) {
			delete(s.seen, seen)
		}
	}
	if _, exists := s.seen[key]; exists {
		return false
	}
	s.seen[key] = expiresAt
	return true
}

func (s *PeerUnlockService) signRequest(req PeerUnlockRequest) string {
	mac := hmac.New(sha256.New, s.sharedKey)
	_, _ = mac.Write([]byte(req.Requester))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(req.Nonce))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(req.Timestamp))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *PeerUnlockService) decryptResponse(request PeerUnlockRequest, response PeerUnlockResponse) ([]byte, error) {
	if response.Version != peerUnlockVersion {
		return nil, errors.New("unsupported peer unlock response version")
	}
	if response.Requester != s.nodeID || response.RequestNonce != request.Nonce {
		return nil, errors.New("peer unlock response does not match request")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, response.ExpiresAt)
	if err != nil {
		return nil, errors.New("peer unlock response expiry is invalid")
	}
	if !s.clock().UTC().Before(expiresAt) {
		return nil, errors.New("peer unlock response expired")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(response.ResponseNonce)
	if err != nil {
		return nil, fmt.Errorf("invalid peer unlock response nonce: %w", err)
	}
	wrapped, err := base64.RawURLEncoding.DecodeString(response.WrappedMasterKey)
	if err != nil {
		return nil, fmt.Errorf("invalid peer unlock wrapped master key: %w", err)
	}
	ad := responseAAD(response.Requester, response.RequestNonce, response.ExpiresAt)
	masterKey, err := decryptFromPeer(s.sharedKey, wrapped, nonce, ad)
	if err != nil {
		return nil, err
	}
	if len(masterKey) != crypto.MasterKeyLen {
		clearBytes(masterKey)
		return nil, fmt.Errorf("peer unlock returned invalid master key length: %d", len(masterKey))
	}
	return masterKey, nil
}

func responseAAD(requester, nonce, expiresAt string) []byte {
	return []byte(requester + "\x00" + nonce + "\x00" + expiresAt)
}

func encryptForPeer(sharedKey, plaintext, nonce, ad []byte) ([]byte, error) {
	gcm, err := peerUnlockGCM(sharedKey)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, ad), nil
}

func decryptFromPeer(sharedKey, ciphertext, nonce, ad []byte) ([]byte, error) {
	gcm, err := peerUnlockGCM(sharedKey)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, ad)
}

func peerUnlockGCM(sharedKey []byte) (cipher.AEAD, error) {
	sum := sha256.Sum256(append([]byte("knox peer unlock v1:"), sharedKey...))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func randomBytes(n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func clearBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
