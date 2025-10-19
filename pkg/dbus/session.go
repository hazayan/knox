package dbus

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
)

// Session represents a client session for encrypted communication.
type Session struct {
	id        string
	path      dbus.ObjectPath
	algorithm EncryptionAlgorithm
	key       []byte
	dh        *DHKeyExchange // Diffie-Hellman key exchange state
	mu        sync.RWMutex
	closed    bool
	createdAt time.Time
	lastUsed  time.Time
}

// NewSession creates a new session with the specified algorithm.
func NewSession(algorithm EncryptionAlgorithm) (*Session, []byte, error) {
	id, err := generateID()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	s := &Session{
		id:        id,
		path:      makeSessionPath(id),
		algorithm: algorithm,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
	}

	var output []byte

	switch algorithm {
	case AlgorithmPlain:
		// No encryption, no key exchange needed
		output = []byte{}
	case AlgorithmDHAES:
		// Perform Diffie-Hellman key exchange
		dh, err := NewDHKeyExchange()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to initialize DH: %w", err)
		}
		s.dh = dh

		// Return our public key for the client
		output = encodeDBusPublicKey(dh.GetPublicKey())
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	return s, output, nil
}

// Path returns the D-Bus object path for this session.
func (s *Session) Path() dbus.ObjectPath {
	return s.path
}

// Encrypt encrypts data using the session's algorithm and key.
func (s *Session) Encrypt(data []byte) ([]byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, nil, errors.New("session is closed")
	}

	// Update last used timestamp
	s.lastUsed = time.Now()

	switch s.algorithm {
	case AlgorithmPlain:
		// No encryption
		return []byte{}, data, nil
	case AlgorithmDHAES:
		if s.dh == nil {
			return nil, nil, errors.New("DH key exchange not completed")
		}

		key := s.dh.GetSharedKey()
		if key == nil {
			return nil, nil, errors.New("shared key not established")
		}

		// Encrypt using AES-128-CBC
		iv, ciphertext, err := encryptAES128CBC(key, data)
		if err != nil {
			return nil, nil, fmt.Errorf("encryption failed: %w", err)
		}

		// Return IV as parameters, ciphertext as value
		return iv, ciphertext, nil
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %s", s.algorithm)
	}
}

// Decrypt decrypts data using the session's algorithm and key.
func (s *Session) Decrypt(parameters, value []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, errors.New("session is closed")
	}

	// Update last used timestamp
	s.lastUsed = time.Now()

	switch s.algorithm {
	case AlgorithmPlain:
		// No decryption needed
		return value, nil
	case AlgorithmDHAES:
		if s.dh == nil {
			return nil, errors.New("DH key exchange not completed")
		}

		key := s.dh.GetSharedKey()
		if key == nil {
			return nil, errors.New("shared key not established")
		}

		// Decrypt using AES-128-CBC
		// parameters contains the IV, value contains the ciphertext
		plaintext, err := decryptAES128CBC(key, parameters, value)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: %w", err)
		}

		return plaintext, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", s.algorithm)
	}
}

// CompleteKeyExchange completes the DH key exchange with the client's public key.
func (s *Session) CompleteKeyExchange(clientPublicKey []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.algorithm != AlgorithmDHAES {
		return errors.New("key exchange only applicable for DH-AES algorithm")
	}

	if s.dh == nil {
		return errors.New("DH not initialized")
	}

	// Compute shared key using client's public key
	if err := s.dh.ComputeSharedKey(clientPublicKey); err != nil {
		return fmt.Errorf("failed to compute shared key: %w", err)
	}

	return nil
}

// Close closes the session.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closed = true

	// Clear sensitive data
	if s.key != nil {
		for i := range s.key {
			s.key[i] = 0
		}
		s.key = nil
	}

	// Clear DH state
	if s.dh != nil && s.dh.sharedKey != nil {
		for i := range s.dh.sharedKey {
			s.dh.sharedKey[i] = 0
		}
	}

	return nil
}

// Export exports the session to D-Bus.
func (s *Session) Export(conn *dbus.Conn) error {
	return conn.Export(s, s.path, SessionInterface)
}

// Unexport removes the session from D-Bus.
func (s *Session) Unexport(conn *dbus.Conn) {
	conn.Export(nil, s.path, SessionInterface)
}

// D-Bus methods

// Close is the D-Bus method for closing a session.
func (s *Session) CloseDBus() *dbus.Error {
	if err := s.Close(); err != nil {
		return dbus.MakeFailedError(err)
	}
	return nil
}

// Introspect returns XML introspection data.
func (s *Session) Introspect() *introspect.Node {
	return &introspect.Node{
		Interfaces: []introspect.Interface{
			{
				Name: SessionInterface,
				Methods: []introspect.Method{
					{
						Name: "Close",
					},
				},
			},
			introspect.IntrospectData,
		},
	}
}

// SessionManager manages active sessions.
type SessionManager struct {
	sessions       map[string]*Session
	mu             sync.RWMutex
	stopCleanup    chan struct{}
	cleanupDone    chan struct{}
	sessionMaxAge  time.Duration
	sessionMaxIdle time.Duration
}

// NewSessionManager creates a new session manager.
func NewSessionManager() *SessionManager {
	sm := &SessionManager{
		sessions:       make(map[string]*Session),
		stopCleanup:    make(chan struct{}),
		cleanupDone:    make(chan struct{}),
		sessionMaxAge:  1 * time.Hour,    // Sessions expire after 1 hour
		sessionMaxIdle: 15 * time.Minute, // Sessions expire after 15 minutes of inactivity
	}

	// Start background cleanup goroutine
	go sm.cleanupExpiredSessions()

	return sm
}

// cleanupExpiredSessions periodically removes expired sessions.
func (sm *SessionManager) cleanupExpiredSessions() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	defer close(sm.cleanupDone)

	for {
		select {
		case <-ticker.C:
			sm.removeExpiredSessions()
		case <-sm.stopCleanup:
			return
		}
	}
}

// removeExpiredSessions removes sessions that have expired.
func (sm *SessionManager) removeExpiredSessions() {
	now := time.Now()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	for id, session := range sm.sessions {
		session.mu.RLock()
		age := now.Sub(session.createdAt)
		idle := now.Sub(session.lastUsed)
		closed := session.closed
		session.mu.RUnlock()

		// Remove if closed, too old, or idle too long
		if closed || age > sm.sessionMaxAge || idle > sm.sessionMaxIdle {
			session.Close()
			delete(sm.sessions, id)
		}
	}
}

// CreateSession creates a new session.
func (sm *SessionManager) CreateSession(conn *dbus.Conn, algorithm EncryptionAlgorithm) (*Session, []byte, error) {
	session, output, err := NewSession(algorithm)
	if err != nil {
		return nil, nil, err
	}

	if err := session.Export(conn); err != nil {
		return nil, nil, fmt.Errorf("failed to export session: %w", err)
	}

	sm.mu.Lock()
	sm.sessions[session.id] = session
	sm.mu.Unlock()

	return session, output, nil
}

// GetSession retrieves a session by path.
func (sm *SessionManager) GetSession(path dbus.ObjectPath) (*Session, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Extract session ID from path
	id := string(path)[len(SessionPrefix):]

	session, ok := sm.sessions[id]
	if !ok {
		return nil, fmt.Errorf("session not found: %s", path)
	}

	return session, nil
}

// CloseSession closes and removes a session.
func (sm *SessionManager) CloseSession(conn *dbus.Conn, path dbus.ObjectPath) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Extract session ID from path
	id := string(path)[len(SessionPrefix):]

	session, ok := sm.sessions[id]
	if !ok {
		return fmt.Errorf("session not found: %s", path)
	}

	session.Unexport(conn)
	session.Close()
	delete(sm.sessions, id)

	return nil
}

// CloseAll closes all sessions and stops the cleanup goroutine.
func (sm *SessionManager) CloseAll(conn *dbus.Conn) {
	// Stop cleanup goroutine
	close(sm.stopCleanup)
	<-sm.cleanupDone

	sm.mu.Lock()
	defer sm.mu.Unlock()

	for id, session := range sm.sessions {
		session.Unexport(conn)
		session.Close()
		delete(sm.sessions, id)
	}
}

// generateID generates a random session ID.
func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
