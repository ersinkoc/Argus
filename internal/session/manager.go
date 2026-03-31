package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"
)

// Session represents an active client session.
type Session struct {
	ID            string
	Username      string
	Database      string
	ClientIP      net.IP
	Roles         []string
	AuthMethod    string
	StartTime     time.Time
	LastActivity  time.Time
	CommandCount  int64
	BytesIn       int64
	BytesOut      int64
	ClientConn    net.Conn
	BackendConn   net.Conn
	Parameters    map[string]string

	mu sync.Mutex
}

// Touch updates the last activity timestamp.
func (s *Session) Touch() {
	s.mu.Lock()
	s.LastActivity = time.Now()
	s.mu.Unlock()
}

// IncrementCommand increments the command counter.
func (s *Session) IncrementCommand() {
	s.mu.Lock()
	s.CommandCount++
	s.LastActivity = time.Now()
	s.mu.Unlock()
}

// AddBytes records bytes transferred.
func (s *Session) AddBytes(in, out int64) {
	s.mu.Lock()
	s.BytesIn += in
	s.BytesOut += out
	s.mu.Unlock()
}

// Stats returns a snapshot of the session's mutable counters.
func (s *Session) Stats() (commandCount, bytesIn, bytesOut int64) {
	s.mu.Lock()
	commandCount = s.CommandCount
	bytesIn = s.BytesIn
	bytesOut = s.BytesOut
	s.mu.Unlock()
	return
}

// Duration returns how long the session has been active.
func (s *Session) Duration() time.Duration {
	return time.Since(s.StartTime)
}

// IdleDuration returns how long since the last activity.
func (s *Session) IdleDuration() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.LastActivity)
}

// Manager manages active sessions.
type Manager struct {
	sessions      sync.Map // sessionID → *Session
	idleTimeout   time.Duration
	maxDuration   time.Duration
	checkInterval time.Duration
	onTimeout     func(*Session, string)
	stopCh        chan struct{}
	wg            sync.WaitGroup
}

// NewManager creates a new session manager.
func NewManager(idleTimeout, maxDuration time.Duration) *Manager {
	return &Manager{
		idleTimeout:   idleTimeout,
		maxDuration:   maxDuration,
		checkInterval: 30 * time.Second,
		stopCh:        make(chan struct{}),
	}
}

// OnTimeout sets a callback for session timeout events.
// The string argument is the reason: "idle_timeout" or "max_duration".
func (m *Manager) OnTimeout(fn func(*Session, string)) {
	m.onTimeout = fn
}

// Start begins the background timeout checker.
func (m *Manager) Start() {
	m.wg.Add(1)
	go m.timeoutLoop()
}

// Stop stops the timeout checker.
func (m *Manager) Stop() {
	close(m.stopCh)
	m.wg.Wait()
}

// Create creates a new session from connection info.
func (m *Manager) Create(info *Info, clientConn net.Conn) *Session {
	now := time.Now()
	s := &Session{
		ID:           generateSessionID(),
		Username:     info.Username,
		Database:     info.Database,
		ClientIP:     info.ClientIP,
		AuthMethod:   info.AuthMethod,
		Parameters:   info.Parameters,
		StartTime:    now,
		LastActivity: now,
		ClientConn:   clientConn,
	}
	m.sessions.Store(s.ID, s)
	return s
}

// Get returns a session by ID.
func (m *Manager) Get(id string) *Session {
	v, ok := m.sessions.Load(id)
	if !ok {
		return nil
	}
	return v.(*Session)
}

// Remove removes a session.
func (m *Manager) Remove(id string) {
	m.sessions.Delete(id)
}

// Kill closes a session's connections and removes it.
func (m *Manager) Kill(id string) error {
	s := m.Get(id)
	if s == nil {
		return fmt.Errorf("session %q not found", id)
	}
	if s.ClientConn != nil {
		s.ClientConn.Close()
	}
	if s.BackendConn != nil {
		s.BackendConn.Close()
	}
	m.Remove(id)
	return nil
}

// ActiveSessions returns all active sessions.
func (m *Manager) ActiveSessions() []*Session {
	var sessions []*Session
	m.sessions.Range(func(_, v any) bool {
		sessions = append(sessions, v.(*Session))
		return true
	})
	return sessions
}

// Count returns the number of active sessions.
func (m *Manager) Count() int {
	count := 0
	m.sessions.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

func (m *Manager) timeoutLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.checkTimeouts()
		case <-m.stopCh:
			return
		}
	}
}

func (m *Manager) checkTimeouts() {
	m.sessions.Range(func(key, value any) bool {
		s := value.(*Session)

		timedOut := false
		reason := ""

		if m.idleTimeout > 0 && s.IdleDuration() > m.idleTimeout {
			timedOut = true
			reason = "idle_timeout"
		}
		if m.maxDuration > 0 && s.Duration() > m.maxDuration {
			timedOut = true
			reason = "max_duration"
		}

		if timedOut {
			if m.onTimeout != nil {
				m.onTimeout(s, reason)
			}
			if s.ClientConn != nil {
				s.ClientConn.Close()
			}
			if s.BackendConn != nil {
				s.BackendConn.Close()
			}
			m.sessions.Delete(key)
		}
		return true
	})
}

func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
