package cluster

import (
	"log/slog"
	"time"

	"github.com/ersinkoc/argus/internal/session"
)

// SessionMirror mirrors session lifecycle events into a shared Store so that
// other Argus instances can see sessions owned by this node.
//
// It implements session.Observer: register it with
// Manager.SetObserver(NewSessionMirror(nodeID, store, ttl)).
//
// When ttl > 0, entries expire from the store unless refreshed; the session
// manager refreshes every live session once per check interval (default 30s),
// so ttl should comfortably exceed that interval (e.g. 2m). A positive ttl
// keeps the cluster view clean if a node crashes without deleting its
// entries. ttl = 0 means entries never expire and are removed only on
// session close.
type SessionMirror struct {
	nodeID string
	store  Store
	ttl    time.Duration
}

// NewSessionMirror creates a mirror that writes sessions owned by nodeID
// into store with the given TTL.
func NewSessionMirror(nodeID string, store Store, ttl time.Duration) *SessionMirror {
	return &SessionMirror{nodeID: nodeID, store: store, ttl: ttl}
}

// SessionCreated stores a new session entry.
func (m *SessionMirror) SessionCreated(s *session.Session) {
	m.put(s)
}

// SessionAlive refreshes the entry (and its TTL) for a live session.
func (m *SessionMirror) SessionAlive(s *session.Session) {
	m.put(s)
}

// SessionRemoved deletes the session entry.
func (m *SessionMirror) SessionRemoved(id string) {
	if err := m.store.Delete(id); err != nil {
		slog.Warn("cluster store delete failed", "session_id", id, "error", err)
	}
}

func (m *SessionMirror) put(s *session.Session) {
	commandCount, _, _ := s.Stats()
	clientIP := ""
	if s.ClientIP != nil {
		clientIP = s.ClientIP.String()
	}
	entry := &SessionEntry{
		ID:           s.ID,
		Username:     s.Username,
		Database:     s.Database,
		ClientIP:     clientIP,
		Roles:        s.RolesCopy(),
		NodeID:       m.nodeID,
		StartTime:    s.StartTime,
		LastActivity: s.LastActivityTime(),
		CommandCount: commandCount,
	}
	if err := m.store.Put(s.ID, entry, m.ttl); err != nil {
		slog.Warn("cluster store put failed", "session_id", s.ID, "error", err)
	}
}
