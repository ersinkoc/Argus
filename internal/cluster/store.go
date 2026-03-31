package cluster

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// SessionEntry represents a session in the shared store.
type SessionEntry struct {
	ID           string            `json:"id"`
	Username     string            `json:"username"`
	Database     string            `json:"database"`
	ClientIP     string            `json:"client_ip"`
	Roles        []string          `json:"roles"`
	NodeID       string            `json:"node_id"` // which Argus instance owns this session
	StartTime    time.Time         `json:"start_time"`
	LastActivity time.Time         `json:"last_activity"`
	CommandCount int64             `json:"command_count"`
	Tags         map[string]string `json:"tags,omitempty"`
}

// Store is the interface for shared session storage.
// Can be backed by in-memory (single instance) or external store (Redis, etcd).
type Store interface {
	// Put stores a session entry with TTL.
	Put(id string, entry *SessionEntry, ttl time.Duration) error

	// Get retrieves a session entry.
	Get(id string) (*SessionEntry, error)

	// Delete removes a session entry.
	Delete(id string) error

	// List returns all sessions, optionally filtered by node.
	List(nodeFilter string) ([]*SessionEntry, error)

	// Touch updates last activity timestamp.
	Touch(id string) error

	// Close closes the store connection.
	Close() error
}

// MemoryStore implements Store with in-memory map (single instance).
type MemoryStore struct {
	mu      sync.RWMutex
	entries map[string]*storeEntry
}

type storeEntry struct {
	session *SessionEntry
	expiry  time.Time
}

// NewMemoryStore creates an in-memory store.
func NewMemoryStore() *MemoryStore {
	s := &MemoryStore{
		entries: make(map[string]*storeEntry),
	}
	return s
}

func (s *MemoryStore) Put(id string, entry *SessionEntry, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	expiry := time.Time{}
	if ttl > 0 {
		expiry = time.Now().Add(ttl)
	}

	data, _ := json.Marshal(entry)
	var stored SessionEntry
	json.Unmarshal(data, &stored)

	s.entries[id] = &storeEntry{session: &stored, expiry: expiry}
	return nil
}

func (s *MemoryStore) Get(id string) (*SessionEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.entries[id]
	if !ok {
		return nil, fmt.Errorf("session %q not found", id)
	}

	if !entry.expiry.IsZero() && time.Now().After(entry.expiry) {
		return nil, fmt.Errorf("session %q expired", id)
	}

	return entry.session, nil
}

func (s *MemoryStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, id)
	return nil
}

func (s *MemoryStore) List(nodeFilter string) ([]*SessionEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*SessionEntry
	now := time.Now()

	for _, entry := range s.entries {
		if !entry.expiry.IsZero() && now.After(entry.expiry) {
			continue
		}
		if nodeFilter != "" && entry.session.NodeID != nodeFilter {
			continue
		}
		result = append(result, entry.session)
	}

	return result, nil
}

func (s *MemoryStore) Touch(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[id]
	if !ok {
		return fmt.Errorf("session %q not found", id)
	}

	entry.session.LastActivity = time.Now()
	return nil
}

func (s *MemoryStore) Close() error {
	return nil
}

// Count returns the number of stored sessions.
func (s *MemoryStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// NodeInfo represents a cluster node.
type NodeInfo struct {
	ID        string    `json:"id"`
	Address   string    `json:"address"`
	StartTime time.Time `json:"start_time"`
	Sessions  int       `json:"sessions"`
	Healthy   bool      `json:"healthy"`
}

// ClusterManager coordinates multiple Argus instances.
type ClusterManager struct {
	nodeID string
	store  Store
	nodes  map[string]*NodeInfo
	mu     sync.RWMutex
}

// NewClusterManager creates a cluster manager.
func NewClusterManager(nodeID string, store Store) *ClusterManager {
	return &ClusterManager{
		nodeID: nodeID,
		store:  store,
		nodes:  make(map[string]*NodeInfo),
	}
}

// NodeID returns this node's ID.
func (cm *ClusterManager) NodeID() string {
	return cm.nodeID
}

// RegisterNode registers this node in the cluster.
func (cm *ClusterManager) RegisterNode(address string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.nodes[cm.nodeID] = &NodeInfo{
		ID:        cm.nodeID,
		Address:   address,
		StartTime: time.Now(),
		Healthy:   true,
	}
}

// Nodes returns all known nodes.
func (cm *ClusterManager) Nodes() []*NodeInfo {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	result := make([]*NodeInfo, 0, len(cm.nodes))
	for _, n := range cm.nodes {
		result = append(result, n)
	}
	return result
}

// ClusterSessions returns sessions across all nodes.
func (cm *ClusterManager) ClusterSessions() ([]*SessionEntry, error) {
	return cm.store.List("")
}
