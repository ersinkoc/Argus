package session

import "sync"

// TagStore holds custom metadata tags per session.
// Tags can be set by admin API, policies, or hooks.
type TagStore struct {
	mu   sync.RWMutex
	tags map[string]map[string]string // sessionID → key → value
}

// NewTagStore creates a tag store.
func NewTagStore() *TagStore {
	return &TagStore{
		tags: make(map[string]map[string]string),
	}
}

// Set sets a tag on a session.
func (ts *TagStore) Set(sessionID, key, value string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if _, ok := ts.tags[sessionID]; !ok {
		ts.tags[sessionID] = make(map[string]string)
	}
	ts.tags[sessionID][key] = value
}

// Get returns a tag value.
func (ts *TagStore) Get(sessionID, key string) (string, bool) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	tags, ok := ts.tags[sessionID]
	if !ok {
		return "", false
	}
	val, ok := tags[key]
	return val, ok
}

// All returns all tags for a session.
func (ts *TagStore) All(sessionID string) map[string]string {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	tags, ok := ts.tags[sessionID]
	if !ok {
		return nil
	}
	// Return a copy
	result := make(map[string]string, len(tags))
	for k, v := range tags {
		result[k] = v
	}
	return result
}

// Delete removes a tag.
func (ts *TagStore) Delete(sessionID, key string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if tags, ok := ts.tags[sessionID]; ok {
		delete(tags, key)
	}
}

// Cleanup removes all tags for a session (call on session close).
func (ts *TagStore) Cleanup(sessionID string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	delete(ts.tags, sessionID)
}

// Count returns the number of sessions with tags.
func (ts *TagStore) Count() int {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return len(ts.tags)
}
