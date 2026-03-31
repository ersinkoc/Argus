package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// AllowlistEntryType determines how an allowlist entry is consumed.
type AllowlistEntryType int

const (
	AllowlistOneTime    AllowlistEntryType = iota // consumed on first use
	AllowlistTimeWindow                           // valid until ExpiresAt
)

// AllowlistEntry is a pre-approved query authorization.
// Created when an admin approves a gateway query.
type AllowlistEntry struct {
	ID          string             `json:"id"`
	Fingerprint string             `json:"fingerprint"`
	Username    string             `json:"username"`
	Database    string             `json:"database"`
	Type        AllowlistEntryType `json:"type"`
	CreatedAt   time.Time          `json:"created_at"`
	ExpiresAt   time.Time          `json:"expires_at,omitempty"`
	CreatedBy   string             `json:"created_by"`
	ApprovalID  string             `json:"approval_id,omitempty"`
	Used        bool               `json:"used"`
}

// Allowlist manages pre-approved query authorizations keyed by fingerprint+username+database.
type Allowlist struct {
	mu      sync.RWMutex
	entries map[string]*AllowlistEntry // compositeKey -> entry
	byID    map[string]*AllowlistEntry // id -> entry
}

// NewAllowlist creates an empty allowlist.
func NewAllowlist() *Allowlist {
	return &Allowlist{
		entries: make(map[string]*AllowlistEntry),
		byID:    make(map[string]*AllowlistEntry),
	}
}

// compositeKey builds the lookup key from fingerprint+username+database.
func compositeKey(fingerprint, username, database string) string {
	return fingerprint + "|" + username + "|" + database
}

// Check returns a valid entry if one exists for the given query context.
// For ONE_TIME entries, the entry is marked as used (consumed).
// Returns nil if no valid entry exists.
func (a *Allowlist) Check(fingerprint, username, database string) *AllowlistEntry {
	key := compositeKey(fingerprint, username, database)

	a.mu.Lock()
	defer a.mu.Unlock()

	entry, ok := a.entries[key]
	if !ok {
		return nil
	}

	// Check expiry
	if !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
		delete(a.entries, key)
		delete(a.byID, entry.ID)
		return nil
	}

	// Check if already used (one-time)
	if entry.Type == AllowlistOneTime && entry.Used {
		delete(a.entries, key)
		delete(a.byID, entry.ID)
		return nil
	}

	// Consume one-time entry
	if entry.Type == AllowlistOneTime {
		entry.Used = true
		// Remove after consumption
		delete(a.entries, key)
		delete(a.byID, entry.ID)
	}

	return entry
}

// Peek checks if a valid entry exists without consuming it.
// Unlike Check(), this never modifies state — safe for dry-run previews.
func (a *Allowlist) Peek(fingerprint, username, database string) *AllowlistEntry {
	key := compositeKey(fingerprint, username, database)

	a.mu.RLock()
	defer a.mu.RUnlock()

	entry, ok := a.entries[key]
	if !ok {
		return nil
	}
	if !entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt) {
		return nil
	}
	if entry.Type == AllowlistOneTime && entry.Used {
		return nil
	}
	return entry
}

// Add creates a new allowlist entry. Returns the generated ID.
func (a *Allowlist) Add(entry *AllowlistEntry) string {
	if entry.ID == "" {
		b := make([]byte, 8)
		rand.Read(b)
		entry.ID = hex.EncodeToString(b)
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now()
	}

	key := compositeKey(entry.Fingerprint, entry.Username, entry.Database)

	a.mu.Lock()
	defer a.mu.Unlock()

	a.entries[key] = entry
	a.byID[entry.ID] = entry
	return entry.ID
}

// Remove deletes an entry by ID.
func (a *Allowlist) Remove(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	entry, ok := a.byID[id]
	if !ok {
		return false
	}

	key := compositeKey(entry.Fingerprint, entry.Username, entry.Database)
	delete(a.entries, key)
	delete(a.byID, id)
	return true
}

// List returns all active (non-expired, non-used) entries.
func (a *Allowlist) List() []*AllowlistEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()

	now := time.Now()
	result := make([]*AllowlistEntry, 0, len(a.entries))
	for _, entry := range a.entries {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			continue
		}
		if entry.Type == AllowlistOneTime && entry.Used {
			continue
		}
		result = append(result, entry)
	}
	return result
}

// Cleanup removes expired and consumed entries. Call periodically.
func (a *Allowlist) Cleanup() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	removed := 0
	for key, entry := range a.entries {
		expired := !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt)
		consumed := entry.Type == AllowlistOneTime && entry.Used
		if expired || consumed {
			delete(a.entries, key)
			delete(a.byID, entry.ID)
			removed++
		}
	}
	return removed
}

// Count returns the number of active entries.
func (a *Allowlist) Count() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.entries)
}
