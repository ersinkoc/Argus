package session

import "sync"

// ConcurrencyLimiter limits the number of concurrent sessions per user.
type ConcurrencyLimiter struct {
	mu       sync.RWMutex
	counts   map[string]int
	maxPerUser int
}

// NewConcurrencyLimiter creates a limiter with the given max sessions per user.
// Set maxPerUser to 0 for unlimited.
func NewConcurrencyLimiter(maxPerUser int) *ConcurrencyLimiter {
	return &ConcurrencyLimiter{
		counts:     make(map[string]int),
		maxPerUser: maxPerUser,
	}
}

// Acquire tries to acquire a session slot for the user.
// Returns true if allowed, false if limit reached.
func (l *ConcurrencyLimiter) Acquire(username string) bool {
	if l.maxPerUser <= 0 {
		return true // unlimited
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.counts[username] >= l.maxPerUser {
		return false
	}
	l.counts[username]++
	return true
}

// Release releases a session slot for the user.
func (l *ConcurrencyLimiter) Release(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.counts[username] > 0 {
		l.counts[username]--
		if l.counts[username] == 0 {
			delete(l.counts, username)
		}
	}
}

// Count returns the current session count for a user.
func (l *ConcurrencyLimiter) Count(username string) int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.counts[username]
}

// AllCounts returns session counts for all users.
func (l *ConcurrencyLimiter) AllCounts() map[string]int {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make(map[string]int, len(l.counts))
	for k, v := range l.counts {
		result[k] = v
	}
	return result
}
