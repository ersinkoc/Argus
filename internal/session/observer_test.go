package session

import (
	"sync"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/testutil"
)

type recordingObserver struct {
	mu      sync.Mutex
	created []string
	alive   []string
	removed []string
}

func (o *recordingObserver) SessionCreated(s *Session) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.created = append(o.created, s.ID)
}

func (o *recordingObserver) SessionAlive(s *Session) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.alive = append(o.alive, s.ID)
}

func (o *recordingObserver) SessionRemoved(id string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.removed = append(o.removed, id)
}

func (o *recordingObserver) counts() (created, alive, removed int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.created), len(o.alive), len(o.removed)
}

func TestObserverCreateAndRemove(t *testing.T) {
	obs := &recordingObserver{}
	m := NewManager(0, 0)
	m.SetObserver(obs)

	sess := m.Create(&Info{Username: "alice"}, nil)
	if created, _, _ := obs.counts(); created != 1 {
		t.Fatalf("created = %d, want 1", created)
	}

	m.Remove(sess.ID)
	if _, _, removed := obs.counts(); removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}

	// Removing an unknown session must not notify again.
	m.Remove(sess.ID)
	if _, _, removed := obs.counts(); removed != 1 {
		t.Fatalf("removed after duplicate = %d, want 1", removed)
	}
}

func TestObserverAliveOnCheckInterval(t *testing.T) {
	obs := &recordingObserver{}
	m := NewManager(0, 0)
	m.SetObserver(obs)
	m.SetCheckInterval(5 * time.Millisecond)

	m.Create(&Info{Username: "bob"}, nil)
	m.Start()
	defer m.Stop()

	testutil.WaitFor(t, time.Second, func() bool {
		_, alive, _ := obs.counts()
		return alive >= 2
	}, "observer should receive periodic SessionAlive notifications")
}

func TestObserverNotifiedOnTimeout(t *testing.T) {
	obs := &recordingObserver{}
	m := NewManager(time.Nanosecond, 0)
	m.SetObserver(obs)
	m.SetCheckInterval(5 * time.Millisecond)

	m.Create(&Info{Username: "carol"}, nil)
	m.Start()
	defer m.Stop()

	testutil.WaitFor(t, time.Second, func() bool {
		_, _, removed := obs.counts()
		return removed == 1
	}, "idle timeout should notify SessionRemoved")
	if m.Count() != 0 {
		t.Fatalf("count = %d, want 0", m.Count())
	}
}

func TestSessionRolesAccessors(t *testing.T) {
	s := &Session{}
	if roles := s.RolesCopy(); len(roles) != 0 {
		t.Fatalf("initial roles = %v, want empty", roles)
	}

	s.SetRoles([]string{"dba", "analyst"})
	got := s.RolesCopy()
	if len(got) != 2 || got[0] != "dba" || got[1] != "analyst" {
		t.Fatalf("roles = %v, want [dba analyst]", got)
	}

	// The copy must be independent of the session's slice.
	got[0] = "mutated"
	if s.RolesCopy()[0] != "dba" {
		t.Fatal("RolesCopy should return an independent copy")
	}
}

func TestSessionLastActivityTime(t *testing.T) {
	now := time.Now()
	s := &Session{LastActivity: now}
	if got := s.LastActivityTime(); !got.Equal(now) {
		t.Fatalf("LastActivityTime = %v, want %v", got, now)
	}

	s.Touch()
	if got := s.LastActivityTime(); got.Before(now) {
		t.Fatalf("LastActivityTime after Touch = %v, should not be before %v", got, now)
	}
}
