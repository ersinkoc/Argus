package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ersinkoc/argus/internal/cluster"
)

type fakeClusterProvider struct {
	sessions []*cluster.SessionEntry
	err      error
}

func (f *fakeClusterProvider) NodeID() string { return "node-1" }
func (f *fakeClusterProvider) Nodes() []*cluster.NodeInfo {
	return []*cluster.NodeInfo{{ID: "node-1", Address: ":9090", Healthy: true}}
}
func (f *fakeClusterProvider) ClusterSessions() ([]*cluster.SessionEntry, error) {
	return f.sessions, f.err
}

func TestHandleClusterDisabled(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/api/cluster", nil)
	w := httptest.NewRecorder()
	s.handleCluster(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleClusterMethodNotAllowed(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetClusterProvider(&fakeClusterProvider{})

	req := httptest.NewRequest("POST", "/api/cluster", nil)
	w := httptest.NewRecorder()
	s.handleCluster(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHandleClusterStoreError(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetClusterProvider(&fakeClusterProvider{err: fmt.Errorf("store down")})

	req := httptest.NewRequest("GET", "/api/cluster", nil)
	w := httptest.NewRecorder()
	s.handleCluster(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestHandleClusterSuccess(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetClusterProvider(&fakeClusterProvider{
		sessions: []*cluster.SessionEntry{{ID: "abc", Username: "alice", NodeID: "node-1"}},
	})

	req := httptest.NewRequest("GET", "/api/cluster", nil)
	w := httptest.NewRecorder()
	s.handleCluster(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var resp struct {
		NodeID   string                  `json:"node_id"`
		Nodes    []*cluster.NodeInfo     `json:"nodes"`
		Sessions []*cluster.SessionEntry `json:"sessions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if resp.NodeID != "node-1" || len(resp.Nodes) != 1 || len(resp.Sessions) != 1 {
		t.Fatalf("resp = %+v, want node-1 with 1 node and 1 session", resp)
	}
	if resp.Sessions[0].Username != "alice" {
		t.Fatalf("session username = %q, want alice", resp.Sessions[0].Username)
	}
}

func TestHandleClusterEmptySessionsIsArray(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetClusterProvider(&fakeClusterProvider{})

	req := httptest.NewRequest("GET", "/api/cluster", nil)
	w := httptest.NewRecorder()
	s.handleCluster(w, req)

	var resp map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if string(resp["sessions"]) != "[]" {
		t.Fatalf("sessions = %s, want []", resp["sessions"])
	}
}
