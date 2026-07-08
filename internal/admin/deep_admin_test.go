package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/audit"
	"github.com/ersinkoc/argus/internal/pool"
	"github.com/ersinkoc/argus/internal/session"
)

type deepProvider struct{}

func (p *deepProvider) SessionManager() *session.Manager {
	return session.NewManager(time.Hour, time.Hour)
}
func (p *deepProvider) PoolStats() map[string]pool.PoolStats {
	return map[string]pool.PoolStats{}
}

// --- handleApprovalAction: missing approver (defaults to "admin") ---

func TestHandleApprovalActionDefaultApprover(t *testing.T) {
	s := NewServer(&deepProvider{}, ":0")
	s.SetApprovalProvider(&testApprovalMock{})
	req := httptest.NewRequest(http.MethodPost, "/api/approvals/approve?id=nonexistent", nil)
	w := httptest.NewRecorder()
	s.handleApprovalAction(w, req)
	// Will get 404 (no such approval), but exercises default approver path
	if w.Code != http.StatusNotFound {
		t.Errorf("code = %d", w.Code)
	}
}

// --- handleAuditSearch with all filter params ---

func TestHandleAuditSearchAllParams(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.jsonl")
	f, _ := os.Create(logFile)
	enc := json.NewEncoder(f)
	enc.Encode(audit.Event{Timestamp: time.Now(), EventType: "command_executed", Username: "alice", Database: "prod", Action: "allow", CommandType: "SELECT"})
	enc.Encode(audit.Event{Timestamp: time.Now(), EventType: "auth_success", Username: "bob", Database: "dev", Action: "allow"})
	f.Close()

	s := NewServer(&deepProvider{}, ":0")
	s.auditLogPath = logFile

	now := time.Now()
	start := now.Add(-time.Hour).Format(time.RFC3339)
	end := now.Add(time.Hour).Format(time.RFC3339)

	req := httptest.NewRequest(http.MethodGet,
		"/api/audit/search?username=alice&database=prod&event_type=command_executed&action=allow&command_type=SELECT&limit=10&start="+start+"&end="+end, nil)
	w := httptest.NewRecorder()
	s.handleAuditSearch(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("code = %d, body = %s", w.Code, w.Body.String())
	}
}

// --- handleAuditExport with filters ---

func TestHandleAuditExportWithFilters(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.jsonl")
	f, _ := os.Create(logFile)
	enc := json.NewEncoder(f)
	enc.Encode(audit.Event{Timestamp: time.Now(), EventType: "cmd", Username: "alice", Action: "allow"})
	enc.Encode(audit.Event{Timestamp: time.Now(), EventType: "cmd", Username: "bob", Action: "block"})
	f.Close()

	s := NewServer(&deepProvider{}, ":0")
	s.auditLogPath = logFile

	req := httptest.NewRequest(http.MethodGet, "/api/audit/export?username=alice&action=allow", nil)
	w := httptest.NewRecorder()
	s.handleAuditExport(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("code = %d", w.Code)
	}
}

// --- handleDryRun with error result ---

func TestHandleDryRunError(t *testing.T) {
	s := NewServer(&deepProvider{}, ":0")
	s.SetDryRunFunc(func(user, db, sql, ip string) (any, error) {
		return nil, fmt.Errorf("policy error")
	})
	req := httptest.NewRequest(http.MethodPost, "/api/policy/dry-run?username=u&sql=DROP+TABLE+x", nil)
	w := httptest.NewRecorder()
	s.handleDryRun(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("code = %d", w.Code)
	}
}

// --- handlePolicyValidate with error ---

func TestHandlePolicyValidateError(t *testing.T) {
	s := NewServer(&deepProvider{}, ":0")
	s.SetPolicyValidator(func() (any, error) {
		return nil, fmt.Errorf("validation error")
	})
	req := httptest.NewRequest(http.MethodGet, "/api/policy/validate", nil)
	w := httptest.NewRecorder()
	s.handlePolicyValidate(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("code = %d", w.Code)
	}
}

// --- handleFingerprints with valid file ---

func TestHandleFingerprintsWithData(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "recordings.jsonl")
	f, _ := os.Create(logFile)
	enc := json.NewEncoder(f)
	for range 5 {
		enc.Encode(audit.QueryRecord{
			Timestamp:   time.Now(),
			SQL:         "SELECT * FROM users",
			Fingerprint: "abc123",
			Duration:    1000,
			RowCount:    10,
		})
	}
	f.Close()

	s := NewServer(&deepProvider{}, ":0")
	s.SetRecordFile(logFile)

	req := httptest.NewRequest(http.MethodGet, "/api/audit/fingerprints?limit=5", nil)
	w := httptest.NewRecorder()
	s.handleFingerprints(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("code = %d, body = %s", w.Code, w.Body.String())
	}
}

// --- handleReplay with valid data ---

func TestHandleReplayWithData(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "recordings.jsonl")
	f, _ := os.Create(logFile)
	enc := json.NewEncoder(f)
	enc.Encode(audit.QueryRecord{
		Timestamp: time.Now(),
		SessionID: "sess-123",
		SQL:       "SELECT 1",
	})
	f.Close()

	s := NewServer(&deepProvider{}, ":0")
	s.SetRecordFile(logFile)

	req := httptest.NewRequest(http.MethodGet, "/api/audit/replay?session_id=sess-123", nil)
	w := httptest.NewRecorder()
	s.handleReplay(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("code = %d, body = %s", w.Code, w.Body.String())
	}
}

// --- handleCompact ---

func TestHandleCompactSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	// Create an old log file
	oldFile := filepath.Join(tmpDir, "argus-old.jsonl")
	os.WriteFile(oldFile, []byte("{}\n"), 0644)
	os.Chtimes(oldFile, time.Now().Add(-48*time.Hour), time.Now().Add(-48*time.Hour))

	s := NewServer(&deepProvider{}, ":0")
	s.auditLogPath = filepath.Join(tmpDir, "current.jsonl")

	req := httptest.NewRequest(http.MethodPost, "/api/audit/compact?max_age=1h", nil)
	w := httptest.NewRecorder()
	s.handleCompact(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("code = %d, body = %s", w.Code, w.Body.String())
	}
}

// --- mock ---

type testApprovalMock struct{}

func (m *testApprovalMock) Approve(id, approver string) error {
	return fmt.Errorf("not found: %s", id)
}
func (m *testApprovalMock) Deny(id, approver, reason string) error {
	return fmt.Errorf("not found: %s", id)
}
func (m *testApprovalMock) PendingRequests() []any { return nil }
