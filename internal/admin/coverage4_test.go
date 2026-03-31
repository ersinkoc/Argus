package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ersinkoc/argus/internal/metrics"
)

// TestHandleMetricsDatabaseStats checks the per-database metrics section,
// which is only rendered when DatabaseStats has at least one entry.
func TestHandleMetricsDatabaseStats(t *testing.T) {
	// Seed global DatabaseStats so the conditional block is exercised.
	metrics.DatabaseStats.RecordQuery("testdb")
	metrics.DatabaseStats.RecordWrite("testdb")
	metrics.DatabaseStats.RecordBlocked("testdb")
	metrics.DatabaseStats.RecordRows("testdb", 42)

	s := NewServer(newMockProvider(), ":0")
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	s.handleMetrics(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	body := w.Body.String()
	checks := []string{
		"argus_database_queries_total",
		"argus_database_writes_total",
		"argus_database_blocked_total",
		"argus_database_rows_total",
		`database="testdb"`,
	}
	for _, check := range checks {
		if !strings.Contains(body, check) {
			t.Errorf("metrics should contain %q", check)
		}
	}
}

// TestHandleApprovalActionMethodNotAllowed covers the non-POST method branch.
func TestHandleApprovalActionMethodNotAllowed(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetApprovalProvider(&mockApproval{})

	req := httptest.NewRequest("GET", "/api/approvals/approve?id=1", nil)
	w := httptest.NewRecorder()
	s.handleApprovalAction(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

// TestHandleApprovalDenyNoProvider covers deny with no provider set.
func TestHandleApprovalDenyNoProvider(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("POST", "/api/approvals/deny?id=1", nil)
	w := httptest.NewRecorder()
	s.handleApprovalDeny(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// TestHandleAuditSearchNoPath covers the missing path 500 error.
func TestHandleAuditSearchNoPath(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/api/audit/search", nil)
	w := httptest.NewRecorder()
	s.handleAuditSearch(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}
