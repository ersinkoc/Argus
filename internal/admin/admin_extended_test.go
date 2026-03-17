package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDashboardEndpoint(t *testing.T) {
	server := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/api/dashboard", nil)
	w := httptest.NewRecorder()
	server.handleDashboard(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	if _, ok := resp["overview"]; !ok {
		t.Error("dashboard should include overview")
	}
	if _, ok := resp["traffic"]; !ok {
		t.Error("dashboard should include traffic")
	}
	if _, ok := resp["pool"]; !ok {
		t.Error("dashboard should include pool")
	}
}

func TestReadyEndpoint(t *testing.T) {
	server := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	server.handleReady(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("ready status = %d, want 200", w.Code)
	}
}

func TestLiveEndpoint(t *testing.T) {
	server := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/livez", nil)
	w := httptest.NewRecorder()
	server.handleLive(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("livez status = %d, want 200", w.Code)
	}
}

func TestConfigExportNotConfigured(t *testing.T) {
	server := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/api/config/export", nil)
	w := httptest.NewRecorder()
	server.handleConfigExport(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestConfigExportConfigured(t *testing.T) {
	server := NewServer(newMockProvider(), ":0")
	server.SetConfigExporter(func() ([]byte, error) {
		return []byte(`{"test": true}`), nil
	})

	req := httptest.NewRequest("GET", "/api/config/export", nil)
	w := httptest.NewRecorder()
	server.handleConfigExport(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestDryRunNotConfigured(t *testing.T) {
	server := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("POST", "/api/policies/dryrun?username=test&sql=SELECT+1", nil)
	w := httptest.NewRecorder()
	server.handleDryRun(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestDryRunMethodNotAllowed(t *testing.T) {
	server := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/api/policies/dryrun", nil)
	w := httptest.NewRecorder()
	server.handleDryRun(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestPolicyValidateNotConfigured(t *testing.T) {
	server := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/api/policies/validate", nil)
	w := httptest.NewRecorder()
	server.handlePolicyValidate(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestPolicyValidateConfigured(t *testing.T) {
	server := NewServer(newMockProvider(), ":0")
	server.SetPolicyValidator(func() (any, error) {
		return map[string]any{"valid": true, "issues": []any{}}, nil
	})

	req := httptest.NewRequest("GET", "/api/policies/validate", nil)
	w := httptest.NewRecorder()
	server.handlePolicyValidate(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestReplayNotConfigured(t *testing.T) {
	server := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/api/audit/replay?session_id=test", nil)
	w := httptest.NewRecorder()
	server.handleReplay(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestReplayMissingSessionID(t *testing.T) {
	server := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/api/audit/replay", nil)
	w := httptest.NewRecorder()
	server.handleReplay(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestFingerprintsNotConfigured(t *testing.T) {
	server := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/api/audit/fingerprints", nil)
	w := httptest.NewRecorder()
	server.handleFingerprints(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestCompactMethodNotAllowed(t *testing.T) {
	server := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/api/audit/compact", nil)
	w := httptest.NewRecorder()
	server.handleCompact(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestEventStreamCount(t *testing.T) {
	es := NewEventStream()
	if es.Count() != 0 {
		t.Errorf("initial count = %d, want 0", es.Count())
	}
}
