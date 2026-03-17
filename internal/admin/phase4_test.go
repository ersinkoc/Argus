package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleClassifyNotConfigured(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	req := httptest.NewRequest("GET", "/api/classify?column=email", nil)
	w := httptest.NewRecorder()
	s.handleClassify(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestHandleClassifyNoColumns(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetClassifyFunc(func(cols []string) any { return cols })

	req := httptest.NewRequest("GET", "/api/classify", nil)
	w := httptest.NewRecorder()
	s.handleClassify(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleClassifyWithColumns(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetClassifyFunc(func(cols []string) any {
		return map[string]any{"columns": cols, "count": len(cols)}
	})

	req := httptest.NewRequest("GET", "/api/classify?column=email&column=salary", nil)
	w := httptest.NewRecorder()
	s.handleClassify(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandleClassifyCommaSeparated(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetClassifyFunc(func(cols []string) any { return cols })

	req := httptest.NewRequest("GET", "/api/classify?columns=email,salary,phone", nil)
	w := httptest.NewRecorder()
	s.handleClassify(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandlePluginsDefault(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")

	req := httptest.NewRequest("GET", "/api/plugins", nil)
	w := httptest.NewRecorder()
	s.handlePlugins(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["count"] != float64(0) {
		t.Errorf("count = %v", resp["count"])
	}
}

func TestHandlePluginsWithProvider(t *testing.T) {
	s := NewServer(newMockProvider(), ":0")
	s.SetPluginListFunc(func() any {
		return map[string]any{
			"plugins": map[string]string{"custom_mask": "transformer"},
			"count":   1,
		}
	})

	req := httptest.NewRequest("GET", "/api/plugins", nil)
	w := httptest.NewRecorder()
	s.handlePlugins(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestHandleDashboardUI(t *testing.T) {
	req := httptest.NewRequest("GET", "/ui", nil)
	w := httptest.NewRecorder()
	HandleDashboardUI(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "text/html; charset=utf-8" {
		t.Errorf("content-type = %q", ct)
	}
	if len(w.Body.Bytes()) < 100 {
		t.Error("dashboard HTML too short")
	}
}

func TestSplitComma(t *testing.T) {
	result := splitComma("a,b,c")
	if len(result) != 3 {
		t.Errorf("split = %v", result)
	}
	result = splitComma("")
	if len(result) != 0 {
		t.Errorf("empty = %v", result)
	}
	result = splitComma("single")
	if len(result) != 1 || result[0] != "single" {
		t.Errorf("single = %v", result)
	}
}
