package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteAPIErrorShape(t *testing.T) {
	rec := httptest.NewRecorder()

	writeAPIError(rec, http.StatusForbidden, "FORBIDDEN", "access denied")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if body.Error.Code != "FORBIDDEN" || body.Error.Message != "access denied" {
		t.Fatalf("error = %+v, want FORBIDDEN/access denied", body.Error)
	}
}
