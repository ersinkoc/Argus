package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteAPIErrorShape(t *testing.T) {
	rec := httptest.NewRecorder()

	writeAPIError(rec, http.StatusBadRequest, "VALIDATION_ERROR", "bad request")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
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
	if body.Error.Code != "VALIDATION_ERROR" || body.Error.Message != "bad request" {
		t.Fatalf("error = %+v, want VALIDATION_ERROR/bad request", body.Error)
	}
}
