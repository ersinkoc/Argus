package core

import "testing"

func TestRouterGetHandler(t *testing.T) {
	r := NewRouter()

	// Should have PostgreSQL, MySQL, MSSQL
	pg := r.GetHandler("postgresql")
	if pg == nil {
		t.Error("should have postgresql handler")
	}
	if pg.Name() != "postgresql" {
		t.Errorf("pg name = %q", pg.Name())
	}

	mysql := r.GetHandler("mysql")
	if mysql == nil {
		t.Error("should have mysql handler")
	}

	mssql := r.GetHandler("mssql")
	if mssql == nil {
		t.Error("should have mssql handler")
	}

	// Unknown
	if r.GetHandler("oracle") != nil {
		t.Error("should return nil for oracle")
	}
}

func TestRouterDetectHandler(t *testing.T) {
	r := NewRouter()

	// PostgreSQL v3.0 startup bytes
	pgBytes := []byte{0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00}
	handler := r.DetectHandler(pgBytes)
	if handler == nil || handler.Name() != "postgresql" {
		t.Error("should detect PostgreSQL")
	}

	// MSSQL TDS pre-login
	tdsBytes := []byte{0x12, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00}
	handler = r.DetectHandler(tdsBytes)
	if handler == nil || handler.Name() != "mssql" {
		t.Error("should detect MSSQL TDS")
	}

	// Random bytes
	handler = r.DetectHandler([]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11})
	if handler != nil {
		t.Error("should return nil for random bytes")
	}
}
