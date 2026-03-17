package pg

import (
	"testing"
)

func TestParseStartupMessage(t *testing.T) {
	params := map[string]string{
		"user":     "testuser",
		"database": "testdb",
	}
	raw := BuildStartupMessage(params)

	startup, err := ParseStartupMessage(raw)
	if err != nil {
		t.Fatalf("ParseStartupMessage: %v", err)
	}

	if startup.IsSSLRequest {
		t.Error("should not be SSL request")
	}

	if startup.Parameters["user"] != "testuser" {
		t.Errorf("user = %q, want %q", startup.Parameters["user"], "testuser")
	}
	if startup.Parameters["database"] != "testdb" {
		t.Errorf("database = %q, want %q", startup.Parameters["database"], "testdb")
	}
}

func TestBuildErrorResponse(t *testing.T) {
	msg := BuildErrorResponse("ERROR", "42501", "Access denied")
	if msg.Type != MsgErrorResponse {
		t.Errorf("type = %c, want %c", msg.Type, MsgErrorResponse)
	}

	fields := ParseErrorResponse(msg.Payload)
	if fields['S'] != "ERROR" {
		t.Errorf("severity = %q, want %q", fields['S'], "ERROR")
	}
	if fields['C'] != "42501" {
		t.Errorf("code = %q, want %q", fields['C'], "42501")
	}
	if fields['M'] != "Access denied" {
		t.Errorf("message = %q, want %q", fields['M'], "Access denied")
	}
}

func TestParseRowDescription(t *testing.T) {
	// Build a simple RowDescription with 2 columns
	payload := make([]byte, 0)
	// Number of columns
	payload = append(payload, 0, 2)

	// Column 1: "id"
	payload = append(payload, []byte("id")...)
	payload = append(payload, 0) // null terminator
	payload = append(payload, 0, 0, 0, 0) // table OID
	payload = append(payload, 0, 1) // column index
	payload = append(payload, 0, 0, 0, 23) // type OID (int4)
	payload = append(payload, 0, 4) // type size
	payload = append(payload, 0xFF, 0xFF, 0xFF, 0xFF) // type modifier
	payload = append(payload, 0, 0) // format

	// Column 2: "name"
	payload = append(payload, []byte("name")...)
	payload = append(payload, 0) // null terminator
	payload = append(payload, 0, 0, 0, 0)
	payload = append(payload, 0, 2)
	payload = append(payload, 0, 0, 0, 25) // type OID (text)
	payload = append(payload, 0xFF, 0xFF) // type size (-1)
	payload = append(payload, 0xFF, 0xFF, 0xFF, 0xFF)
	payload = append(payload, 0, 0)

	cols, err := ParseRowDescription(payload)
	if err != nil {
		t.Fatalf("ParseRowDescription: %v", err)
	}

	if len(cols) != 2 {
		t.Fatalf("got %d columns, want 2", len(cols))
	}

	if cols[0].Name != "id" {
		t.Errorf("col 0 name = %q, want %q", cols[0].Name, "id")
	}
	if cols[1].Name != "name" {
		t.Errorf("col 1 name = %q, want %q", cols[1].Name, "name")
	}
}

func TestBuildAndParseDataRow(t *testing.T) {
	fields := [][]byte{
		[]byte("1"),
		[]byte("John"),
		nil, // NULL
	}

	msg := BuildDataRow(fields)
	if msg.Type != MsgDataRow {
		t.Errorf("type = %c, want %c", msg.Type, MsgDataRow)
	}

	parsed, err := ParseDataRow(msg.Payload)
	if err != nil {
		t.Fatalf("ParseDataRow: %v", err)
	}

	if len(parsed) != 3 {
		t.Fatalf("got %d fields, want 3", len(parsed))
	}

	if string(parsed[0]) != "1" {
		t.Errorf("field 0 = %q, want %q", parsed[0], "1")
	}
	if string(parsed[1]) != "John" {
		t.Errorf("field 1 = %q, want %q", parsed[1], "John")
	}
	if parsed[2] != nil {
		t.Errorf("field 2 should be nil (NULL), got %v", parsed[2])
	}
}

func TestBuildReadyForQuery(t *testing.T) {
	msg := BuildReadyForQuery('I')
	if msg.Type != MsgReadyForQuery {
		t.Errorf("type = %c, want %c", msg.Type, MsgReadyForQuery)
	}
	if len(msg.Payload) != 1 || msg.Payload[0] != 'I' {
		t.Errorf("payload = %v, want [I]", msg.Payload)
	}
}
