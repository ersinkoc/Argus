package gateway

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/policy"
	"github.com/ersinkoc/argus/internal/pool"
)

// --- Helper: build PG wire protocol messages ---

func pgMsg(typ byte, payload []byte) []byte {
	buf := make([]byte, 5+len(payload))
	buf[0] = typ
	binary.BigEndian.PutUint32(buf[1:5], uint32(4+len(payload)))
	copy(buf[5:], payload)
	return buf
}

func pgRowDescription(names []string) []byte {
	var payload []byte
	ncols := make([]byte, 2)
	binary.BigEndian.PutUint16(ncols, uint16(len(names)))
	payload = append(payload, ncols...)
	for _, name := range names {
		payload = append(payload, []byte(name)...)
		payload = append(payload, 0) // null terminator
		// tableOID(4) + colIndex(2) + typeOID(4) + typeSize(2) + typeMod(4) + format(2) = 18 bytes
		colMeta := make([]byte, 18)
		binary.BigEndian.PutUint32(colMeta[6:10], 25) // typeOID=25 (text)
		payload = append(payload, colMeta...)
	}
	return pgMsg('T', payload)
}

func pgDataRow(fields []string) []byte {
	var payload []byte
	ncols := make([]byte, 2)
	binary.BigEndian.PutUint16(ncols, uint16(len(fields)))
	payload = append(payload, ncols...)
	for _, f := range fields {
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(f)))
		payload = append(payload, lenBuf...)
		payload = append(payload, []byte(f)...)
	}
	return pgMsg('D', payload)
}

func pgCommandComplete(tag string) []byte {
	payload := append([]byte(tag), 0)
	return pgMsg('C', payload)
}

func pgReadyForQuery() []byte {
	return pgMsg('Z', []byte{'I'})
}

func pgErrorResponse(code, message string) []byte {
	var payload []byte
	payload = append(payload, 'C')
	payload = append(payload, []byte(code)...)
	payload = append(payload, 0)
	payload = append(payload, 'M')
	payload = append(payload, []byte(message)...)
	payload = append(payload, 0)
	payload = append(payload, 0) // terminator
	return pgMsg('E', payload)
}

// mockPGPool creates a pool with a mock PG backend that responds with the given messages.
func mockPGPool(t *testing.T, responses []byte) *pool.Pool {
	t.Helper()
	serverConn, clientConn := net.Pipe()

	// Write responses in background
	go func() {
		// Read the incoming Simple Query message (consume it)
		buf := make([]byte, 4096)
		serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		serverConn.Read(buf)
		// Write pre-built responses
		serverConn.Write(responses)
		// Keep connection open briefly
		time.Sleep(100 * time.Millisecond)
		serverConn.Close()
	}()

	p := pool.NewPool("mock", 1, 0, time.Hour, 10*time.Second, 0)
	p.SetConnectFunc(func(ctx context.Context) (net.Conn, error) {
		return clientConn, nil
	})
	return p
}

func TestExecutePG_SelectRows(t *testing.T) {
	// Build mock PG response: RowDescription + 2 DataRows + CommandComplete + ReadyForQuery
	var resp []byte
	resp = append(resp, pgRowDescription([]string{"id", "name"})...)
	resp = append(resp, pgDataRow([]string{"1", "Alice"})...)
	resp = append(resp, pgDataRow([]string{"2", "Bob"})...)
	resp = append(resp, pgCommandComplete("SELECT 2")...)
	resp = append(resp, pgReadyForQuery()...)

	pl := mockPGPool(t, resp)

	result, err := executePG(context.Background(), pl, "SELECT id, name FROM users", 100, nil, nil, false)
	if err != nil {
		t.Fatalf("executePG failed: %v", err)
	}

	if result.RowCount != 2 {
		t.Errorf("row_count = %d, want 2", result.RowCount)
	}
	if len(result.Columns) != 2 {
		t.Fatalf("columns = %d, want 2", len(result.Columns))
	}
	if result.Columns[0].Name != "id" || result.Columns[1].Name != "name" {
		t.Errorf("columns = %v", result.Columns)
	}
	if len(result.Rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(result.Rows))
	}
	if result.Rows[0][1] != "Alice" {
		t.Errorf("row[0][1] = %v, want Alice", result.Rows[0][1])
	}
}

func TestExecutePG_EmptyResult(t *testing.T) {
	var resp []byte
	resp = append(resp, pgRowDescription([]string{"id"})...)
	resp = append(resp, pgCommandComplete("SELECT 0")...)
	resp = append(resp, pgReadyForQuery()...)

	pl := mockPGPool(t, resp)

	result, err := executePG(context.Background(), pl, "SELECT id FROM users WHERE 1=0", 100, nil, nil, false)
	if err != nil {
		t.Fatalf("executePG failed: %v", err)
	}
	if result.RowCount != 0 {
		t.Errorf("row_count = %d, want 0", result.RowCount)
	}
}

func TestExecutePG_SQLError(t *testing.T) {
	var resp []byte
	resp = append(resp, pgErrorResponse("42P01", "relation \"nonexistent\" does not exist")...)
	resp = append(resp, pgReadyForQuery()...)

	pl := mockPGPool(t, resp)

	_, err := executePG(context.Background(), pl, "SELECT * FROM nonexistent", 100, nil, nil, false)
	if err == nil {
		t.Fatal("expected error")
	}
	if !contains(err.Error(), "42P01") {
		t.Errorf("error = %v, want to contain 42P01", err)
	}
}

func TestExecutePG_MaxRows(t *testing.T) {
	var resp []byte
	resp = append(resp, pgRowDescription([]string{"id"})...)
	for i := 0; i < 10; i++ {
		resp = append(resp, pgDataRow([]string{"val"})...)
	}
	resp = append(resp, pgCommandComplete("SELECT 10")...)
	resp = append(resp, pgReadyForQuery()...)

	pl := mockPGPool(t, resp)

	result, err := executePG(context.Background(), pl, "SELECT id FROM t", 3, nil, nil, false)
	if err != nil {
		t.Fatalf("executePG failed: %v", err)
	}
	// Should only collect 3 rows even though backend sent 10
	if result.RowCount != 3 {
		t.Errorf("row_count = %d, want 3 (maxRows capped)", result.RowCount)
	}
}

func TestExecutePG_WithMasking(t *testing.T) {
	var resp []byte
	resp = append(resp, pgRowDescription([]string{"id", "email"})...)
	resp = append(resp, pgDataRow([]string{"1", "alice@example.com"})...)
	resp = append(resp, pgCommandComplete("SELECT 1")...)
	resp = append(resp, pgReadyForQuery()...)

	pl := mockPGPool(t, resp)

	// Masking rules: mask the "email" column
	maskRules := []policy.MaskingRule{
		{Column: "email", Transformer: "redact"},
	}

	result, err := executePG(context.Background(), pl, "SELECT id, email FROM users", 100, maskRules, nil, false)
	if err != nil {
		t.Fatalf("executePG with masking failed: %v", err)
	}
	if result.RowCount != 1 {
		t.Errorf("row_count = %d, want 1", result.RowCount)
	}
	// Email should be masked (not original value)
	if len(result.Rows) > 0 && result.Rows[0][1] == "alice@example.com" {
		t.Error("email should be masked, got original value")
	}
	if len(result.MaskedCols) == 0 {
		t.Error("masked_cols should not be empty")
	}
}

func TestExecutePG_EmptyQuery(t *testing.T) {
	var resp []byte
	resp = append(resp, pgMsg('I', nil)...)    // EmptyQueryResponse
	resp = append(resp, pgReadyForQuery()...)

	pl := mockPGPool(t, resp)

	result, err := executePG(context.Background(), pl, "", 100, nil, nil, false)
	if err != nil {
		t.Fatalf("executePG empty query failed: %v", err)
	}
	if result.RowCount != 0 {
		t.Errorf("row_count = %d, want 0", result.RowCount)
	}
}

func TestPgTypeName(t *testing.T) {
	tests := map[int32]string{
		16: "bool", 23: "int4", 25: "text", 701: "float8",
		1043: "varchar", 1114: "timestamp", 2950: "uuid", 9999: "oid:9999",
	}
	for oid, want := range tests {
		got := pgTypeName(oid)
		if got != want {
			t.Errorf("pgTypeName(%d) = %q, want %q", oid, got, want)
		}
	}
}

func TestAppendUnique(t *testing.T) {
	s := []string{"a", "b"}
	s = appendUnique(s, "b") // already exists
	if len(s) != 2 {
		t.Errorf("len = %d, want 2 (no dup)", len(s))
	}
	s = appendUnique(s, "c")
	if len(s) != 3 {
		t.Errorf("len = %d, want 3", len(s))
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && stringContains(s, sub)
}

func stringContains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
