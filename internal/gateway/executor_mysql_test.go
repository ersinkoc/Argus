package gateway

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/pool"
)

// --- Helper: build MySQL wire protocol messages ---

func mysqlPacket(seqID byte, payload []byte) []byte {
	length := len(payload)
	buf := make([]byte, 4+length)
	buf[0] = byte(length)
	buf[1] = byte(length >> 8)
	buf[2] = byte(length >> 16)
	buf[3] = seqID
	copy(buf[4:], payload)
	return buf
}

func mysqlOKPacket(seqID byte) []byte {
	// 0x00 + affected_rows(1) + last_insert_id(1) + status(2) + warnings(2)
	payload := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
	return mysqlPacket(seqID, payload)
}

func mysqlErrPacket(seqID byte, code uint16, message string) []byte {
	payload := []byte{0xFF}
	payload = append(payload, byte(code), byte(code>>8))
	payload = append(payload, '#')
	payload = append(payload, []byte("HY000")...)
	payload = append(payload, []byte(message)...)
	return mysqlPacket(seqID, payload)
}

func mysqlColumnCount(seqID byte, count int) []byte {
	return mysqlPacket(seqID, []byte{byte(count)})
}

func mysqlColumnDef(seqID byte, name string) []byte {
	// Simplified: 4 length-encoded strings (catalog, schema, table, org_table) + name + org_name + filler
	var payload []byte
	// catalog: "def"
	payload = append(payload, 3, 'd', 'e', 'f')
	// schema: ""
	payload = append(payload, 0)
	// table: ""
	payload = append(payload, 0)
	// org_table: ""
	payload = append(payload, 0)
	// name
	payload = append(payload, byte(len(name)))
	payload = append(payload, []byte(name)...)
	// org_name
	payload = append(payload, byte(len(name)))
	payload = append(payload, []byte(name)...)
	// filler(1) + charset(2) + length(4) + type(1) + flags(2) + decimals(1) + filler(2)
	payload = append(payload, 0x0C)
	payload = append(payload, make([]byte, 12)...)
	return mysqlPacket(seqID, payload)
}

func mysqlEOFPacket(seqID byte) []byte {
	payload := []byte{0xFE, 0x00, 0x00, 0x02, 0x00}
	return mysqlPacket(seqID, payload)
}

func mysqlTextRow(seqID byte, fields []string) []byte {
	var payload []byte
	for _, f := range fields {
		payload = append(payload, byte(len(f)))
		payload = append(payload, []byte(f)...)
	}
	return mysqlPacket(seqID, payload)
}

// mockMySQLPool creates a pool with a mock MySQL backend.
func mockMySQLPool(t *testing.T, responses []byte) *pool.Pool {
	t.Helper()
	serverConn, clientConn := net.Pipe()

	go func() {
		buf := make([]byte, 4096)
		serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		serverConn.Read(buf) // consume COM_QUERY
		serverConn.Write(responses)
		time.Sleep(100 * time.Millisecond)
		serverConn.Close()
	}()

	p := pool.NewPool("mock-mysql", 1, 0, time.Hour, 10*time.Second, 0)
	p.SetConnectFunc(func(ctx context.Context) (net.Conn, error) {
		return clientConn, nil
	})
	return p
}

func TestExecuteMySQL_SelectRows(t *testing.T) {
	var resp []byte
	resp = append(resp, mysqlColumnCount(1, 2)...)
	resp = append(resp, mysqlColumnDef(2, "id")...)
	resp = append(resp, mysqlColumnDef(3, "name")...)
	resp = append(resp, mysqlEOFPacket(4)...)
	resp = append(resp, mysqlTextRow(5, []string{"1", "Alice"})...)
	resp = append(resp, mysqlTextRow(6, []string{"2", "Bob"})...)
	resp = append(resp, mysqlEOFPacket(7)...)

	pl := mockMySQLPool(t, resp)

	result, err := executeMySQL(context.Background(), pl, "SELECT id, name FROM users", 100, nil, nil, false)
	if err != nil {
		t.Fatalf("executeMySQL failed: %v", err)
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

func TestExecuteMySQL_OKPacket(t *testing.T) {
	resp := mysqlOKPacket(1)
	pl := mockMySQLPool(t, resp)

	result, err := executeMySQL(context.Background(), pl, "INSERT INTO t VALUES (1)", 100, nil, nil, false)
	if err != nil {
		t.Fatalf("executeMySQL failed: %v", err)
	}
	if result.RowCount != 0 {
		t.Errorf("row_count = %d, want 0", result.RowCount)
	}
}

func TestExecuteMySQL_ErrPacket(t *testing.T) {
	resp := mysqlErrPacket(1, 1146, "Table 'test.nonexistent' doesn't exist")
	pl := mockMySQLPool(t, resp)

	_, err := executeMySQL(context.Background(), pl, "SELECT * FROM nonexistent", 100, nil, nil, false)
	if err == nil {
		t.Fatal("expected error")
	}
	if !contains(err.Error(), "doesn't exist") {
		t.Errorf("error = %v, want 'doesn't exist'", err)
	}
}

func TestExecuteMySQL_MaxRows(t *testing.T) {
	var resp []byte
	resp = append(resp, mysqlColumnCount(1, 1)...)
	resp = append(resp, mysqlColumnDef(2, "val")...)
	resp = append(resp, mysqlEOFPacket(3)...)
	seq := byte(4)
	for i := 0; i < 10; i++ {
		resp = append(resp, mysqlTextRow(seq, []string{"data"})...)
		seq++
	}
	resp = append(resp, mysqlEOFPacket(seq)...)

	pl := mockMySQLPool(t, resp)

	result, err := executeMySQL(context.Background(), pl, "SELECT val FROM t", 3, nil, nil, false)
	if err != nil {
		t.Fatalf("executeMySQL failed: %v", err)
	}
	if result.RowCount != 3 {
		t.Errorf("row_count = %d, want 3 (maxRows capped)", result.RowCount)
	}
}
