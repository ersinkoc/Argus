package gateway

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/policy"
	"github.com/ersinkoc/argus/internal/pool"
	mssql "github.com/ersinkoc/argus/internal/protocol/mssql"
)

// --- TDS reply builders (server → client) ---

func utf16le(s string) []byte {
	b := make([]byte, len(s)*2)
	for i, r := range s {
		b[i*2] = byte(r)
		b[i*2+1] = byte(r >> 8)
	}
	return b
}

// tdsNVarcharColumn builds a COLMETADATA column def for an NVARCHAR column.
func tdsNVarcharColumn(name string, maxLen int) []byte {
	var c []byte
	c = append(c, 0, 0, 0, 0) // user type (4)
	c = append(c, 0, 0)       // flags (2)
	c = append(c, 0xE7)       // NVARCHAR type
	c = append(c, byte(maxLen), byte(maxLen>>8))
	c = append(c, 0, 0, 0, 0, 0) // collation (5)
	c = append(c, byte(len(name)))
	c = append(c, utf16le(name)...)
	return c
}

// tdsIntColumn builds a COLMETADATA column def for a fixed 4-byte INT column.
func tdsIntColumn(name string) []byte {
	var c []byte
	c = append(c, 0, 0, 0, 0) // user type
	c = append(c, 0, 0)       // flags
	c = append(c, 0x38)       // INT4
	c = append(c, byte(len(name)))
	c = append(c, utf16le(name)...)
	return c
}

func tdsColMetadata(colCount int, cols ...[]byte) []byte {
	out := []byte{mssql.TokenColMetadata, byte(colCount), byte(colCount >> 8)}
	for _, c := range cols {
		out = append(out, c...)
	}
	return out
}

// tdsRow builds a ROW token. Each field is either an int (fixed 4-byte LE) or a
// string (NVARCHAR: 2-byte byte-length + UTF-16LE), or nil for a NULL NVARCHAR.
func tdsRow(fields ...any) []byte {
	out := []byte{mssql.TokenRow}
	for _, f := range fields {
		switch v := f.(type) {
		case int:
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, uint32(v))
			out = append(out, b...)
		case string:
			enc := utf16le(v)
			out = append(out, byte(len(enc)), byte(len(enc)>>8))
			out = append(out, enc...)
		case nil:
			out = append(out, 0xFF, 0xFF) // NULL
		}
	}
	return out
}

func tdsDone() []byte {
	return []byte{mssql.TokenDone, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
}

func tdsReplyPacket(tokens ...[]byte) []byte {
	var data []byte
	for _, t := range tokens {
		data = append(data, t...)
	}
	total := 8 + len(data)
	pkt := make([]byte, total)
	pkt[0] = mssql.PacketReply
	pkt[1] = mssql.StatusEOM
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	copy(pkt[8:], data)
	return pkt
}

func mockMSSQLPool(t *testing.T, reply []byte) *pool.Pool {
	t.Helper()
	serverConn, clientConn := net.Pipe()

	go func() {
		buf := make([]byte, 4096)
		serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		serverConn.Read(buf) // consume the SQL Batch
		serverConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		serverConn.Write(reply)
	}()

	p := pool.NewPool("mock-mssql", 1, 0, time.Hour, 10*time.Second, 0)
	p.SetConnectFunc(func(ctx context.Context) (net.Conn, error) {
		return clientConn, nil
	})
	return p
}

func TestExecuteMSSQL_SelectRows(t *testing.T) {
	reply := tdsReplyPacket(
		tdsColMetadata(2, tdsIntColumn("id"), tdsNVarcharColumn("name", 100)),
		tdsRow(1, "Alice"),
		tdsRow(2, "Bob"),
		tdsDone(),
	)
	pl := mockMSSQLPool(t, reply)

	result, err := executeMSSQL(context.Background(), pl, "SELECT id, name FROM users", 100, nil, nil, false)
	if err != nil {
		t.Fatalf("executeMSSQL: %v", err)
	}
	if len(result.Columns) != 2 || result.Columns[0].Name != "id" || result.Columns[1].Name != "name" {
		t.Fatalf("columns = %+v", result.Columns)
	}
	if result.RowCount != 2 || len(result.Rows) != 2 {
		t.Fatalf("row count = %d, rows = %d, want 2/2", result.RowCount, len(result.Rows))
	}
	if result.Rows[0][1] != "Alice" || result.Rows[1][1] != "Bob" {
		t.Fatalf("row values = %+v", result.Rows)
	}
}

func TestExecuteMSSQL_NullField(t *testing.T) {
	reply := tdsReplyPacket(
		tdsColMetadata(2, tdsIntColumn("id"), tdsNVarcharColumn("name", 100)),
		tdsRow(7, nil),
		tdsDone(),
	)
	pl := mockMSSQLPool(t, reply)

	result, err := executeMSSQL(context.Background(), pl, "SELECT id, name FROM t", 100, nil, nil, false)
	if err != nil {
		t.Fatalf("executeMSSQL: %v", err)
	}
	if len(result.Rows) != 1 || result.Rows[0][1] != nil {
		t.Fatalf("expected NULL second field, got %+v", result.Rows)
	}
}

func TestExecuteMSSQL_MaxRows(t *testing.T) {
	reply := tdsReplyPacket(
		tdsColMetadata(1, tdsIntColumn("n")),
		tdsRow(1), tdsRow(2), tdsRow(3), tdsRow(4),
		tdsDone(),
	)
	pl := mockMSSQLPool(t, reply)

	result, err := executeMSSQL(context.Background(), pl, "SELECT n FROM t", 2, nil, nil, false)
	if err != nil {
		t.Fatalf("executeMSSQL: %v", err)
	}
	if result.RowCount != 4 {
		t.Errorf("RowCount = %d, want 4 (all counted)", result.RowCount)
	}
	if len(result.Rows) != 2 {
		t.Errorf("returned rows = %d, want 2 (capped)", len(result.Rows))
	}
}

func TestExecuteMSSQL_ErrorToken(t *testing.T) {
	errTok := mssql.BuildErrorToken(208, 1, 16, "Invalid object name 'x'", "srv", "", 1)
	reply := tdsReplyPacket(errTok, tdsDone())
	pl := mockMSSQLPool(t, reply)

	_, err := executeMSSQL(context.Background(), pl, "SELECT * FROM x", 100, nil, nil, false)
	if err == nil {
		t.Fatal("expected SQL error")
	}
	if want := "Invalid object name"; !contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q", err.Error(), want)
	}
}

// (contains is defined in executor_test.go)

func TestExecuteMSSQL_Masking(t *testing.T) {
	reply := tdsReplyPacket(
		tdsColMetadata(2, tdsIntColumn("id"), tdsNVarcharColumn("email", 200)),
		tdsRow(1, "alice@example.com"),
		tdsDone(),
	)
	pl := mockMSSQLPool(t, reply)

	rules := []policy.MaskingRule{{Column: "email", Transformer: "partial_email"}}
	result, err := executeMSSQL(context.Background(), pl, "SELECT id, email FROM users", 100, rules, nil, false)
	if err != nil {
		t.Fatalf("executeMSSQL: %v", err)
	}
	if len(result.MaskedCols) != 1 || result.MaskedCols[0] != "email" {
		t.Fatalf("MaskedCols = %+v, want [email]", result.MaskedCols)
	}
	got, _ := result.Rows[0][1].(string)
	if got != "a***@example.com" {
		t.Fatalf("masked email = %q, want a***@example.com", got)
	}
}

func TestExecuteMSSQL_EmptyResult(t *testing.T) {
	reply := tdsReplyPacket(tdsDone())
	pl := mockMSSQLPool(t, reply)

	result, err := executeMSSQL(context.Background(), pl, "UPDATE t SET x=1", 100, nil, nil, false)
	if err != nil {
		t.Fatalf("executeMSSQL: %v", err)
	}
	if result.RowCount != 0 || len(result.Rows) != 0 {
		t.Fatalf("expected empty result, got %+v", result)
	}
}

func TestExecuteMSSQL_PIIAutoDetect(t *testing.T) {
	reply := tdsReplyPacket(
		tdsColMetadata(1, tdsNVarcharColumn("email", 200)),
		tdsRow("bob@example.com"),
		tdsDone(),
	)
	pl := mockMSSQLPool(t, reply)

	det := masking.NewPIIDetector()
	result, err := executeMSSQL(context.Background(), pl, "SELECT email FROM users", 100, nil, det, true)
	if err != nil {
		t.Fatalf("executeMSSQL: %v", err)
	}
	if len(result.MaskedCols) != 1 || result.MaskedCols[0] != "email" {
		t.Fatalf("MaskedCols = %+v, want [email] via PII auto-detect", result.MaskedCols)
	}
}
