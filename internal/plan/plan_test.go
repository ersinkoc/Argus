package plan

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
)

// pgServer simulates a minimal PostgreSQL backend that responds to EXPLAIN queries.
type pgServer struct {
	ln       net.Listener
	planCost float64
	errMsg   string // if non-empty, send an error response
}

func newPGServer(t *testing.T, planCost float64) *pgServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &pgServer{ln: ln, planCost: planCost}
	go s.serve(t)
	return s
}

func newPGErrorServer(t *testing.T, errMsg string) *pgServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &pgServer{ln: ln, errMsg: errMsg}
	go s.serve(t)
	return s
}

func (s *pgServer) Addr() string { return s.ln.Addr().String() }

func (s *pgServer) serve(t *testing.T) {
	conn, err := s.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	// Read the incoming EXPLAIN query message (we don't validate content)
	hdr := make([]byte, 5)
	if _, err := readFull(conn, hdr); err != nil {
		return
	}
	msgLen := int(binary.BigEndian.Uint32(hdr[1:])) - 4
	payload := make([]byte, msgLen)
	readFull(conn, payload) //nolint:errcheck

	if s.errMsg != "" {
		s.sendError(conn, s.errMsg)
		s.sendReadyForQuery(conn)
		return
	}

	// Send RowDescription (1 column: "QUERY PLAN")
	s.sendRowDescription(conn)
	// Send DataRow with JSON
	s.sendDataRow(conn, s.planCost)
	// Send CommandComplete
	s.sendCommandComplete(conn)
	// Send ReadyForQuery
	s.sendReadyForQuery(conn)
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (s *pgServer) sendRowDescription(conn net.Conn) {
	colName := []byte("QUERY PLAN\x00")
	// field: name + 6 int16/int32 values = name + 18 bytes
	fieldCount := 1
	payloadLen := 2 + len(colName) + 18
	buf := make([]byte, 1+4+payloadLen)
	buf[0] = 'T'
	binary.BigEndian.PutUint32(buf[1:], uint32(4+payloadLen))
	binary.BigEndian.PutUint16(buf[5:], uint16(fieldCount))
	copy(buf[7:], colName)
	// tableOID(4) colAttr(2) typeOID(4) typeLen(2) typeMod(4) format(2)
	// all zeros is fine for our purposes
	conn.Write(buf) //nolint:errcheck
}

func (s *pgServer) sendDataRow(conn net.Conn, cost float64) {
	type planNode struct {
		TotalCost float64 `json:"Total Cost"`
		PlanRows  float64 `json:"Plan Rows"`
		PlanWidth int     `json:"Plan Width"`
	}
	type planEntry struct {
		Plan planNode `json:"Plan"`
	}
	jsonBytes, _ := json.Marshal([]planEntry{{Plan: planNode{TotalCost: cost, PlanRows: 100, PlanWidth: 8}}})

	// DataRow: type 'D', fieldCount=1, field len (int32), field data
	fieldCount := 1
	payloadLen := 2 + 4 + len(jsonBytes)
	buf := make([]byte, 1+4+payloadLen)
	buf[0] = 'D'
	binary.BigEndian.PutUint32(buf[1:], uint32(4+payloadLen))
	binary.BigEndian.PutUint16(buf[5:], uint16(fieldCount))
	binary.BigEndian.PutUint32(buf[7:], uint32(len(jsonBytes)))
	copy(buf[11:], jsonBytes)
	conn.Write(buf) //nolint:errcheck
}

func (s *pgServer) sendCommandComplete(conn net.Conn) {
	tag := []byte("SELECT 1\x00")
	buf := make([]byte, 1+4+len(tag))
	buf[0] = 'C'
	binary.BigEndian.PutUint32(buf[1:], uint32(4+len(tag)))
	copy(buf[5:], tag)
	conn.Write(buf) //nolint:errcheck
}

func (s *pgServer) sendReadyForQuery(conn net.Conn) {
	// ReadyForQuery: 'Z', len=5, status='I'
	buf := []byte{'Z', 0, 0, 0, 5, 'I'}
	conn.Write(buf) //nolint:errcheck
}

func (s *pgServer) sendError(conn net.Conn, msg string) {
	// ErrorResponse: 'E', len, 'M' + msg + \x00 + \x00
	fields := []byte{'M'}
	fields = append(fields, []byte(msg)...)
	fields = append(fields, 0, 0)
	buf := make([]byte, 1+4+len(fields))
	buf[0] = 'E'
	binary.BigEndian.PutUint32(buf[1:], uint32(4+len(fields)))
	copy(buf[5:], fields)
	conn.Write(buf) //nolint:errcheck
}

// Tests

func TestExplainPG_Success(t *testing.T) {
	srv := newPGServer(t, 1234.56)
	defer srv.ln.Close()

	conn, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	result, err := ExplainPG(context.Background(), conn, "SELECT 1", 2*time.Second)
	if err != nil {
		t.Fatalf("ExplainPG error: %v", err)
	}
	if result.TotalCost != 1234.56 {
		t.Errorf("TotalCost = %v, want 1234.56", result.TotalCost)
	}
}

func TestExplainPG_ServerError(t *testing.T) {
	srv := newPGErrorServer(t, "permission denied for table users")
	defer srv.ln.Close()

	conn, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, err = ExplainPG(context.Background(), conn, "SELECT * FROM users", 2*time.Second)
	if err == nil {
		t.Fatal("expected error from server error response")
	}
}

func TestExplainPG_Timeout(t *testing.T) {
	// Server that never responds
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			// read but don't respond
			buf := make([]byte, 512)
			conn.Read(buf) //nolint:errcheck
			time.Sleep(5 * time.Second)
			conn.Close()
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ctx := context.Background()
	_, err = ExplainPG(ctx, conn, "SELECT 1", 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestParseExplainJSON_Valid(t *testing.T) {
	input := `[{"Plan":{"Total Cost":42.0,"Plan Rows":10,"Plan Width":8}}]`
	result, err := parseExplainJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalCost != 42.0 {
		t.Errorf("TotalCost = %v, want 42.0", result.TotalCost)
	}
	if result.PlanRows != 10 {
		t.Errorf("PlanRows = %v, want 10", result.PlanRows)
	}
}

func TestParseExplainJSON_Empty(t *testing.T) {
	_, err := parseExplainJSON("")
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestParseExplainJSON_EmptyArray(t *testing.T) {
	_, err := parseExplainJSON("[]")
	if err == nil {
		t.Fatal("expected error for empty plan array")
	}
}

func TestParseExplainJSON_Invalid(t *testing.T) {
	_, err := parseExplainJSON("{not valid json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestBuildSimpleQuery(t *testing.T) {
	msg := buildSimpleQuery("SELECT 1")
	if msg[0] != 'Q' {
		t.Errorf("expected message type 'Q', got %c", msg[0])
	}
	// payload = "SELECT 1\x00"
	want := uint32(4 + len("SELECT 1") + 1)
	got := binary.BigEndian.Uint32(msg[1:])
	if got != want {
		t.Errorf("length = %d, want %d", got, want)
	}
}

func TestExtractDataRowText_NullField(t *testing.T) {
	// fieldCount=1, field length=-1 (NULL)
	payload := make([]byte, 6)
	binary.BigEndian.PutUint16(payload[:2], 1)
	binary.BigEndian.PutUint32(payload[2:], 0xFFFFFFFF) // -1 as uint32
	result := extractDataRowText(payload)
	if result != "" {
		t.Errorf("expected empty string for NULL field, got %q", result)
	}
}

func TestExtractErrorMessage(t *testing.T) {
	payload := []byte{'S', 'E', 'R', 'R', 'O', 'R', 0, 'M', 'p', 'e', 'r', 'm', 0, 0}
	msg := extractErrorMessage(payload)
	if msg != "perm" {
		t.Errorf("got %q, want %q", msg, "perm")
	}
}

func TestExtractErrorMessage_NotFound(t *testing.T) {
	payload := []byte{'S', 'E', 'R', 'R', 'O', 'R', 0}
	msg := extractErrorMessage(payload)
	if msg != "unknown error" {
		t.Errorf("got %q, want %q", msg, "unknown error")
	}
}

// ── MySQL tests ──────────────────────────────────────────────────────────────

// mysqlServer simulates a minimal MySQL backend that responds to COM_QUERY
// EXPLAIN commands with a text result set.
type mysqlServer struct {
	ln        net.Listener
	queryCost string // e.g. "123.45"
	errPkt    bool   // send ERR packet instead
}

func newMySQLServer(t *testing.T, queryCost string) *mysqlServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &mysqlServer{ln: ln, queryCost: queryCost}
	go s.serve(t)
	return s
}

func newMySQLErrorServer(t *testing.T) *mysqlServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &mysqlServer{ln: ln, errPkt: true}
	go s.serve(t)
	return s
}

func (s *mysqlServer) Addr() string { return s.ln.Addr().String() }

func (s *mysqlServer) serve(t *testing.T) {
	conn, err := s.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	// Read the COM_QUERY packet
	hdr := make([]byte, 4)
	if _, err := readFull(conn, hdr); err != nil {
		return
	}
	pktLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	pktBody := make([]byte, pktLen)
	readFull(conn, pktBody) //nolint:errcheck

	if s.errPkt {
		s.sendErrPacket(conn, 1064, "You have an error in your SQL syntax")
		return
	}

	// Build MySQL EXPLAIN FORMAT=JSON response
	jsonStr := `{"query_block":{"cost_info":{"query_cost":"` + s.queryCost + `"}}}`
	s.sendColumnCountPacket(conn, 1, 1)
	s.sendColumnDefPacket(conn, "EXPLAIN", 2)
	s.sendEOFPacket(conn, 3)
	s.sendRowPacket(conn, jsonStr, 4)
	s.sendEOFPacket(conn, 5)
}

func writeMySQLPacket(conn net.Conn, seqID byte, payload []byte) {
	l := len(payload)
	buf := make([]byte, 4+l)
	buf[0] = byte(l)
	buf[1] = byte(l >> 8)
	buf[2] = byte(l >> 16)
	buf[3] = seqID
	copy(buf[4:], payload)
	conn.Write(buf) //nolint:errcheck
}

func (s *mysqlServer) sendColumnCountPacket(conn net.Conn, count int, seq byte) {
	writeMySQLPacket(conn, seq, []byte{byte(count)})
}

func (s *mysqlServer) sendColumnDefPacket(conn net.Conn, name string, seq byte) {
	// Minimal column def: catalog(def) + various fixed strings + flags
	fields := []byte{
		3, 'd', 'e', 'f', // catalog = "def"
		0,                // schema = ""
		0,                // table = ""
		0,                // org_table = ""
		byte(len(name)),  // name length prefix
	}
	fields = append(fields, []byte(name)...)
	fields = append(fields,
		0,          // org_name = ""
		0x0c,       // length of fixed fields
		0x21, 0x00, // character set = utf8
		0x00, 0x00, 0x01, 0x00, // column length
		0xfd,       // column type = BLOB
		0x01, 0x00, // flags
		0x00,       // decimals
		0x00, 0x00, // filler
	)
	writeMySQLPacket(conn, seq, fields)
}

func (s *mysqlServer) sendEOFPacket(conn net.Conn, seq byte) {
	// EOF: 0xfe + warnings(2) + status(2)
	writeMySQLPacket(conn, seq, []byte{0xfe, 0x00, 0x00, 0x02, 0x00})
}

func (s *mysqlServer) sendRowPacket(conn net.Conn, val string, seq byte) {
	// Length-encoded string
	payload := make([]byte, 0, 1+len(val))
	payload = append(payload, byte(len(val)))
	payload = append(payload, []byte(val)...)
	writeMySQLPacket(conn, seq, payload)
}

func (s *mysqlServer) sendErrPacket(conn net.Conn, errCode uint16, msg string) {
	payload := make([]byte, 0, 3+6+len(msg))
	payload = append(payload, 0xff)
	payload = append(payload, byte(errCode), byte(errCode>>8))
	payload = append(payload, '#')
	payload = append(payload, "HY000"...)
	payload = append(payload, []byte(msg)...)
	writeMySQLPacket(conn, 1, payload)
}

func TestExplainMySQL_Success(t *testing.T) {
	srv := newMySQLServer(t, "456.78")
	defer srv.ln.Close()

	conn, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	result, err := ExplainMySQL(context.Background(), conn, "SELECT 1", 2*time.Second)
	if err != nil {
		t.Fatalf("ExplainMySQL error: %v", err)
	}
	if result.TotalCost != 456.78 {
		t.Errorf("TotalCost = %v, want 456.78", result.TotalCost)
	}
}

func TestExplainMySQL_ServerError(t *testing.T) {
	srv := newMySQLErrorServer(t)
	defer srv.ln.Close()

	conn, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, err = ExplainMySQL(context.Background(), conn, "SELECT 1", 2*time.Second)
	if err == nil {
		t.Fatal("expected error from MySQL ERR packet")
	}
}

func TestExplainMySQL_Timeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			buf := make([]byte, 512)
			conn.Read(buf) //nolint:errcheck
			time.Sleep(5 * time.Second)
			conn.Close()
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, err = ExplainMySQL(context.Background(), conn, "SELECT 1", 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestParseMySQLExplainJSON_Valid(t *testing.T) {
	input := `{"query_block":{"cost_info":{"query_cost":"99.50"}}}`
	result, err := parseMySQLExplainJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalCost != 99.50 {
		t.Errorf("TotalCost = %v, want 99.50", result.TotalCost)
	}
}

func TestParseMySQLExplainJSON_Empty(t *testing.T) {
	_, err := parseMySQLExplainJSON("")
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestParseMySQLExplainJSON_MissingCost(t *testing.T) {
	input := `{"query_block":{}}`
	_, err := parseMySQLExplainJSON(input)
	if err == nil {
		t.Fatal("expected error when query_cost is missing")
	}
}

func TestReadLenEnc_Values(t *testing.T) {
	tests := []struct {
		buf  []byte
		want uint64
	}{
		{[]byte{0x05}, 5},
		{[]byte{0xfc, 0x00, 0x01}, 256},
		{[]byte{0xfd, 0x01, 0x00, 0x01}, 65537},
	}
	for _, tc := range tests {
		got, _, err := readLenEnc(tc.buf, 0)
		if err != nil {
			t.Errorf("readLenEnc(%x) error: %v", tc.buf, err)
			continue
		}
		if got != tc.want {
			t.Errorf("readLenEnc(%x) = %d, want %d", tc.buf, got, tc.want)
		}
	}
}

func TestMySQLErrorMessage(t *testing.T) {
	// 0xff + errCode(2) + '#' + SQLSTATE(5) + message
	pkt := []byte{0xff, 0x48, 0x04, '#', 'H', 'Y', '0', '0', '0', 'S', 'y', 'n', 't', 'a', 'x'}
	msg := mysqlErrorMessage(pkt)
	if msg != "Syntax" {
		t.Errorf("got %q, want %q", msg, "Syntax")
	}
}

func TestMySQLErrorMessage_Short(t *testing.T) {
	// Too short — should return "unknown error"
	if got := mysqlErrorMessage([]byte{0xff}); got != "unknown error" {
		t.Errorf("got %q, want %q", got, "unknown error")
	}
}

func TestMySQLErrorMessage_NoSQLState(t *testing.T) {
	// 0xff + errCode(2) + message (no '#')
	pkt := []byte{0xff, 0x48, 0x04, 'b', 'a', 'd'}
	msg := mysqlErrorMessage(pkt)
	if msg != "bad" {
		t.Errorf("got %q, want %q", msg, "bad")
	}
}

func TestReadLenEnc_EightByte(t *testing.T) {
	buf := []byte{0xfe, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	got, _, err := readLenEnc(buf, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 1 {
		t.Errorf("got %d, want 1", got)
	}
}

func TestReadLenEnc_Underflow(t *testing.T) {
	// 0xfc = 2-byte, but only 1 byte available
	_, _, err := readLenEnc([]byte{0xfc, 0x01}, 0)
	if err == nil {
		t.Fatal("expected error for 2-byte underflow")
	}
}

func TestReadLenEnc_Underflow3(t *testing.T) {
	_, _, err := readLenEnc([]byte{0xfd, 0x01, 0x00}, 0)
	if err == nil {
		t.Fatal("expected error for 3-byte underflow")
	}
}

func TestReadLenEnc_Underflow8(t *testing.T) {
	_, _, err := readLenEnc([]byte{0xfe, 0x01, 0x00, 0x00}, 0)
	if err == nil {
		t.Fatal("expected error for 8-byte underflow")
	}
}

func TestReadLenEnc_BufferUnderflow(t *testing.T) {
	_, _, err := readLenEnc([]byte{}, 0)
	if err == nil {
		t.Fatal("expected error for empty buffer")
	}
}

func TestReadLenEncString_Null(t *testing.T) {
	// 0xfb = NULL
	val, newOff, err := readLenEncString([]byte{0xfb}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "" || newOff != 1 {
		t.Errorf("got %q off=%d, want \"\" 1", val, newOff)
	}
}

func TestReadLenEncString_Underflow(t *testing.T) {
	// length=10 but only 2 bytes available
	_, _, err := readLenEncString([]byte{0x0a, 'a', 'b'}, 0)
	if err == nil {
		t.Fatal("expected error for string underflow")
	}
}

func TestReadLenEncString_EmptyBuf(t *testing.T) {
	_, _, err := readLenEncString([]byte{}, 0)
	if err == nil {
		t.Fatal("expected error for empty buffer")
	}
}

// mysqlBadEOFServer sends a non-0xfe byte where EOF should come after column defs.
type mysqlBadEOFServer struct{ ln net.Listener }

func (s *mysqlBadEOFServer) Addr() string { return s.ln.Addr().String() }

func newMySQLBadEOFServer(t *testing.T) *mysqlBadEOFServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &mysqlBadEOFServer{ln: ln}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read COM_QUERY
		hdr := make([]byte, 4)
		io.ReadFull(conn, hdr) //nolint:errcheck
		pktLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
		body := make([]byte, pktLen)
		io.ReadFull(conn, body) //nolint:errcheck

		// Column count = 1
		writeMySQLPacket(conn, 1, []byte{0x01})
		// Column def
		writeMySQLPacket(conn, 2, []byte{'d', 'e', 'f'})
		// Send 0x00 instead of 0xfe (not an EOF)
		writeMySQLPacket(conn, 3, []byte{0x00, 0x00, 0x00, 0x00, 0x00})
	}()
	return s
}

func TestExplainMySQL_BadEOFAfterColumns(t *testing.T) {
	srv := newMySQLBadEOFServer(t)
	defer srv.ln.Close()

	conn, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, err = ExplainMySQL(context.Background(), conn, "SELECT 1", 2*time.Second)
	if err == nil {
		t.Fatal("expected error for bad EOF packet")
	}
}

// mysqlRowErrServer sends an ERR row packet after column defs.
type mysqlRowErrServer struct{ ln net.Listener }

func newMySQLRowErrServer(t *testing.T) *mysqlRowErrServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &mysqlRowErrServer{ln: ln}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		hdr := make([]byte, 4)
		io.ReadFull(conn, hdr) //nolint:errcheck
		pktLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
		body := make([]byte, pktLen)
		io.ReadFull(conn, body) //nolint:errcheck

		writeMySQLPacket(conn, 1, []byte{0x01})                     // col count=1
		writeMySQLPacket(conn, 2, []byte{'d', 'e', 'f'})            // col def
		writeMySQLPacket(conn, 3, []byte{0xfe, 0x00, 0x00, 0x02, 0x00}) // EOF
		// ERR row
		errPkt := []byte{0xff, 0x48, 0x04, '#', 'H', 'Y', '0', '0', '0', 'f', 'a', 'i', 'l'}
		writeMySQLPacket(conn, 4, errPkt)
	}()
	return s
}

func TestExplainMySQL_RowErrPacket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		hdr := make([]byte, 4)
		io.ReadFull(conn, hdr) //nolint:errcheck
		pktLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
		body := make([]byte, pktLen)
		io.ReadFull(conn, body) //nolint:errcheck

		writeMySQLPacket(conn, 1, []byte{0x01})
		writeMySQLPacket(conn, 2, []byte{'d', 'e', 'f'})
		writeMySQLPacket(conn, 3, []byte{0xfe, 0x00, 0x00, 0x02, 0x00})
		errPkt := []byte{0xff, 0x48, 0x04, '#', 'H', 'Y', '0', '0', '0', 'f', 'a', 'i', 'l'}
		writeMySQLPacket(conn, 4, errPkt)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, err = ExplainMySQL(context.Background(), conn, "SELECT 1", 2*time.Second)
	if err == nil {
		t.Fatal("expected error for row ERR packet")
	}
}

func TestParseMySQLExplainJSON_InvalidJSON(t *testing.T) {
	_, err := parseMySQLExplainJSON("{not json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseMySQLExplainJSON_InvalidCost(t *testing.T) {
	// query_cost present but not parseable as float
	input := `{"query_block":{"cost_info":{"query_cost":"not-a-number"}}}`
	_, err := parseMySQLExplainJSON(input)
	if err == nil {
		t.Fatal("expected error for non-numeric query_cost")
	}
}

func TestExplainPG_ContextDeadlineAlreadyPassed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Already-expired context
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	_, err = ExplainPG(ctx, conn, "SELECT 1", 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected error with expired context")
	}
}

func TestExplainMySQL_ContextDeadlineAlreadyPassed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	_, err = ExplainMySQL(ctx, conn, "SELECT 1", 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected error with expired context")
	}
}

// ── Connection-closed error path tests ────────────────────────────────────────

// TestReadMessage_EOF exercises the readMessage EOF path.
func TestReadMessage_EOF(t *testing.T) {
	client, server := net.Pipe()
	server.Close() // immediate EOF
	_, _, err := readMessage(client)
	if err == nil {
		t.Fatal("expected EOF error from readMessage")
	}
	client.Close()
}

// TestReadMessage_ShortPayload exercises the readMessage payload read error.
func TestReadMessage_ShortPayload(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		// Send 5-byte header (type + 4 bytes length = 4+100 = 104 bytes)
		// but then close without sending the payload.
		hdr := []byte{'T', 0, 0, 0, 108} // length=104
		server.Write(hdr)                  //nolint:errcheck
		server.Close()
	}()
	_, _, err := readMessage(client)
	if err == nil {
		t.Fatal("expected error reading truncated payload")
	}
	client.Close()
}

// TestExtractDataRowText_TruncatedField exercises the boundary check.
func TestExtractDataRowText_TruncatedField(t *testing.T) {
	// fieldCount=1, but field length says 100 bytes, only 0 bytes follow
	payload := make([]byte, 6)
	binary.BigEndian.PutUint16(payload[:2], 1)   // 1 field
	binary.BigEndian.PutUint32(payload[2:], 100) // length=100, but no data
	result := extractDataRowText(payload)
	// Should return empty (out of bounds guard)
	if result != "" {
		t.Errorf("expected empty for truncated field, got %q", result)
	}
}

// TestExtractDataRowText_TooShort exercises the len(payload) < 2 guard.
func TestExtractDataRowText_TooShort(t *testing.T) {
	result := extractDataRowText([]byte{})
	if result != "" {
		t.Errorf("expected empty for empty payload, got %q", result)
	}
	result = extractDataRowText([]byte{0x01})
	if result != "" {
		t.Errorf("expected empty for 1-byte payload, got %q", result)
	}
}

// TestExplainPG_DefaultTimeout exercises the timeout <= 0 default path.
func TestExplainPG_DefaultTimeout(t *testing.T) {
	srv := newPGServer(t, 42.0)
	defer srv.ln.Close()

	conn, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Pass timeout=0, which should use DefaultTimeout
	result, err := ExplainPG(context.Background(), conn, "SELECT 1", 0)
	if err != nil {
		t.Fatalf("ExplainPG error: %v", err)
	}
	if result.TotalCost != 42.0 {
		t.Errorf("TotalCost = %v, want 42.0", result.TotalCost)
	}
}

// TestExplainMySQL_DefaultTimeout exercises the timeout <= 0 default path.
func TestExplainMySQL_DefaultTimeout(t *testing.T) {
	srv := newMySQLServer(t, "99.0")
	defer srv.ln.Close()

	conn, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Pass timeout=0, which should use DefaultTimeout
	result, err := ExplainMySQL(context.Background(), conn, "SELECT 1", 0)
	if err != nil {
		t.Fatalf("ExplainMySQL error: %v", err)
	}
	if result.TotalCost != 99.0 {
		t.Errorf("TotalCost = %v, want 99.0", result.TotalCost)
	}
}

// deadlineErrorConn wraps a net.Conn and makes SetWriteDeadline or
// SetReadDeadline return an error.
type deadlineErrorConn struct {
	net.Conn
	failWrite bool
	failRead  bool
}

func (c *deadlineErrorConn) SetWriteDeadline(t time.Time) error {
	if c.failWrite && !t.IsZero() {
		return net.ErrClosed
	}
	return c.Conn.SetWriteDeadline(t)
}

func (c *deadlineErrorConn) SetReadDeadline(t time.Time) error {
	if c.failRead && !t.IsZero() {
		return net.ErrClosed
	}
	return c.Conn.SetReadDeadline(t)
}

// TestExplainPG_SetWriteDeadlineError exercises the SetWriteDeadline error path.
func TestExplainPG_SetWriteDeadlineError(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	wrapped := &deadlineErrorConn{Conn: client, failWrite: true}
	_, err := ExplainPG(context.Background(), wrapped, "SELECT 1", time.Second)
	if err == nil {
		t.Fatal("expected error from SetWriteDeadline failure")
	}
}

// TestExplainPG_SetReadDeadlineError exercises the SetReadDeadline error path.
func TestExplainPG_SetReadDeadlineError(t *testing.T) {
	// We need Write to succeed but SetReadDeadline to fail.
	// Use a real TCP connection with a server that accepts but doesn't respond.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			buf := make([]byte, 4096)
			conn.Read(buf)
			time.Sleep(2 * time.Second)
			conn.Close()
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	wrapped := &deadlineErrorConn{Conn: conn, failRead: true}
	_, err = ExplainPG(context.Background(), wrapped, "SELECT 1", time.Second)
	if err == nil {
		t.Fatal("expected error from SetReadDeadline failure")
	}
}

// TestExplainMySQL_SetWriteDeadlineError exercises the SetWriteDeadline error path.
func TestExplainMySQL_SetWriteDeadlineError(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	wrapped := &deadlineErrorConn{Conn: client, failWrite: true}
	_, err := ExplainMySQL(context.Background(), wrapped, "SELECT 1", time.Second)
	if err == nil {
		t.Fatal("expected error from SetWriteDeadline failure")
	}
}

// TestExplainMySQL_SetReadDeadlineError exercises the SetReadDeadline error path.
func TestExplainMySQL_SetReadDeadlineError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			buf := make([]byte, 4096)
			conn.Read(buf)
			time.Sleep(2 * time.Second)
			conn.Close()
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	wrapped := &deadlineErrorConn{Conn: conn, failRead: true}
	_, err = ExplainMySQL(context.Background(), wrapped, "SELECT 1", time.Second)
	if err == nil {
		t.Fatal("expected error from SetReadDeadline failure")
	}
}

// TestReadLenEnc_DefaultCase exercises the default/0xff branch in readLenEnc.
func TestReadLenEnc_DefaultCase(t *testing.T) {
	// 0xff is the NULL marker in MySQL length-encoded integers
	_, _, err := readLenEnc([]byte{0xff}, 0)
	if err == nil {
		t.Fatal("expected error for 0xff (NULL) length-encoded int")
	}
}

// TestReadMySQLExplainResult_ZeroColumnCount exercises colCount == 0 path.
func TestReadMySQLExplainResult_ZeroColumnCount(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		// Send a column count packet with value 0
		writeMySQLPacket(server, 1, []byte{0x00})
		server.Close()
	}()
	defer client.Close()

	_, err := readMySQLExplainResult(client)
	if err == nil {
		t.Fatal("expected error for zero column count")
	}
}

// TestReadMySQLExplainResult_EmptyRowPacket exercises the len(row)==0 continue path.
func TestReadMySQLExplainResult_EmptyRowPacket(t *testing.T) {
	client, server := net.Pipe()

	queryCost := `{"query_block":{"cost_info":{"query_cost":"10.0"}}}`

	go func() {
		// Column count = 1
		writeMySQLPacket(server, 1, []byte{0x01})
		// Column def
		writeMySQLPacket(server, 2, []byte{'d', 'e', 'f'})
		// EOF
		writeMySQLPacket(server, 3, []byte{0xfe, 0x00, 0x00, 0x02, 0x00})
		// Empty row packet (length=0 payload)
		writeMySQLPacket(server, 4, []byte{})
		// Real data row
		row := make([]byte, 0, 1+len(queryCost))
		row = append(row, byte(len(queryCost)))
		row = append(row, []byte(queryCost)...)
		writeMySQLPacket(server, 5, row)
		// EOF
		writeMySQLPacket(server, 6, []byte{0xfe, 0x00, 0x00, 0x02, 0x00})
		server.Close()
	}()
	defer client.Close()

	result, err := readMySQLExplainResult(client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalCost != 10.0 {
		t.Errorf("TotalCost = %v, want 10.0", result.TotalCost)
	}
}

// TestReadMySQLPacket_ZeroLength verifies empty packet handling.
func TestReadMySQLPacket_ZeroLength(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		// Send 4-byte header with length=0
		server.Write([]byte{0, 0, 0, 1}) //nolint:errcheck
		server.Close()
	}()
	pkt, err := readMySQLPacket(client)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkt) != 0 {
		t.Errorf("expected empty packet, got len=%d", len(pkt))
	}
	client.Close()
}

// TestExplainMySQL_ColDefReadError exercises column def read failure.
func TestExplainMySQL_ColDefReadError(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		// COM_QUERY header
		hdr := make([]byte, 4)
		io.ReadFull(server, hdr) //nolint:errcheck
		pktLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
		body := make([]byte, pktLen)
		io.ReadFull(server, body) //nolint:errcheck

		// Column count = 1
		writeMySQLPacket(server, 1, []byte{0x01})
		// Then close without sending column def
	}()

	_, err := ExplainMySQL(context.Background(), client, "SELECT 1", 2*time.Second)
	if err == nil {
		t.Fatal("expected error when column def read fails")
	}
	client.Close()
}

// TestExplainMySQL_EOFAfterColError exercises EOF packet read failure.
func TestExplainMySQL_EOFAfterColError(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		hdr := make([]byte, 4)
		io.ReadFull(server, hdr) //nolint:errcheck
		pktLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
		body := make([]byte, pktLen)
		io.ReadFull(server, body) //nolint:errcheck

		writeMySQLPacket(server, 1, []byte{0x01})            // col count
		writeMySQLPacket(server, 2, []byte{'d', 'e', 'f'})   // col def
		// Close before EOF packet
	}()

	_, err := ExplainMySQL(context.Background(), client, "SELECT 1", 2*time.Second)
	if err == nil {
		t.Fatal("expected error when EOF packet missing")
	}
	client.Close()
}

// TestExplainMySQL_RowReadError exercises row read failure.
func TestExplainMySQL_RowReadError(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		hdr := make([]byte, 4)
		io.ReadFull(server, hdr) //nolint:errcheck
		pktLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
		body := make([]byte, pktLen)
		io.ReadFull(server, body) //nolint:errcheck

		writeMySQLPacket(server, 1, []byte{0x01})
		writeMySQLPacket(server, 2, []byte{'d', 'e', 'f'})
		writeMySQLPacket(server, 3, []byte{0xfe, 0x00, 0x00, 0x02, 0x00}) // EOF
		// Close before row
	}()

	_, err := ExplainMySQL(context.Background(), client, "SELECT 1", 2*time.Second)
	if err == nil {
		t.Fatal("expected error when row read fails")
	}
	client.Close()
}

// TestExplainMySQL_EmptyColumnCount exercises zero-length column count packet.
func TestExplainMySQL_EmptyColumnCount(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		hdr := make([]byte, 4)
		io.ReadFull(server, hdr) //nolint:errcheck
		pktLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
		body := make([]byte, pktLen)
		io.ReadFull(server, body) //nolint:errcheck

		// Send zero-length packet (empty column count)
		server.Write([]byte{0, 0, 0, 1}) //nolint:errcheck
	}()

	_, err := ExplainMySQL(context.Background(), client, "SELECT 1", 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected error for empty column count packet")
	}
	client.Close()
}

// TestMySQLErrorMessage_EmptyAfterSQLState verifies no message after SQLSTATE.
func TestMySQLErrorMessage_EmptyAfterSQLState(t *testing.T) {
	// 0xff + errCode(2) + '#' + 'HYABC' only (no trailing message)
	pkt := []byte{0xff, 0x48, 0x04, '#', 'H', 'Y', 'A', 'B', 'C'}
	msg := mysqlErrorMessage(pkt)
	// off=9 which equals len(pkt), should return "unknown error"
	if msg != "unknown error" {
		t.Errorf("got %q, want %q", msg, "unknown error")
	}
}

// TestReadMessage_NegativeLength exercises the negative msgLen guard.
func TestReadMessage_NegativeLength(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		// Send type 'T' + length=3 (int32 big-endian = 0x00000003),
		// which gives msgLen = 3-4 = -1
		server.Write([]byte{'T', 0x00, 0x00, 0x00, 0x03}) //nolint:errcheck
	}()
	_, _, err := readMessage(client)
	if err == nil {
		t.Fatal("expected error for negative message length")
	}
	client.Close()
}

// TestExtractDataRowText_ShortHeader exercises the off+4 > len(payload) guard.
func TestExtractDataRowText_ShortHeader(t *testing.T) {
	// fieldCount=1, but only 2 bytes remain after the count (not 4 needed for length)
	payload := make([]byte, 4) // fieldCount(2) + only 2 bytes
	binary.BigEndian.PutUint16(payload[:2], 1)
	result := extractDataRowText(payload)
	if result != "" {
		t.Errorf("expected empty for short header, got %q", result)
	}
}

// TestReadMySQLPacket_truncatedPayload exercises io.ReadFull failure for payload.
func TestReadMySQLPacket_TruncatedPayload(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		// Send header saying 10 bytes but only write 3
		server.Write([]byte{0x0a, 0x00, 0x00, 0x01}) //nolint:errcheck
		server.Write([]byte{0x01, 0x02, 0x03})        //nolint:errcheck
		// close — truncated
	}()
	_, err := readMySQLPacket(client)
	if err == nil {
		t.Fatal("expected error for truncated payload")
	}
	client.Close()
}

// TestReadLenEncString_LenEncError exercises the error path from readLenEnc.
func TestReadLenEncString_LenEncError(t *testing.T) {
	// 0xfc = 2-byte length but only 1 byte after
	_, _, err := readLenEncString([]byte{0xfc, 0x01}, 0)
	if err == nil {
		t.Fatal("expected error when readLenEnc fails inside readLenEncString")
	}
}
