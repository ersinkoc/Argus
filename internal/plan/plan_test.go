package plan

import (
	"context"
	"encoding/binary"
	"encoding/json"
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
