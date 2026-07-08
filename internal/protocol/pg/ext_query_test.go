package pg

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/policy"
)

func TestIsExtendedQueryMsgAll(t *testing.T) {
	extended := []byte{MsgParse, 'B', 'D', 'E', 'S', 'C', MsgFlush}
	for _, m := range extended {
		if !IsExtendedQueryMsg(m) {
			t.Errorf("0x%02x should be extended query", m)
		}
	}
	nonExtended := []byte{MsgQuery, MsgTerminate, MsgAuth, MsgReadyForQuery}
	for _, m := range nonExtended {
		if IsExtendedQueryMsg(m) {
			t.Errorf("0x%02x should NOT be extended query", m)
		}
	}
}

func TestForwardResultWithCopyInResponse(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		// Backend sends CopyInResponse
		WriteMessage(backendConn, &Message{Type: MsgCopyInResponse, Payload: []byte{0, 0, 1, 0, 0}})
		// Read CopyDone from proxy
		ReadMessage(backendConn)
		// Send CommandComplete + ReadyForQuery
		WriteMessage(backendConn, BuildCommandComplete("COPY 0"))
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	go func() {
		// Client reads CopyInResponse
		ReadMessage(clientConn)
		// Client sends CopyDone
		WriteMessage(clientConn, &Message{Type: MsgCopyDone, Payload: nil})
		// Read CommandComplete + ReadyForQuery
		ReadMessage(clientConn)
		ReadMessage(clientConn)
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	stats, err := ForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("ForwardResult COPY IN: %v", err)
	}
	_ = stats
}

func TestForwardResultWithCopyOutResponse(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		// Backend sends CopyOutResponse + CopyData + CopyDone
		WriteMessage(backendConn, &Message{Type: MsgCopyOutResponse, Payload: []byte{0, 0, 1, 0, 0}})
		WriteMessage(backendConn, &Message{Type: MsgCopyData, Payload: []byte("data\n")})
		WriteMessage(backendConn, &Message{Type: MsgCopyDone, Payload: nil})
		WriteMessage(backendConn, BuildCommandComplete("COPY 1"))
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	go func() {
		for range 5 {
			ReadMessage(clientConn)
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	stats, err := ForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("ForwardResult COPY OUT: %v", err)
	}
	_ = stats
}

func TestForwardResultWithError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		WriteMessage(backendConn, BuildErrorResponse("ERROR", "42P01", "relation not found"))
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	go func() {
		ReadMessage(clientConn) // error
		ReadMessage(clientConn) // ready
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))

	stats, err := ForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("ForwardResult error: %v", err)
	}
	_ = stats
}

func TestForwardResultEmptyQuery(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		WriteMessage(backendConn, &Message{Type: MsgEmptyQuery, Payload: nil})
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	go func() {
		ReadMessage(clientConn)
		ReadMessage(clientConn)
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))

	stats, err := ForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("ForwardResult empty: %v", err)
	}
	_ = stats
}

func TestForwardResultExtendedQueryTokens(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		WriteMessage(backendConn, &Message{Type: MsgParseComplete, Payload: nil})
		WriteMessage(backendConn, &Message{Type: MsgBindComplete, Payload: nil})
		// RowDescription + DataRow
		var rd []byte
		rd = append(rd, 0, 1)
		rd = append(rd, []byte("x")...)
		rd = append(rd, 0)
		rd = append(rd, make([]byte, 18)...)
		WriteMessage(backendConn, &Message{Type: MsgRowDescription, Payload: rd})
		WriteMessage(backendConn, BuildDataRow([][]byte{[]byte("1")}))
		WriteMessage(backendConn, BuildCommandComplete("SELECT 1"))
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	go func() {
		for range 6 {
			ReadMessage(clientConn)
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	stats, err := ForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if stats.RowCount != 1 {
		t.Errorf("rows = %d", stats.RowCount)
	}
}

func TestForwardResultWithTruncation(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		var rd []byte
		rd = append(rd, 0, 1)
		rd = append(rd, []byte("v")...)
		rd = append(rd, 0)
		rd = append(rd, make([]byte, 18)...)
		WriteMessage(backendConn, &Message{Type: MsgRowDescription, Payload: rd})
		// 5 rows but limit is 2
		for range 5 {
			WriteMessage(backendConn, BuildDataRow([][]byte{[]byte("x")}))
		}
		WriteMessage(backendConn, BuildCommandComplete("SELECT 5"))
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	go func() {
		for range 10 {
			m, err := ReadMessage(clientConn)
			if err != nil { return }
			if m.Type == MsgReadyForQuery { return }
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	rules := []policy.MaskingRule{{Column: "v", Transformer: "redact"}}
	pipeline := masking.NewPipeline(rules, nil, 2) // max 2 rows

	stats, err := ForwardResult(context.Background(), proxyBackend, proxyClient, pipeline)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !stats.Truncated {
		t.Error("should be truncated (limit=2, sent 5)")
	}
}

func TestReadMessageInvalidLength(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		// Type + length = 2 (less than 4 = invalid)
		buf := []byte{'Q', 0, 0, 0, 2}
		clientConn.Write(buf)
	}()

	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadMessage(serverConn)
	if err == nil {
		t.Error("should fail on invalid length")
	}
}

func TestReadExtendedBatchWithFlush(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	go func() {
		// Parse + Flush (not Sync)
		var p []byte
		p = append(p, 0)
		p = append(p, []byte("SELECT 1")...)
		p = append(p, 0, 0, 0)
		WriteMessage(clientConn, &Message{Type: MsgParse, Payload: p})
		WriteMessage(clientConn, &Message{Type: MsgFlush, Payload: nil})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	cmd, _, err := ReadQueryCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if cmd.Raw != "SELECT 1" {
		t.Errorf("SQL = %q", cmd.Raw)
	}
}

func TestReadExtendedBatchTerminate(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	defer proxyConn.Close()

	go func() {
		var p []byte
		p = append(p, 0)
		p = append(p, []byte("SELECT 1")...)
		p = append(p, 0, 0, 0)
		WriteMessage(clientConn, &Message{Type: MsgParse, Payload: p})
		WriteMessage(clientConn, &Message{Type: MsgTerminate, Payload: nil})
	}()

	proxyConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	cmd, _, err := ReadQueryCommand(context.Background(), proxyConn)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	_ = cmd
}

func TestHandleCopyInContextCancel(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	_, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer backendConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancel

	err := HandleCopyIn(ctx, proxyClient, backendConn)
	if err == nil {
		t.Error("should fail with cancelled context")
	}
}

func TestHandleCopyOutContextCancel(t *testing.T) {
	_, backendConn := net.Pipe()
	proxyClient, _ := net.Pipe()
	defer backendConn.Close()
	defer proxyClient.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := HandleCopyOut(ctx, backendConn, proxyClient)
	if err == nil {
		t.Error("should fail with cancelled context")
	}
}

func TestParseStartupMessageShort(t *testing.T) {
	_, err := ParseStartupMessage([]byte{0, 0, 0, 4})
	if err == nil {
		t.Error("4-byte message should fail (too short)")
	}
}

func TestParseDataRowTruncated(t *testing.T) {
	// 1 field, but data is truncated
	payload := []byte{0, 1, 0, 0, 0, 10} // says 10 bytes but only 1 available
	_, err := ParseDataRow(payload)
	if err == nil {
		t.Error("truncated data should fail")
	}
}

func TestParseRowDescriptionTruncated(t *testing.T) {
	// Says 1 column but no data
	payload := []byte{0, 1}
	_, err := ParseRowDescription(payload)
	if err == nil {
		t.Error("truncated row description should fail")
	}
}

func TestBuildStartupMessageAndParse(t *testing.T) {
	msg := BuildStartupMessage(map[string]string{
		"user":             "testuser",
		"database":         "testdb",
		"application_name": "argus_test",
	})

	parsed, err := ParseStartupMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Parameters["user"] != "testuser" {
		t.Error("user mismatch")
	}
	if parsed.Parameters["application_name"] != "argus_test" {
		t.Error("app name mismatch")
	}
	if parsed.ProtocolVersion != 0x00030000 {
		t.Errorf("version = 0x%08x", parsed.ProtocolVersion)
	}
}
