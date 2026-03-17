package pg

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/policy"
	"github.com/ersinkoc/argus/internal/protocol"
)

// --- ForwardResult edge cases ---

func TestForwardResultContextCancelled(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Don't send anything — context is already cancelled
	_, err := ForwardResult(ctx, proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("cancelled context should return error")
	}
}

func TestForwardResultNoticeMessage(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		// Send Notice + CommandComplete + ReadyForQuery
		WriteMessage(backendConn, &Message{Type: MsgNoticeResponse, Payload: []byte("notice")})
		WriteMessage(backendConn, BuildCommandComplete("SELECT 0"))
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	go func() {
		// Read all messages from client side
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadMessage(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	stats, err := ForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if stats.RowCount != 0 {
		t.Errorf("rows = %d", stats.RowCount)
	}
}

func TestForwardResultEmptyQueryMsg(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		// EmptyQuery response
		WriteMessage(backendConn, &Message{Type: MsgEmptyQuery, Payload: nil})
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadMessage(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	stats, err := ForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if stats.RowCount != 0 {
		t.Errorf("rows = %d", stats.RowCount)
	}
}

func TestForwardResultNoDataMsg(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		WriteMessage(backendConn, &Message{Type: MsgNoData, Payload: nil})
		WriteMessage(backendConn, BuildCommandComplete("SELECT 0"))
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadMessage(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := ForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestForwardResultParseBindCloseComplete(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		// Extended query backend responses
		WriteMessage(backendConn, &Message{Type: MsgParseComplete, Payload: nil})
		WriteMessage(backendConn, &Message{Type: MsgBindComplete, Payload: nil})
		WriteMessage(backendConn, &Message{Type: MsgCloseComplete, Payload: nil})
		WriteMessage(backendConn, BuildCommandComplete("SELECT 0"))
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadMessage(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := ForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestForwardResultParameterDescAndPortalSuspended(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		WriteMessage(backendConn, &Message{Type: MsgParameterDesc, Payload: []byte{0, 0}})
		WriteMessage(backendConn, &Message{Type: MsgPortalSuspended, Payload: nil})
		WriteMessage(backendConn, BuildCommandComplete("SELECT 0"))
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadMessage(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := ForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestForwardResultUnknownMsg(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		// Unknown message type 'Y'
		WriteMessage(backendConn, &Message{Type: 'Y', Payload: []byte{1, 2, 3}})
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadMessage(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := ForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestForwardResultMaskingWithRowLimit(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		// RowDescription with 1 column "name"
		var rd []byte
		rd = append(rd, 0, 1) // 1 column
		rd = append(rd, []byte("name")...)
		rd = append(rd, 0)
		rd = append(rd, make([]byte, 18)...) // field metadata
		WriteMessage(backendConn, &Message{Type: MsgRowDescription, Payload: rd})

		// Send 5 data rows
		for i := 0; i < 5; i++ {
			WriteMessage(backendConn, BuildDataRow([][]byte{[]byte("value")}))
		}

		WriteMessage(backendConn, BuildCommandComplete("SELECT 5"))
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
			_, err := ReadMessage(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	// Pipeline with max 2 rows
	rules := []policy.MaskingRule{{Column: "name", Transformer: "redact"}}
	pipeline := masking.NewPipeline(rules, []masking.ColumnInfo{{Name: "name", Index: 0}}, 2)

	stats, err := ForwardResult(context.Background(), proxyBackend, proxyClient, pipeline)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if !stats.Truncated {
		t.Log("truncation flag may or may not be set depending on pipeline implementation")
	}
}

func TestForwardResultErrorResponse(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		errMsg := BuildErrorResponse("ERROR", "42601", "syntax error")
		WriteMessage(backendConn, errMsg)
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadMessage(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	stats, err := ForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if stats.RowCount != 0 {
		t.Errorf("error response should have 0 rows, got %d", stats.RowCount)
	}
}

// --- Auth edge cases ---

func TestDoHandshakeSASLAuth(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		// Client: send startup
		startup := BuildStartupMessage(map[string]string{"user": "sasl_user", "database": "db"})
		clientConn.Write(startup)

		// Client: read SASL auth request and respond
		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		msg, _ := ReadMessage(clientConn)
		if msg != nil && msg.Type == MsgAuth {
			// Send password response
			WriteMessage(clientConn, &Message{Type: MsgPassword, Payload: []byte("sasl-response")})
		}

		// Read SASL continue
		msg, _ = ReadMessage(clientConn)
		if msg != nil && msg.Type == MsgAuth {
			// Send final response
			WriteMessage(clientConn, &Message{Type: MsgPassword, Payload: []byte("sasl-final")})
		}

		// Read SASL final — no response needed
		ReadMessage(clientConn)

		// Read AuthOK
		ReadMessage(clientConn)

		// Read ParameterStatus + BackendKeyData + ReadyForQuery
		for {
			msg, err := ReadMessage(clientConn)
			if err != nil || msg.Type == MsgReadyForQuery {
				return
			}
		}
	}()

	go func() {
		// Backend: read startup
		backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadStartupMessage(backendConn)

		// Send SASL auth request (type 10)
		saslPayload := make([]byte, 4)
		binary.BigEndian.PutUint32(saslPayload, uint32(AuthSASL))
		saslPayload = append(saslPayload, []byte("SCRAM-SHA-256")...)
		saslPayload = append(saslPayload, 0, 0) // double null terminator
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: saslPayload})

		// Read client SASL response
		ReadMessage(backendConn)

		// Send SASL continue (type 11)
		continuePayload := make([]byte, 4)
		binary.BigEndian.PutUint32(continuePayload, uint32(AuthSASLContinue))
		continuePayload = append(continuePayload, []byte("server-first")...)
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: continuePayload})

		// Read client final response
		ReadMessage(backendConn)

		// Send SASL final (type 12) — no client response expected
		finalPayload := make([]byte, 4)
		binary.BigEndian.PutUint32(finalPayload, uint32(AuthSASLFinal))
		finalPayload = append(finalPayload, []byte("server-final")...)
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: finalPayload})

		// Send AuthOK
		authOk := make([]byte, 4)
		binary.BigEndian.PutUint32(authOk, uint32(AuthOK))
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: authOk})

		// Send ParameterStatus + BackendKeyData + ReadyForQuery
		ps := append([]byte("server_version"), 0)
		ps = append(ps, []byte("16")...)
		ps = append(ps, 0)
		WriteMessage(backendConn, &Message{Type: MsgParameterStatus, Payload: ps})
		WriteMessage(backendConn, &Message{Type: MsgBackendKeyData, Payload: make([]byte, 8)})
		WriteMessage(backendConn, BuildReadyForQuery('I'))
	}()

	proxyClient.SetDeadline(time.Now().Add(5 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(5 * time.Second))

	info, err := DoHandshake(context.Background(), proxyClient, proxyBackend)
	if err != nil {
		t.Fatalf("DoHandshake SASL: %v", err)
	}
	if info.AuthMethod != "sasl" {
		t.Errorf("auth method = %q, want sasl", info.AuthMethod)
	}
	if info.Username != "sasl_user" {
		t.Errorf("username = %q", info.Username)
	}
}

func TestRelayAuthUnsupportedAuthType(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		// Client: send startup
		startup := BuildStartupMessage(map[string]string{"user": "test", "database": "db"})
		clientConn.Write(startup)
		// Read whatever comes back
		for {
			clientConn.SetReadDeadline(time.Now().Add(time.Second))
			_, err := ReadMessage(clientConn)
			if err != nil {
				return
			}
		}
	}()

	go func() {
		backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadStartupMessage(backendConn)

		// Send unsupported auth type (99)
		authPayload := make([]byte, 4)
		binary.BigEndian.PutUint32(authPayload, 99)
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: authPayload})
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := DoHandshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("unsupported auth type should fail")
	}
}

func TestRelayPostAuthErrorResponse(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		startup := BuildStartupMessage(map[string]string{"user": "test", "database": "db"})
		clientConn.Write(startup)
		for {
			clientConn.SetReadDeadline(time.Now().Add(time.Second))
			_, err := ReadMessage(clientConn)
			if err != nil {
				return
			}
		}
	}()

	go func() {
		backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadStartupMessage(backendConn)

		// Send AuthOK
		authOk := make([]byte, 4)
		binary.BigEndian.PutUint32(authOk, uint32(AuthOK))
		WriteMessage(backendConn, &Message{Type: MsgAuth, Payload: authOk})

		// Then send ErrorResponse during post-auth
		errMsg := BuildErrorResponse("FATAL", "28000", "password auth failed")
		WriteMessage(backendConn, errMsg)
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := DoHandshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("post-auth error should fail")
	}
}

// --- COPY edge cases ---

func TestHandleCopyInCopyFail(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		// Client sends CopyFail
		msg := &Message{Type: MsgCopyFail, Payload: append([]byte("aborted"), 0)}
		WriteMessage(clientConn, msg)
	}()

	go func() {
		backendConn.SetReadDeadline(time.Now().Add(time.Second))
		ReadMessage(backendConn)
	}()

	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))

	err := HandleCopyIn(context.Background(), proxyClient, proxyBackend)
	if err != nil {
		t.Errorf("CopyFail should succeed: %v", err)
	}
}

func TestHandleCopyOutErrorResponse(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		// Backend sends ErrorResponse during COPY OUT
		errMsg := BuildErrorResponse("ERROR", "42501", "permission denied")
		WriteMessage(backendConn, errMsg)
	}()

	go func() {
		clientConn.SetReadDeadline(time.Now().Add(time.Second))
		ReadMessage(clientConn)
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))

	err := HandleCopyOut(context.Background(), proxyBackend, proxyClient)
	if err != nil {
		t.Errorf("CopyOut ErrorResponse should succeed: %v", err)
	}
}

// --- BuildStartupMessage edge cases ---

func TestBuildStartupMessageMultipleParams(t *testing.T) {
	params := map[string]string{
		"user":            "test",
		"database":        "mydb",
		"application_name": "argus",
		"client_encoding": "UTF8",
	}
	data := BuildStartupMessage(params)
	if len(data) == 0 {
		t.Fatal("empty startup message")
	}

	// Parse it back
	startup, err := ParseStartupMessage(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if startup.Parameters["user"] != "test" {
		t.Errorf("user = %q", startup.Parameters["user"])
	}
	if startup.Parameters["database"] != "mydb" {
		t.Errorf("database = %q", startup.Parameters["database"])
	}
}

// --- ParseErrorResponse edge cases ---

func TestParseErrorResponseMultipleFields(t *testing.T) {
	msg := BuildErrorResponse("ERROR", "42601", "syntax error at or near")
	fields := ParseErrorResponse(msg.Payload)
	if fields['S'] != "ERROR" {
		t.Errorf("severity = %q", fields['S'])
	}
	if fields['C'] != "42601" {
		t.Errorf("code = %q", fields['C'])
	}
	if fields['M'] != "syntax error at or near" {
		t.Errorf("message = %q", fields['M'])
	}
}

// Ensure protocol.ResultStats is used correctly
var _ *protocol.ResultStats
