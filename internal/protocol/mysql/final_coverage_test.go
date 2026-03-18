package mysql

import (
	"context"
	"net"
	"testing"
	"time"
)

// --- Handshake: forward greeting write error ---

func TestHandshakeForwardGreetingError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer proxyBackend.Close()
	defer backendConn.Close()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(0, "8.0"))
	}()

	clientConn.Close() // close client before greeting arrives

	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	proxyClient.Close()
	if err == nil {
		t.Error("forward greeting write error should fail")
	}
}

// --- Handshake: forward to backend write error ---

func TestHandshakeForwardToBackendError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(0, "8.0"))
		backendConn.Close() // close backend after sending greeting
	}()

	go func() {
		ReadPacket(clientConn) // greeting
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("u")...)
		payload = append(payload, 0, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("forward to backend error should fail")
	}
}

// --- Handshake: forward auth result write error ---

func TestHandshakeForwardAuthResultError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(0, "8.0"))
		ReadPacket(backendConn) // response
		WritePacket(backendConn, BuildOKPacket(2, 0, 0))
	}()

	go func() {
		ReadPacket(clientConn) // greeting
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("u")...)
		payload = append(payload, 0, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})
		clientConn.Close() // close before reading auth result
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("forward auth result error should fail")
	}
}

// --- Handshake: fast auth read final OK error ---

func TestHandshakeFastAuthReadFinalError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(0, "8.0"))
		ReadPacket(backendConn) // response
		// Send AuthMoreData fast auth success
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte{0x01, 0x04}})
		backendConn.Close() // close before sending final OK
	}()

	go func() {
		ReadPacket(clientConn) // greeting
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("u")...)
		payload = append(payload, 0, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})
		ReadPacket(clientConn) // AuthMoreData
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("fast auth final read error should fail")
	}
}

// --- Handshake: auth continuation read client error ---

func TestHandshakeAuthContinuationClientError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(0, "8.0"))
		ReadPacket(backendConn) // response
		// Send auth switch (0xFE)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte{0xFE, 'n', 'a', 't', 0}})
	}()

	go func() {
		ReadPacket(clientConn) // greeting
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("u")...)
		payload = append(payload, 0, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})
		ReadPacket(clientConn) // auth switch
		clientConn.Close()     // close before sending auth response
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("auth continuation client error should fail")
	}
}

// --- ReadAndForwardResult: header read error ---

func TestReadAndForwardResultHeaderError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, _ := net.Pipe()
	defer proxyClient.Close()
	defer proxyBackend.Close()

	backendConn.Close()

	h := New()
	proxyBackend.SetDeadline(time.Now().Add(time.Second))
	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("header read error should fail")
	}
}

// --- ReadAndForwardResult: column def read error ---

func TestReadAndForwardResultColDefError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: []byte{2}}) // 2 columns
		// Send 1 col def then close
		var col []byte
		for _, s := range []string{"def", "db", "t", "t"} {
			col = append(col, byte(len(s)))
			col = append(col, []byte(s)...)
		}
		col = append(col, 1, 'x', 1, 'x', 0x0c)
		col = append(col, make([]byte, 12)...)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: col})
		backendConn.Close() // close before 2nd col def
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadPacket(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("col def read error should fail")
	}
}

// --- ReadAndForwardResult: EOF read error ---

func TestReadAndForwardResultEOFReadError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: []byte{1}}) // 1 col
		var col []byte
		for _, s := range []string{"def", "db", "t", "t"} {
			col = append(col, byte(len(s)))
			col = append(col, []byte(s)...)
		}
		col = append(col, 1, 'x', 1, 'x', 0x0c)
		col = append(col, make([]byte, 12)...)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: col})
		backendConn.Close() // close before EOF
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadPacket(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("EOF read error should fail")
	}
}

// --- ReadAndForwardResult: row read error ---

func TestReadAndForwardResultRowReadError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	go func() {
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: []byte{1}})
		var col []byte
		for _, s := range []string{"def", "db", "t", "t"} {
			col = append(col, byte(len(s)))
			col = append(col, []byte(s)...)
		}
		col = append(col, 1, 'x', 1, 'x', 0x0c)
		col = append(col, make([]byte, 12)...)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: col})
		WritePacket(backendConn, BuildEOFPacket(3))
		backendConn.Close() // close before sending rows
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadPacket(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("row read error should fail")
	}
}

// --- handlePrepareResponse: read error ---

func TestHandlePrepareResponseReadError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, _ := net.Pipe()
	defer proxyClient.Close()
	defer proxyBackend.Close()

	backendConn.Close()

	h := New()
	h.lastCmdByte = ComStmtPrepare

	proxyBackend.SetDeadline(time.Now().Add(time.Second))
	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("prepare read error should fail")
	}
}

// --- handlePrepareResponse: forward write error ---

func TestHandlePrepareResponseWriteError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, _ := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	proxyClient.Close()

	go func() {
		WritePacket(backendConn, BuildOKPacket(1, 0, 0))
	}()

	h := New()
	h.lastCmdByte = ComStmtPrepare

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err == nil {
		t.Error("prepare write error should fail")
	}
}

// --- ReadCommand: read error ---

func TestReadCommandReadError(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer proxyConn.Close()

	clientConn.Close()

	h := New()
	proxyConn.SetReadDeadline(time.Now().Add(time.Second))
	_, _, err := h.ReadCommand(context.Background(), proxyConn)
	if err == nil {
		t.Error("read error should fail")
	}
}

// --- extractColumnName: all early return paths ---

func TestExtractColumnNameMidSkip(t *testing.T) {
	// Truncated during 2nd skip field
	payload := []byte{3, 'd', 'e', 'f', 2, 'd', 'b'}
	name := extractColumnName(payload)
	if name != "" {
		t.Errorf("truncated mid-skip should return empty, got %q", name)
	}
}

func TestExtractColumnNameNameTruncated(t *testing.T) {
	// All 4 skips ok, but name field truncated
	var payload []byte
	for _, s := range []string{"def", "db", "t", "t"} {
		payload = append(payload, byte(len(s)))
		payload = append(payload, []byte(s)...)
	}
	payload = append(payload, 10) // name length = 10 but no data follows

	name := extractColumnName(payload)
	if name != "" {
		t.Errorf("truncated name should return empty, got %q", name)
	}
}
