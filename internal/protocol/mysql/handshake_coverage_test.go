package mysql

import (
	"context"
	"net"
	"testing"
	"time"
)

// --- Handshake: fast auth success (0x01 0x04) ---

func TestHandshakeFastAuthSuccess(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	h := New()

	go func() {
		// Backend: greeting → read response → send AuthMoreData(0x01,0x04) → send OK
		WritePacket(backendConn, BuildHandshakeV10(0, "8.0.33"))
		ReadPacket(backendConn)
		// AuthMoreData with fast auth success
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte{0x01, 0x04}})
		// Final OK
		WritePacket(backendConn, BuildOKPacket(3, 0, 0))
	}()

	go func() {
		ReadPacket(clientConn) // greeting
		var payload []byte
		payload = append(payload, 0x0F, 0x00, 0x00, 0x00)
		payload = append(payload, 0x00, 0x00, 0x00, 0x01)
		payload = append(payload, 45)
		payload = append(payload, make([]byte, 23)...)
		payload = append(payload, []byte("admin")...)
		payload = append(payload, 0, 0)
		WritePacket(clientConn, &Packet{SequenceID: 1, Payload: payload})
		ReadPacket(clientConn) // AuthMoreData
		ReadPacket(clientConn) // final OK
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	info, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	if info.Username != "admin" {
		t.Errorf("username = %q", info.Username)
	}
}

// --- Handshake: greeting read error ---

func TestHandshakeGreetingReadError(t *testing.T) {
	_, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer proxyClient.Close()
	defer proxyBackend.Close()

	backendConn.Close() // close backend immediately

	h := New()
	proxyBackend.SetReadDeadline(time.Now().Add(time.Second))
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("greeting read error should fail")
	}
}

// --- Handshake: client response read error ---

func TestHandshakeClientResponseError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(0, "8.0"))
	}()

	// Close client after reading greeting
	go func() {
		ReadPacket(clientConn)
		clientConn.Close()
	}()

	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("client close should fail")
	}
}

// --- Handshake: auth result read error ---

func TestHandshakeAuthResultReadError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()

	go func() {
		WritePacket(backendConn, BuildHandshakeV10(0, "8.0"))
		ReadPacket(backendConn) // client response
		backendConn.Close()     // close before sending auth result
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

	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("auth read error should fail")
	}
}

// --- MySQL ReadAndForwardResult: multiple columns + masking ---

func TestReadAndForwardResultMultiCol(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()

	go func() {
		// 2 columns
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: []byte{2}})

		// Col 1: id
		var col1 []byte
		for _, s := range []string{"def", "db", "t", "t"} {
			col1 = append(col1, byte(len(s)))
			col1 = append(col1, []byte(s)...)
		}
		col1 = append(col1, 2, 'i', 'd', 2, 'i', 'd', 0x0c)
		col1 = append(col1, make([]byte, 12)...)
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: col1})

		// Col 2: name
		var col2 []byte
		for _, s := range []string{"def", "db", "t", "t"} {
			col2 = append(col2, byte(len(s)))
			col2 = append(col2, []byte(s)...)
		}
		col2 = append(col2, 4, 'n', 'a', 'm', 'e', 4, 'n', 'a', 'm', 'e', 0x0c)
		col2 = append(col2, make([]byte, 12)...)
		WritePacket(backendConn, &Packet{SequenceID: 3, Payload: col2})

		// EOF
		WritePacket(backendConn, BuildEOFPacket(4))

		// Row: "1", "Alice"
		row := []byte{1, '1', 5, 'A', 'l', 'i', 'c', 'e'}
		WritePacket(backendConn, &Packet{SequenceID: 5, Payload: row})

		// EOF
		WritePacket(backendConn, BuildEOFPacket(6))
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

	stats, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if stats.RowCount != 1 {
		t.Errorf("rows = %d", stats.RowCount)
	}
}
