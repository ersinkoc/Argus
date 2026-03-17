package mssql

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestMSSQLHandshakeFull(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	h := New()

	// Client sends PreLogin
	go func() {
		preLogin := BuildPreLoginResponse() // reuse as client request
		preLogin.Type = PacketPreLogin
		WritePacket(clientConn, preLogin)

		// Read PreLogin response from proxy
		ReadPacket(clientConn)

		// Send Login7 with username "testuser"
		loginData := buildTestLogin7("testuser")
		loginPkt := &Packet{Type: PacketTDS7Login, Status: StatusEOM, Data: loginData}
		WritePacket(clientConn, loginPkt)

		// Read login response
		ReadPacket(clientConn)
	}()

	// Backend
	go func() {
		// Read PreLogin from proxy
		ReadPacket(backendConn)

		// Send PreLogin response
		resp := BuildPreLoginResponse()
		WritePacket(backendConn, resp)

		// Read Login7 from proxy
		ReadPacket(backendConn)

		// Send login response with LoginAck token
		var loginResp []byte
		loginResp = append(loginResp, TokenEnvChange, 0x05, 0x00, 0x01, 0x00, 0x00)
		loginResp = append(loginResp, TokenLoginAck, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
		loginResp = append(loginResp, TokenDone, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

		loginRespPkt := &Packet{Type: PacketReply, Status: StatusEOM, Data: loginResp}
		WritePacket(backendConn, loginRespPkt)
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	info, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	if info == nil {
		t.Fatal("info should not be nil")
	}
	if info.AuthMethod != "tds7" {
		t.Errorf("auth = %q", info.AuthMethod)
	}
}

func TestMSSQLHandshakeLoginFail(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	h := New()

	go func() {
		preLogin := &Packet{Type: PacketPreLogin, Status: StatusEOM, Data: []byte{0xFF}}
		WritePacket(clientConn, preLogin)
		ReadPacket(clientConn) // response
		loginPkt := &Packet{Type: PacketTDS7Login, Status: StatusEOM, Data: buildTestLogin7("bad")}
		WritePacket(clientConn, loginPkt)
		ReadPacket(clientConn) // error response
	}()

	go func() {
		ReadPacket(backendConn)
		WritePacket(backendConn, &Packet{Type: PacketReply, Status: StatusEOM, Data: []byte{0xFF}})
		ReadPacket(backendConn)
		// No LoginAck — just Done
		loginResp := []byte{TokenDone, 0, 0, 0, 0, 0, 0, 0, 0}
		WritePacket(backendConn, &Packet{Type: PacketReply, Status: StatusEOM, Data: loginResp})
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("should fail without LoginAck")
	}
}

func buildTestLogin7(username string) []byte {
	data := make([]byte, 120)
	// Fixed header (94 bytes)
	// Username offset at bytes 48-49, length at 50-51
	usernameUTF16 := toUTF16LE(username)
	offset := 94
	data[48] = byte(offset)
	data[49] = byte(offset >> 8)
	data[50] = byte(len(username))
	data[51] = byte(len(username) >> 8)
	copy(data[offset:], usernameUTF16)
	return data
}
