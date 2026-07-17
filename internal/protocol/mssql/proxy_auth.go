package mssql

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"time"
	"unicode/utf16"
)

type ProxyLogin struct {
	Username string
	preLogin []byte
	login    []byte
}

func ProxyAuthServer(ctx context.Context, client net.Conn, tlsConfig *tls.Config, requireTLS bool) (net.Conn, *ProxyLogin, error) {
	preLoginData, preLoginType, err := ReadAllPackets(client)
	if err != nil {
		return nil, nil, fmt.Errorf("reading pre-login: %w", err)
	}
	if preLoginType != PacketPreLogin {
		return nil, nil, fmt.Errorf("expected pre-login (0x12), got 0x%02x", preLoginType)
	}
	_ = preLoginData
	encryption := byte(0x02)
	if requireTLS {
		if tlsConfig == nil {
			return nil, nil, fmt.Errorf("mssql tls requested but listener tls config is nil")
		}
		// ENCRYPT_OFF means TLS is used for the login packet, then the session
		// returns to plaintext TDS so the proxy can continue inspecting traffic.
		encryption = 0x00
	}
	pr := BuildPreLoginResponseWithEncryption(encryption)
	if err := WritePacket(client, pr); err != nil {
		return nil, nil, fmt.Errorf("writing pre-login response: %w", err)
	}
	loginConn := net.Conn(client)
	if requireTLS {
		wrapped := NewTDSTLSHandshakeConn(client)
		serverTLSConfig := tlsConfig.Clone()
		serverTLSConfig.SessionTicketsDisabled = true
		tlsConn := tls.Server(wrapped, serverTLSConfig)
		slog.Info("mssql tds tls handshake start")
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, nil, fmt.Errorf("tds tls handshake: %w", err)
		}
		slog.Info("mssql tds tls handshake complete")
		loginConn = tlsConn
	}
	slog.Info("mssql reading login7", "tls", requireTLS, "conn_type", fmt.Sprintf("%T", loginConn))
	_ = loginConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	loginData, loginType, err := readLogin7FromConn(loginConn)
	if err != nil {
		return nil, nil, fmt.Errorf("reading login7: %w", err)
	}
	if loginType != PacketTDS7Login {
		return nil, nil, fmt.Errorf("expected login7 (0x10), got 0x%02x", loginType)
	}
	username := extractLogin7Username(loginData)
	if username == "" {
		return nil, nil, fmt.Errorf("empty username")
	}
	patchedPreLogin := append([]byte(nil), preLoginData...)
	patchPreLoginEncryption(patchedPreLogin)
	return client, &ProxyLogin{Username: username, preLogin: patchedPreLogin, login: append([]byte(nil), loginData...)}, nil
}

func (l *ProxyLogin) PreLoginRequest() []byte {
	if l == nil || len(l.preLogin) == 0 {
		return BuildProxyPreLoginResponse(nil)
	}
	return l.preLogin
}

func (l *ProxyLogin) ValidateClientSecret(secret string) error {
	if l == nil || secret == "" || len(l.login) < 94 {
		return fmt.Errorf("invalid client credential")
	}
	offset := int(binary.LittleEndian.Uint16(l.login[44:46]))
	characters := int(binary.LittleEndian.Uint16(l.login[46:48]))
	length := characters * 2
	if offset < 94 || characters == 0 || offset+length > len(l.login) {
		return fmt.Errorf("invalid client credential")
	}
	expected := obfuscateTDSPassword(utf16ToBytes(utf16.Encode([]rune(secret))))
	if subtle.ConstantTimeCompare(l.login[offset:offset+length], expected) != 1 {
		return fmt.Errorf("invalid client credential")
	}
	return nil
}

func ProxyAuthClient(backend net.Conn, preLoginData []byte, user, pass string) ([]byte, error) {
	slog.Debug("mssql backend: sending prelogin", "bytes", len(preLoginData))
	if err := WritePacket(backend, &Packet{Type: PacketPreLogin, Status: StatusEOM, Data: preLoginData}); err != nil {
		return nil, fmt.Errorf("sending pre-login: %w", err)
	}
	slog.Debug("mssql backend: reading prelogin response")
	pr, err := ReadPacket(backend)
	if err != nil {
		return nil, fmt.Errorf("reading pre-login response: %w", err)
	}
	slog.Debug("mssql backend: got prelogin response", "type", fmt.Sprintf("0x%02x", pr.Type), "data_len", len(pr.Data))
	if pr.Type != PacketReply {
		return nil, fmt.Errorf("expected pre-login reply, got 0x%02x", pr.Type)
	}
	slog.Debug("mssql backend: sending login7", "user", user)
	lp := BuildProxyLogin7(user, pass, nil)
	if err := WritePacket(backend, lp); err != nil {
		return nil, fmt.Errorf("sending login7: %w", err)
	}
	slog.Debug("mssql backend: reading login response")
	lr, err := ReadPacket(backend)
	if err != nil {
		return nil, fmt.Errorf("reading login response: %w", err)
	}
	slog.Debug("mssql backend: login response received", "data_len", len(lr.Data))
	return lr.Data, nil
}

func BuildProxyLogin7(username, password string, _ []byte) *Packet {
	const headerSize = 94
	header := make([]byte, headerSize)
	variable := make([]byte, 0, 128)

	binary.LittleEndian.PutUint32(header[4:8], 0x74000004)
	binary.LittleEndian.PutUint32(header[8:12], 4096)
	binary.LittleEndian.PutUint32(header[12:16], 0x01000000)
	binary.LittleEndian.PutUint32(header[16:20], 1234)
	header[24] = 0xE0
	header[25] = 0x03
	binary.LittleEndian.PutUint32(header[32:36], 0x0409)

	appendLoginString(header, &variable, 36, 38, "argus")
	appendLoginString(header, &variable, 40, 42, username)
	appendLoginBytes(header, &variable, 44, 46,
		obfuscateTDSPassword(utf16ToBytes(utf16.Encode([]rune(password)))))
	appendLoginString(header, &variable, 48, 50, "argus")
	appendLoginString(header, &variable, 52, 54, "")
	appendLoginString(header, &variable, 60, 62, "go-argus")
	appendLoginString(header, &variable, 64, 66, "")
	appendLoginString(header, &variable, 68, 70, "")

	binary.LittleEndian.PutUint32(header[0:4], uint32(headerSize+len(variable)))
	return &Packet{Type: PacketTDS7Login, Status: StatusEOM, Data: append(header, variable...)}
}

func BuildProxyPreLoginResponse(_ []byte) []byte {
	return BuildPreLoginResponse().Data
}

func ForwardLoginResponse(client net.Conn, data []byte) error {
	return WritePacket(client, &Packet{Type: PacketReply, Status: StatusEOM, Data: data})
}

func appendLoginString(header []byte, variable *[]byte, offsetField, lengthField int, value string) {
	appendLoginBytes(header, variable, offsetField, lengthField,
		utf16ToBytes(utf16.Encode([]rune(value))))
}

func appendLoginBytes(header []byte, variable *[]byte, offsetField, lengthField int, value []byte) {
	offset := len(header) + len(*variable)
	binary.LittleEndian.PutUint16(header[offsetField:offsetField+2], uint16(offset))
	binary.LittleEndian.PutUint16(header[lengthField:lengthField+2], uint16(len(value)/2))
	*variable = append(*variable, value...)
}

func obfuscateTDSPassword(password []byte) []byte {
	obfuscated := make([]byte, len(password))
	for i, value := range password {
		obfuscated[i] = ((value << 4) | (value >> 4)) ^ 0xA5
	}
	return obfuscated
}

func utf16ToBytes(runes []uint16) []byte {
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}
