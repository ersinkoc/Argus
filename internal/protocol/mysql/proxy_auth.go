package mysql

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"net"
)

func ProxyAuthServer(client net.Conn, password string) (*HandshakeResponse, error) {
	scramble := make([]byte, 20)
	for i := range scramble {
		scramble[i] = byte(i*17 + 31)
	}
	greeting := buildProxyGreeting(scramble)
	if err := WritePacket(client, greeting); err != nil {
		return nil, fmt.Errorf("writing greeting: %w", err)
	}
	rp, err := ReadPacket(client)
	if err != nil {
		return nil, fmt.Errorf("reading handshake: %w", err)
	}
	resp, err := ParseHandshakeResponse41(rp.Payload)
	if err != nil {
		return nil, fmt.Errorf("parsing handshake: %w", err)
	}
	// Validate password only if one was provided (proxy auth resolves after extracting username)
	if password != "" {
		exp := mysqlNativePassword(password, scramble)
		if !constTimeEq(resp.AuthResponse, exp) {
			WritePacket(client, BuildErrPacket(2, 1045, "Access denied"))
			return nil, fmt.Errorf("password mismatch")
		}
		if err := WritePacket(client, BuildOKPacket(2, 0, 0)); err != nil {
			return nil, fmt.Errorf("writing OK: %w", err)
		}
	}
	return resp, nil
}

func ProxyAuthClient(backend net.Conn, username, database, password string) error {
	g, err := ReadPacket(backend)
	if err != nil {
		return fmt.Errorf("reading greeting: %w", err)
	}
	scramble := extractScramble(g.Payload)
	ar := mysqlNativePassword(password, scramble)
	rp := buildClientResponse(username, database, ar)
	rp.SequenceID = 1
	if err := WritePacket(backend, rp); err != nil {
		return fmt.Errorf("writing handshake: %w", err)
	}
	res, err := ReadPacket(backend)
	if err != nil {
		return fmt.Errorf("reading result: %w", err)
	}
	if len(res.Payload) == 0 {
		return fmt.Errorf("empty result")
	}
	switch res.Payload[0] {
	case 0x00:
		return nil
	case 0xFF:
		return fmt.Errorf("auth error: code=%d", uint16(res.Payload[1])|uint16(res.Payload[2])<<8)
	case 0x01:
		return handleMoreData(backend, password, scramble, res.Payload)
	default:
		return fmt.Errorf("unexpected: 0x%02x", res.Payload[0])
	}
}

func mysqlNativePassword(password string, scramble []byte) []byte {
	h := sha1.New()
	h.Write([]byte(password))
	hp := h.Sum(nil)
	h.Reset()
	h.Write(hp)
	hps := h.Sum(nil)
	h.Reset()
	h.Write(scramble)
	h.Write(hps)
	r := h.Sum(nil)
	for i := range r {
		r[i] ^= hp[i]
	}
	return r
}

func constTimeEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func buildProxyGreeting(scramble []byte) *Packet {
	var p []byte
	p = append(p, 10)
	p = append(p, []byte("Argus Proxy\x00")...)
	p = append(p, 0, 0, 0, 0)
	p = append(p, scramble[:8]...)
	p = append(p, 0)
	p = append(p, 0xFF, 0xFF)
	p = append(p, 45)
	p = append(p, 0x02, 0x00)
	p = append(p, 0x00, 0x00)
	p = append(p, 21)
	p = append(p, make([]byte, 10)...)
	p = append(p, scramble[8:]...)
	p = append(p, 0)
	p = append(p, []byte("mysql_native_password\x00")...)
	return &Packet{SequenceID: 0, Payload: p}
}

func buildClientResponse(username, database string, ar []byte) *Packet {
	var p []byte
	f := make([]byte, 4)
	binary.LittleEndian.PutUint32(f, 0x0001|0x8000|0x0008)
	p = append(p, f...)
	p = append(p, 0x00, 0x00, 0x00, 0x01)
	p = append(p, 45)
	p = append(p, make([]byte, 23)...)
	p = append(p, []byte(username)...)
	p = append(p, 0)
	p = append(p, byte(len(ar)))
	p = append(p, ar...)
	if database != "" {
		p = append(p, []byte(database)...)
		p = append(p, 0)
	}
	return &Packet{SequenceID: 1, Payload: p}
}

func extractScramble(payload []byte) []byte {
	if len(payload) < 45 {
		return nil
	}
	i := 1
	for i < len(payload) && payload[i] != 0 {
		i++
	}
	i++
	i += 4
	part1 := payload[i : i+8]
	i += 8 + 1 + 2 + 1 + 2 + 2
	if i >= len(payload) {
		return nil
	}
	adl := int(payload[i])
	i++
	i += 10
	pl := adl - 9
	if pl < 0 {
		pl = 12
	}
	if i+pl > len(payload) {
		pl = len(payload) - i
		if pl < 0 {
			pl = 0
		}
	}
	return append(part1, payload[i:i+pl]...)
}

func handleMoreData(backend net.Conn, password string, scramble []byte, payload []byte) error {
	if len(payload) < 2 {
		return fmt.Errorf("too short")
	}
	switch payload[1] {
	case 2:
		return WritePacket(backend, &Packet{SequenceID: 1, Payload: mysqlNativePassword(password, scramble)})
	case 3:
		return WritePacket(backend, &Packet{SequenceID: 1, Payload: append([]byte(password), 0)})
	default:
		return fmt.Errorf("unexpected stage: %d", payload[1])
	}
}
