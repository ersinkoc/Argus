package mysql

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"net"
)

type ProxyHandshake struct {
	Response *HandshakeResponse
	scramble []byte
}

func ProxyAuthServer(client net.Conn) (*ProxyHandshake, error) {
	scramble := make([]byte, 20)
	if _, err := rand.Read(scramble); err != nil {
		return nil, fmt.Errorf("generating auth challenge: %w", err)
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
	return &ProxyHandshake{Response: resp, scramble: scramble}, nil
}

func (h *ProxyHandshake) ValidateClientSecret(client net.Conn, secret string) error {
	if h == nil || h.Response == nil || secret == "" {
		return fmt.Errorf("invalid client credential")
	}
	expected := mysqlNativePassword(secret, h.scramble)
	if subtle.ConstantTimeCompare(h.Response.AuthResponse, expected) != 1 {
		if err := WritePacket(client, BuildErrPacket(2, 1045, "Access denied")); err != nil {
			return fmt.Errorf("writing access denied: %w", err)
		}
		return fmt.Errorf("invalid client credential")
	}
	return nil
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

const (
	clientLongPassword     uint32 = 0x00000001
	clientConnectWithDB    uint32 = 0x00000008
	clientProtocol41       uint32 = 0x00000200
	clientTransactions     uint32 = 0x00002000
	clientSecureConnection uint32 = 0x00008000
	clientPluginAuth       uint32 = 0x00080000
)

func buildProxyGreeting(scramble []byte) *Packet {
	capabilities := clientLongPassword | clientConnectWithDB | clientProtocol41 |
		clientTransactions | clientSecureConnection | clientPluginAuth
	var p []byte
	p = append(p, 10)
	p = append(p, []byte("8.0.0-argus\x00")...)
	p = append(p, 1, 0, 0, 0)
	p = append(p, scramble[:8]...)
	p = append(p, 0)
	p = binary.LittleEndian.AppendUint16(p, uint16(capabilities))
	p = append(p, 45)
	p = binary.LittleEndian.AppendUint16(p, StatusAutocommit)
	p = binary.LittleEndian.AppendUint16(p, uint16(capabilities>>16))
	p = append(p, 21)
	p = append(p, make([]byte, 10)...)
	p = append(p, scramble[8:]...)
	p = append(p, 0)
	p = append(p, []byte("mysql_native_password\x00")...)
	return &Packet{SequenceID: 0, Payload: p}
}

func buildClientResponse(username, database string, ar []byte) *Packet {
	capabilities := clientLongPassword | clientProtocol41 | clientTransactions |
		clientSecureConnection | clientPluginAuth
	if database != "" {
		capabilities |= clientConnectWithDB
	}
	var p []byte
	p = binary.LittleEndian.AppendUint32(p, capabilities)
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
	p = append(p, []byte("mysql_native_password\x00")...)
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
	if i+8 > len(payload) {
		return nil
	}
	part1 := payload[i : i+8]
	i += 8 + 1 + 2 + 1 + 2 + 2
	if i >= len(payload) {
		return nil
	}
	adl := int(payload[i])
	i++
	i += 10
	if i > len(payload) {
		i = len(payload)
	}
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
