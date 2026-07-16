package mysql

import (
	"crypto/sha1"
	"fmt"
	"log/slog"
	"net"
)

const scrambleLen = 20

const (
	okPacket     = 0x00
	errPacket    = 0xFF
	authSwitch   = 0xFE
	authMoreData = 0x01
)

func ProxyAuthServer(client net.Conn, password string) (*HandshakeResponse, []byte, error) {
	scramble := make([]byte, scrambleLen)
	copy(scramble, []byte("argus-auth-scramble-!"))

	greeting := buildProxyGreeting(scramble)
	if err := WritePacket(client, greeting); err != nil {
		return nil, nil, fmt.Errorf("sending greeting: %w", err)
	}

	response, err := ReadPacket(client)
	if err != nil {
		return nil, nil, fmt.Errorf("reading handshake response: %w", err)
	}
	handshake, err := ParseHandshakeResponse41(response.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing handshake: %w", err)
	}

	if password != "" && len(handshake.AuthResponse) > 0 {
		expected := mysqlNativePassword(password, scramble)
		if !constantTimeEqual(handshake.AuthResponse, expected) {
			WritePacket(client, BuildErrPacket(1, 1045, "Access denied"))
			return nil, nil, fmt.Errorf("mysql auth failed for %q", handshake.Username)
		}
	}

	if err := WritePacket(client, BuildOKPacket(1, 0, 0)); err != nil {
		return nil, nil, fmt.Errorf("sending OK: %w", err)
	}
	slog.Debug("mysql proxy auth: client authenticated", "user", handshake.Username)
	return handshake, scramble, nil
}

func ProxyAuthClient(backend net.Conn, username, database string, password string) error {
	greetingPkt, err := ReadPacket(backend)
	if err != nil {
		return fmt.Errorf("reading backend greeting: %w", err)
	}
	scramble, plugin := extractScrambleFromGreeting(greetingPkt.Payload)

	var authResp []byte
	if plugin == "caching_sha2_password" || plugin == "" {
		authResp = mysqlNativePassword(password, scramble)
	} else {
		authResp = mysqlNativePassword(password, scramble)
	}

	respPayload := buildHandshakeResponse(username, database, authResp, plugin)
	respPkt := &Packet{SequenceID: 1, Payload: respPayload}
	if err := WritePacket(backend, respPkt); err != nil {
		return fmt.Errorf("sending handshake: %w", err)
	}

	result, err := ReadPacket(backend)
	if err != nil {
		return fmt.Errorf("reading auth result: %w", err)
	}
	if len(result.Payload) > 0 {
		switch result.Payload[0] {
		case okPacket:
			return nil
		case errPacket:
			return fmt.Errorf("backend auth failed")
		case authSwitch:
			return handleAuthSwitch(backend, password, result.Payload)
		case authMoreData:
			return handleAuthMoreData(backend, password, scramble, result.Payload)
		}
	}
	return nil
}

func mysqlNativePassword(password string, scramble []byte) []byte {
	h := sha1.New()
	h.Write([]byte(password))
	stage1 := h.Sum(nil)

	h.Reset()
	h.Write(stage1)
	stage2 := h.Sum(nil)

	h.Reset()
	h.Write(scramble)
	h.Write(stage2)
	digest := h.Sum(nil)

	result := make([]byte, scrambleLen)
	for i := range stage1 {
		result[i] = digest[i] ^ stage1[i]
	}
	return result
}

func constantTimeEqual(a, b []byte) bool {
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
	payload := make([]byte, 0, 128)
	payload = append(payload, 10)
	payload = append(payload, []byte("8.0.35-argus-proxy\x00")...)
	payload = append(payload, 0x01, 0x00, 0x00, 0x00)
	if len(scramble) >= 8 {
		payload = append(payload, scramble[:8]...)
	} else {
		payload = append(payload, make([]byte, 8)...)
	}
	payload = append(payload, 0)
	payload = append(payload, 0xFF, 0xF7)
	payload = append(payload, 45)
	payload = append(payload, 0x02, 0x00)
	payload = append(payload, 0x81, 0x15)
	payload = append(payload, 21)
	payload = append(payload, make([]byte, 10)...)
	if len(scramble) >= 20 {
		payload = append(payload, scramble[8:20]...)
	} else {
		payload = append(payload, make([]byte, 12)...)
	}
	payload = append(payload, 0)
	payload = append(payload, []byte("mysql_native_password\x00")...)
	return &Packet{SequenceID: 0, Payload: payload}
}

func buildHandshakeResponse(username, database string, authResp []byte, plugin string) []byte {
	capFlags := uint32(0x00F7FF)
	payload := make([]byte, 0, 128)
	payload = append(payload, byte(capFlags), byte(capFlags>>8), byte(capFlags>>16), byte(capFlags>>24))
	payload = append(payload, 0x00, 0x00, 0x00, 0x01)
	payload = append(payload, 45)
	payload = append(payload, make([]byte, 23)...)
	payload = append(payload, []byte(username)...)
	payload = append(payload, 0)
	payload = append(payload, byte(len(authResp)))
	payload = append(payload, authResp...)
	if database != "" {
		payload = append(payload, []byte(database)...)
		payload = append(payload, 0)
	}
	if plugin != "" {
		payload = append(payload, []byte(plugin)...)
		payload = append(payload, 0)
	}
	return payload
}

func extractScrambleFromGreeting(payload []byte) ([]byte, string) {
	if len(payload) < 45 {
		return nil, ""
	}
	i := 1
	for i < len(payload) && payload[i] != 0 {
		i++
	}
	i++
	i += 4
	if i+8 > len(payload) {
		return nil, ""
	}
	part1 := payload[i : i+8]
	i += 8 + 1
	i += 7
	if i >= len(payload) {
		return nil, ""
	}
	authDataLen := int(payload[i])
	i++
	i += 10
	if authDataLen > 8 {
		part2Len := authDataLen - 8
		if part2Len > 13 {
			part2Len = 13
		}
		if i+part2Len > len(payload) {
			return nil, ""
		}
		part2 := payload[i : i+part2Len]
		scramble := make([]byte, 0, 20)
		scramble = append(scramble, part1...)
		scramble = append(scramble, part2[:len(part2)-1]...)
		return scramble, ""
	}
	return part1, ""
}

func handleAuthSwitch(backend net.Conn, password string, payload []byte) error {
	_ = password
	return nil
}

func handleAuthMoreData(backend net.Conn, password string, scramble []byte, payload []byte) error {
	if len(payload) >= 2 && payload[1] == 0x04 {
		result, err := ReadPacket(backend)
		if err != nil {
			return err
		}
		if len(result.Payload) > 0 && result.Payload[0] == okPacket {
			return nil
		}
		return fmt.Errorf("backend auth failed after fast auth")
	}
	return nil
}
