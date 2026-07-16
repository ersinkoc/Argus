package mssql

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
)

func ProxyAuthServer(client net.Conn) (username string, loginData []byte, err error) {
	_, pktType, err := ReadAllPackets(client)
	if err != nil {
		return "", nil, fmt.Errorf("reading pre-login: %w", err)
	}
	if pktType != PacketPreLogin {
		return "", nil, fmt.Errorf("expected pre-login, got 0x%02x", pktType)
	}

	nonce := make([]byte, 8)
	rand.Read(nonce)
	respData := BuildProxyPreLoginResponse(nonce)
	if err := WritePacket(client, &Packet{Type: PacketReply, Status: StatusEOM, Data: respData}); err != nil {
		return "", nil, fmt.Errorf("sending pre-login response: %w", err)
	}

	loginData, loginType, err := ReadAllPackets(client)
	if err != nil {
		return "", nil, fmt.Errorf("reading login: %w", err)
	}
	if loginType != PacketTDS7Login {
		return "", nil, fmt.Errorf("expected TDS7 login, got 0x%02x", loginType)
	}

	username = extractLogin7Username(loginData)
	if username == "" {
		return "", nil, fmt.Errorf("could not extract username from Login7")
	}
	slog.Debug("mssql proxy auth: client identified", "user", username)
	return username, loginData, nil
}

func ProxyAuthClient(backend net.Conn, preLoginData []byte, resolvedUser, resolvedPass string) ([]byte, error) {
	if err := WritePacket(backend, &Packet{Type: PacketPreLogin, Status: StatusEOM, Data: preLoginData}); err != nil {
		return nil, fmt.Errorf("forwarding pre-login: %w", err)
	}

	respData, _, err := ReadAllPackets(backend)
	if err != nil {
		return nil, fmt.Errorf("reading backend pre-login: %w", err)
	}
	nonce := extractPreLoginNonce(respData)

	loginPkt := BuildProxyLogin7(resolvedUser, resolvedPass, nonce)
	loginData := disableMARS(loginPkt.Data)
	if err := WritePacket(backend, &Packet{Type: PacketTDS7Login, Status: StatusEOM, Data: loginData}); err != nil {
		return nil, fmt.Errorf("sending login to backend: %w", err)
	}

	loginResp, _, err := ReadAllPackets(backend)
	if err != nil {
		return nil, fmt.Errorf("reading backend login response: %w", err)
	}
	if !containsToken(loginResp, TokenLoginAck) {
		return nil, fmt.Errorf("login failed: no LoginAck")
	}
	slog.Debug("mssql proxy auth: backend authenticated")
	return loginResp, nil
}

func BuildProxyLogin7(username, password string, nonce []byte) *Packet {
	headerSize := 94
	userUTF16 := toUTF16LE(username)
	passUTF16 := toUTF16LE(password)

	var encPass []byte
	if len(nonce) >= 8 {
		encPass = encryptTDSPassword(passUTF16, nonce)
	} else {
		encPass = passUTF16
	}

	data := make([]byte, headerSize)
	data[4] = 0x00
	data[5] = 0x00
	data[6] = 0x00
	data[7] = 0x08
	data[8] = 0x00
	data[9] = 0x10

	hostname := toUTF16LE("argus-proxy")
	appName := toUTF16LE("Argus")

	offset := headerSize
	setDataPtr(data, 36, 38, offset, len(hostname)/2)
	offset += len(hostname)
	setDataPtr(data, 48, 50, offset, len(userUTF16)/2)
	offset += len(userUTF16)
	setDataPtr(data, 52, 54, offset, len(encPass))
	offset += len(encPass)
	setDataPtr(data, 68, 70, offset, len(appName)/2)
	offset += len(appName)
	serverName := toUTF16LE("argus-proxy")
	setDataPtr(data, 112, 114, offset, len(serverName)/2)
	offset += len(serverName)
	libName := toUTF16LE("argus-go")
	setDataPtr(data, 128, 130, offset, len(libName)/2)
	offset += len(libName)

	fullData := make([]byte, offset)
	copy(fullData[:headerSize], data[:headerSize])
	pos := headerSize
	copy(fullData[pos:], hostname)
	pos += len(hostname)
	copy(fullData[pos:], userUTF16)
	pos += len(userUTF16)
	copy(fullData[pos:], encPass)
	pos += len(encPass)
	copy(fullData[pos:], appName)
	pos += len(appName)
	copy(fullData[pos:], serverName)
	pos += len(serverName)
	copy(fullData[pos:], libName)

	length := len(fullData)
	fullData[0] = byte(length)
	fullData[1] = byte(length >> 8)
	fullData[2] = byte(length >> 16)
	fullData[3] = byte(length >> 24)

	if len(fullData) > 22 {
		fullData[22] = 0xE0
	}
	if len(fullData) > 23 {
		fullData[23] = 1
	}
	return &Packet{Type: PacketTDS7Login, Status: StatusEOM, Data: fullData}
}

func BuildProxyPreLoginResponse(nonce []byte) []byte {
	var data []byte
	data = append(data, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	data = append(data, 0x01, 0x00)
	data = append(data, 0x00, 0x00)
	data = append(data, 0x00, 0x00, 0x00, 0x00)
	if len(nonce) >= 8 {
		data = append(data, nonce[:8]...)
	} else {
		data = append(data, make([]byte, 8)...)
	}
	return data
}

func setDataPtr(data []byte, offsetOff, lengthOff int, offset, length int) {
	if offsetOff+2 <= len(data) {
		data[offsetOff] = byte(offset)
		data[offsetOff+1] = byte(offset >> 8)
	}
	if lengthOff+2 <= len(data) {
		data[lengthOff] = byte(length)
		data[lengthOff+1] = byte(length >> 8)
	}
}

func extractPreLoginNonce(data []byte) []byte {
	if len(data) < 8 {
		return nil
	}
	if len(data) >= 34 {
		return data[len(data)-8:]
	}
	return nil
}

func encryptTDSPassword(passUTF16 []byte, nonce []byte) []byte {
	result := make([]byte, 0, 1+len(passUTF16)+4)
	result = append(result, 0x00)
	for i := 0; i < len(passUTF16); i++ {
		result = append(result, passUTF16[i]^nonce[i%len(nonce)])
	}
	var sum uint32
	for _, b := range passUTF16 {
		sum += uint32(b)
	}
	result = append(result, byte(uint32(sum)), byte(uint32(sum)>>8), byte(uint32(sum)>>16), byte(uint32(sum)>>24))
	return result
}

func ForwardLoginResponse(client net.Conn, data []byte) error {
	pkt := &Packet{Type: PacketReply, Status: StatusEOM, Data: data}
	return WritePacket(client, pkt)
}
