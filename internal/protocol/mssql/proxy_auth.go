package mssql

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
)

// ProxyAuthServer handles the server side of TDS authentication for proxy auth.
// It reads the client's PreLogin and Login7, extracts the username, and returns
// the prelogin data for backend connection setup.
//
// Call this BEFORE connecting to the backend. The function:
//  1. Reads client PreLogin
//  2. Sends a proxy-generated PreLogin response
//  3. Reads client Login7 (extracts username)
//  4. Returns the username and original Login7 data
func ProxyAuthServer(client net.Conn) (username string, loginData []byte, err error) {
	// Step 1: Read client PreLogin
	_, pktType, err := ReadAllPackets(client)
	if err != nil {
		return "", nil, fmt.Errorf("reading client pre-login: %w", err)
	}
	if pktType != PacketPreLogin {
		return "", nil, fmt.Errorf("expected pre-login, got 0x%02x", pktType)
	}

	// Step 2: Send proxy-generated PreLogin response
	// Generate a random nonce for the PreLogin response
	nonce := make([]byte, 8)
	rand.Read(nonce)
	respData := BuildProxyPreLoginResponse(nonce)

	respPkt := &Packet{
		Type:   PacketReply,
		Status: StatusEOM,
		Data:   respData,
	}
	if err := WritePacket(client, respPkt); err != nil {
		return "", nil, fmt.Errorf("sending pre-login response: %w", err)
	}

	// Step 3: Read client Login7
	loginData, loginType, err := ReadAllPackets(client)
	if err != nil {
		return "", nil, fmt.Errorf("reading client login: %w", err)
	}
	if loginType != PacketTDS7Login {
		return "", nil, fmt.Errorf("expected TDS7 login, got 0x%02x", loginType)
	}

	username = extractLogin7Username(loginData)
	if username == "" {
		return "", nil, fmt.Errorf("could not extract username from Login7")
	}

	slog.Debug("mssql proxy auth: client identified",
		"user", username)

	return username, loginData, nil
}

// ProxyAuthClient authenticates to the MSSQL backend using the resolved credential.
// It connects to the backend, forwards the client's PreLogin, reads the response,
// and sends a new Login7 packet with the resolved credential.
//
// Call this with the backend connection. The function:
//  1. Sends client's PreLogin to backend
//  2. Reads backend's PreLogin response (extracts nonce)
//  3. Builds Login7 with resolved username and password encrypted with backend's nonce
//  4. Sends Login7 to backend
//  5. Reads backend's Login7 response
//  6. Returns the response data (caller should forward to client)
func ProxyAuthClient(backend net.Conn, preLoginData []byte, resolvedUser, resolvedPass string) ([]byte, error) {
	// Step 1: Forward PreLogin to backend
	preLoginPkt := &Packet{
		Type:   PacketPreLogin,
		Status: StatusEOM,
		Data:   preLoginData,
	}
	if err := WritePacket(backend, preLoginPkt); err != nil {
		return nil, fmt.Errorf("forwarding pre-login: %w", err)
	}

	// Step 2: Read backend PreLogin response
	respData, _, err := ReadAllPackets(backend)
	if err != nil {
		return nil, fmt.Errorf("reading backend pre-login: %w", err)
	}

	// Extract nonce from backend's PreLogin response
	nonce := extractPreLoginNonce(respData)

	// Step 3: Build Login7 with resolved credential
	// Create a basic Login7 packet with SQL Server authentication
	loginPkt := BuildProxyLogin7(resolvedUser, resolvedPass, nonce)

	// Disable MARS to avoid TDS header requirements
	loginData := disableMARS(loginPkt.Data)

	loginPacket := &Packet{
		Type:   PacketTDS7Login,
		Status: StatusEOM,
		Data:   loginData,
	}
	if err := WritePacket(backend, loginPacket); err != nil {
		return nil, fmt.Errorf("sending login to backend: %w", err)
	}

	// Step 4: Read backend login response
	loginResp, _, err := ReadAllPackets(backend)
	if err != nil {
		return nil, fmt.Errorf("reading backend login response: %w", err)
	}

	// Check for LoginAck
	if !containsToken(loginResp, TokenLoginAck) {
		return nil, fmt.Errorf("login failed: no LoginAck token")
	}

	slog.Debug("mssql proxy auth: backend authenticated")

	// Return the response data — caller forwards to client
	return loginResp, nil
}

// BuildProxyLogin7 builds a minimal TDS Login7 packet for SQL Server authentication.
func BuildProxyLogin7(username, password string, nonce []byte) *Packet {
	// Login7 header is 94 bytes (fixed part) followed by variable-length data
	headerSize := 94

	// Encode username and password as UTF-16LE
	userUTF16 := toUTF16LE(username)
	passUTF16 := toUTF16LE(password)

	// Encrypt password with nonce if provided
	var encPass []byte
	if len(nonce) >= 8 {
		encPass = encryptTDSPassword(passUTF16, nonce)
	} else {
		encPass = passUTF16
	}

	// Build Login7 data
	data := make([]byte, headerSize)

	// Length (4 bytes) - will be updated at end
	copy(data[0:4], []byte{0, 0, 0, 0})

	// TDS version (0x08000000 = SQL 2008+)
	data[4] = 0x00
	data[5] = 0x00
	data[6] = 0x00
	data[7] = 0x08 // TDS 8.0

	// Packet size (default 4096)
	data[8] = 0x00
	data[9] = 0x10

	// Program version (0x00000000)
	// Hostname offset/length

	// Set offsets for variable-length fields
	hostname := toUTF16LE("argus-proxy")
	appName := toUTF16LE("Argus")

	// Calculate offsets (after header + all data blocks)
	offset := headerSize

	// Hostname (offset 36, length 38)
	setDataPtr(data, 36, 38, offset, len(hostname))
	offset += len(hostname) * 2

	// Username (offset 48, length 50)
	setDataPtr(data, 48, 50, offset, len(userUTF16)/2)
	offset += len(userUTF16) * 2

	// Password (offset 52, length 54)
	setDataPtr(data, 52, 54, offset, len(encPass))
	offset += len(encPass)

	// App name (offset 68, length 70)
	setDataPtr(data, 68, 70, offset, len(appName))
	offset += len(appName) * 2

	// Server name (offset 112, length 114)
	serverName := toUTF16LE("argus-proxy")
	setDataPtr(data, 112, 114, offset, len(serverName))
	offset += len(serverName) * 2

	// Library name (offset 128, length 130)
	libName := toUTF16LE("argus-go")
	setDataPtr(data, 128, 130, offset, len(libName))
	offset += len(libName) * 2

	// Build the full data with variable-length fields
	fullData := make([]byte, offset)
	copy(fullData[:headerSize], data[:headerSize])

	// Copy variable-length fields
	pos := headerSize
	copy(fullData[pos:], hostname)
	pos += len(hostname) * 2
	copy(fullData[pos:], userUTF16)
	pos += len(userUTF16) * 2
	copy(fullData[pos:], encPass)
	pos += len(encPass)
	copy(fullData[pos:], appName)
	pos += len(appName) * 2
	copy(fullData[pos:], serverName)
	pos += len(serverName) * 2
	copy(fullData[pos:], libName)
	pos += len(libName) * 2

	// Update length
	length := len(fullData)
	fullData[0] = byte(length)
	fullData[1] = byte(length >> 8)
	fullData[2] = byte(length >> 16)
	fullData[3] = byte(length >> 24)

	// Set OptionFlags2 to SQL Server authentication (not Windows/NTLM)
	if len(fullData) > 22 {
		fullData[22] = 0xE0 // fByteOrder | fChar | fFloat | fDumpLoad | fUseDB | fDatabase | fLang
	}
	if len(fullData) > 23 {
		fullData[23] = 1    // SQL Server authentication (fIntL)
	}

	return &Packet{
		Type:   PacketTDS7Login,
		Status: StatusEOM,
		Data:   fullData,
	}
}

// BuildProxyPreLoginResponse builds a PreLogin response for the proxy.
func BuildProxyPreLoginResponse(nonce []byte) []byte {
	// Minimal PreLogin response:
	// - Encryption: 0 (off)
	// - ThreadID: 0
	// - Nonce: 8 random bytes
	var data []byte

	// Version token
	data = append(data, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	// Encryption token: 0 = off
	data = append(data, 0x01, 0x00)

	// Instance token: empty
	data = append(data, 0x00, 0x00)

	// ThreadID token
	data = append(data, 0x00, 0x00, 0x00, 0x00)

	// Nonce token (8 bytes)
	if len(nonce) >= 8 {
		data = append(data, nonce[:8]...)
	} else {
		data = append(data, make([]byte, 8)...)
	}

	return data
}

// --- Helper functions ---

// setDataPtr sets a uint16 offset and length pair in the Login7 header.
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

// extractPreLoginNonce extracts the nonce from a PreLogin response.
// The nonce is used to encrypt the password in Login7.
func extractPreLoginNonce(data []byte) []byte {
	if len(data) < 8 {
		return nil
	}
	// Nonce is typically placed after the standard PreLogin tokens
	// For simplicity, scan for the nonce starting position
	// In a full implementation, parse PreLogin tokens properly
	if len(data) >= 34 {
		return data[len(data)-8:]
	}
	return nil
}

// encryptTDSPassword encrypts a UTF-16LE password for TDS Login7.
// It XORs the password with the nonce (repeated) and adds a 0x00 prefix.
func encryptTDSPassword(passUTF16 []byte, nonce []byte) []byte {
	// Format: 0x00 + XOR(pass, nonce_repeated) + checksum(4 bytes)
	result := make([]byte, 0, 1+len(passUTF16)+4)
	result = append(result, 0x00) // success indicator

	// XOR password with nonce (repeating)
	for i := 0; i < len(passUTF16); i++ {
		result = append(result, passUTF16[i]^nonce[i%len(nonce)])
	}

	// Append a simple checksum (sum of password bytes mod 256)
	var sum uint32
	for _, b := range passUTF16 {
		sum += uint32(b)
	}
	result = append(result, byte(uint32(sum)), byte(uint32(sum)>>8), byte(uint32(sum)>>16), byte(uint32(sum)>>24))

	return result
}

// toUTF16LE converts a string to UTF-16LE byte array.

// ForwardLoginResponse sends a raw TDS login response to the client.
func ForwardLoginResponse(client net.Conn, data []byte) error {
	pkt := &Packet{
		Type:   PacketReply,
		Status: StatusEOM,
		Data:   data,
	}
	return WritePacket(client, pkt)
}
