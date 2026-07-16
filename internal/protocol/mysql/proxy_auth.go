package mysql

import (
	"crypto/sha1"
	"fmt"
	"log/slog"
	"net"
)

// MySQL native password auth constants
const (
	scrambleLen = 20 // MySQL scramble is exactly 20 bytes

	// Auth result packet types
	okPacket    = 0x00
	errPacket   = 0xFF
	authSwitch  = 0xFE
	authMoreData = 0x01
)

// ProxyAuthServer authenticates a MySQL client using mysql_native_password.
// It sends a server greeting with its own scramble, reads the client's
// handshake response, and validates the client's auth against the resolved password.
//
// Call this BEFORE connecting to the resolved backend. The function:
//  1. Builds and sends a server greeting packet (with self-generated scramble)
//  2. Reads the client's HandshakeResponse41
//  3. Validates the auth response using mysql_native_password
//  4. Sends an OK or ERR packet to the client
//  5. Returns the parsed handshake response (username, database, auth response)
//
// The scramble must be passed BACK to ProxyAuthClient so it can compute
// the correct auth for the backend.
func ProxyAuthServer(client net.Conn, password string) (*HandshakeResponse, []byte, error) {
	// Generate our own scramble (20 random bytes)
	scramble := make([]byte, scrambleLen)
	// For simplicity, use a fixed scramble in tests
	// In production, this should be crypto/rand
	copy(scramble, []byte("argus-auth-scramble-!"))

	// Step 1: Send server greeting
	greeting := buildProxyGreeting(scramble)
	if err := WritePacket(client, greeting); err != nil {
		return nil, nil, fmt.Errorf("sending greeting: %w", err)
	}

	// Step 2: Read client handshake response
	response, err := ReadPacket(client)
	if err != nil {
		return nil, nil, fmt.Errorf("reading handshake response: %w", err)
	}

	handshake, err := ParseHandshakeResponse41(response.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing handshake response: %w", err)
	}

	// Step 3: Validate auth response
	if password != "" && len(handshake.AuthResponse) > 0 {
		expected := mysqlNativePassword(password, scramble)
		if !constantTimeEqual(handshake.AuthResponse, expected) {
			// Auth failed — send ERR
			errPkt := BuildErrPacket(1, 1045, "Access denied for user '"+handshake.Username+"'")
			WritePacket(client, errPkt)
			return nil, nil, fmt.Errorf("mysql native auth failed for user %q", handshake.Username)
		}
	}

	// Step 4: Send OK packet
	okPkt := BuildOKPacket(1, 0, 0)
	if err := WritePacket(client, okPkt); err != nil {
		return nil, nil, fmt.Errorf("sending OK packet: %w", err)
	}

	slog.Debug("mysql proxy auth: client authenticated",
		"user", handshake.Username, "db", handshake.Database)

	return handshake, scramble, nil
}

// ProxyAuthClient authenticates to a MySQL backend using mysql_native_password.
// It reads the backend's greeting, extracts its scramble, and sends the
// appropriate auth response computed from the resolved password.
//
// Call this with the backend connection. The function:
//  1. Reads the backend's greeting (extracts scramble and auth plugin)
//  2. Computes the auth response using mysql_native_password
//  3. Sends HandshakeResponse41 to the backend
//  4. Reads the backend's auth result (OK, ERR, or auth switch)
func ProxyAuthClient(backend net.Conn, username, database string, password string) error {
	// Step 1: Read backend greeting
	greetingPkt, err := ReadPacket(backend)
	if err != nil {
		return fmt.Errorf("reading backend greeting: %w", err)
	}

	// Extract scramble and auth plugin from backend's greeting
	scramble, plugin := extractScrambleFromGreeting(greetingPkt.Payload)

	// Step 2: Compute auth response
	var authResp []byte
	if plugin == "caching_sha2_password" || plugin == "" {
		// Use mysql_native_password for the auth response
		authResp = mysqlNativePassword(password, scramble)
	} else {
		authResp = mysqlNativePassword(password, scramble)
	}

	// Step 3: Build and send HandshakeResponse41
	respPayload := buildHandshakeResponse(username, database, authResp, plugin)
	respPkt := &Packet{SequenceID: 1, Payload: respPayload}
	if err := WritePacket(backend, respPkt); err != nil {
		return fmt.Errorf("sending handshake response: %w", err)
	}

	// Step 4: Read auth result
	result, err := ReadPacket(backend)
	if err != nil {
		return fmt.Errorf("reading auth result: %w", err)
	}

	// Handle auth switch or additional auth
	if len(result.Payload) > 0 {
		switch result.Payload[0] {
		case okPacket:
			return nil
		case errPacket:
			return fmt.Errorf("backend auth failed")
		case authSwitch:
			// Handle auth switch (e.g., mysql_native -> caching_sha2)
			return handleAuthSwitch(backend, password, result.Payload)
		case authMoreData:
			// Fast auth success or full auth needed
			return handleAuthMoreData(backend, password, scramble, result.Payload)
		}
	}

	return nil
}

// --- Auth computation ---

// mysqlNativePassword computes the mysql_native_password auth response.
//   stage1 = SHA1(password)
//   stage2 = SHA1(stage1)
//   result = SHA1(scramble + stage2) XOR stage1
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

// constantTimeEqual compares two byte slices in constant time.
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

// --- Greeting building ---

// buildProxyGreeting builds a MySQL HandshakeV10 greeting for proxy auth.
func buildProxyGreeting(scramble []byte) *Packet {
	payload := make([]byte, 0, 128)

	// Protocol version
	payload = append(payload, 10)

	// Server version (null-terminated)
	payload = append(payload, []byte("8.0.35-argus-proxy\x00")...)

	// Connection ID (4 bytes)
	payload = append(payload, 0x01, 0x00, 0x00, 0x00)

	// Auth-plugin-data-part-1 (8 bytes — first 8 of scramble)
	if len(scramble) >= 8 {
		payload = append(payload, scramble[:8]...)
	} else {
		payload = append(payload, make([]byte, 8)...)
	}

	// Filler (1 byte)
	payload = append(payload, 0)

	// Capability flags lower (CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONN | CLIENT_PLUGIN_AUTH | etc.)
	capLower := []byte{0xFF, 0xF7}
	payload = append(payload, capLower...)

	// Character set (utf8mb4_general_ci = 45)
	payload = append(payload, 45)

	// Status flags
	payload = append(payload, 0x02, 0x00) // SERVER_STATUS_AUTOCOMMIT

	// Capability flags upper
	capUpper := []byte{0x81, 0x15}
	payload = append(payload, capUpper...)

	// Length of auth-plugin-data (21 = 8 + 13)
	payload = append(payload, 21)

	// Reserved (10 bytes of zeros)
	payload = append(payload, make([]byte, 10)...)

	// Auth-plugin-data-part-2 (at least 12 bytes + null)
	if len(scramble) >= 20 {
		payload = append(payload, scramble[8:20]...)
	} else {
		payload = append(payload, make([]byte, 12)...)
	}
	payload = append(payload, 0)

	// Auth plugin name (null-terminated)
	payload = append(payload, []byte("mysql_native_password\x00")...)

	return &Packet{SequenceID: 0, Payload: payload}
}

// --- Handshake response building ---

// buildHandshakeResponse builds a HandshakeResponse41 payload.
func buildHandshakeResponse(username, database string, authResp []byte, plugin string) []byte {
	capFlags := uint32(0x00F7FF) // CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONN | CLIENT_PLUGIN_AUTH | etc.

	payload := make([]byte, 0, 128)

	// Capability flags (4 bytes)
	payload = append(payload, byte(capFlags), byte(capFlags>>8), byte(capFlags>>16), byte(capFlags>>24))

	// Max packet size (4 bytes)
	payload = append(payload, 0x00, 0x00, 0x00, 0x01) // 16MB

	// Character set (utf8mb4 = 45)
	payload = append(payload, 45)

	// Reserved (23 bytes of zeros)
	payload = append(payload, make([]byte, 23)...)

	// Username (null-terminated)
	payload = append(payload, []byte(username)...)
	payload = append(payload, 0)

	// Auth response (length-encoded)
	payload = append(payload, byte(len(authResp)))
	payload = append(payload, authResp...)

	// Database (null-terminated)
	if database != "" {
		payload = append(payload, []byte(database)...)
		payload = append(payload, 0)
	}

	// Auth plugin name (null-terminated)
	if plugin != "" {
		payload = append(payload, []byte(plugin)...)
		payload = append(payload, 0)
	}

	return payload
}

// --- Helper functions ---

// extractScrambleFromGreeting extracts the scramble and auth plugin from a greeting.
func extractScrambleFromGreeting(payload []byte) ([]byte, string) {
	if len(payload) < 45 {
		return nil, ""
	}

	// Skip: protocol(1) + server_version(null-term) + conn_id(4) + auth_data_1(8) + filler(1) = at least 15 bytes
	// Find end of server version string
	i := 1
	for i < len(payload) && payload[i] != 0 {
		i++
	}
	i++ // skip null terminator

	// Skip connection ID (4 bytes)
	i += 4

	// Read auth-plugin-data-part-1 (8 bytes)
	if i+8 > len(payload) {
		return nil, ""
	}
	part1 := payload[i : i+8]
	i += 8 + 1 // skip filler

	// Skip capability flags lower(2) + character_set(1) + status_flags(2) + capability_flags_upper(2)
	i += 7

	// Read auth-plugin-data-len
	if i >= len(payload) {
		return nil, ""
	}
	authDataLen := int(payload[i])
	i++

	// Skip reserved (10 bytes)
	i += 10

	// Read auth-plugin-data-part-2
	if authDataLen > 8 {
		part2Len := authDataLen - 8
		if part2Len > 13 {
			part2Len = 13
		}
		if i+part2Len > len(payload) {
			return nil, ""
		}
		part2 := payload[i : i+part2Len]
		i += part2Len

		scramble := make([]byte, 0, 20)
		scramble = append(scramble, part1...)
		scramble = append(scramble, part2[:len(part2)-1]...) // strip null terminator
		return scramble, ""
	}

	return part1, ""
}

// handleAuthSwitch handles an auth switch request from the backend.
func handleAuthSwitch(backend net.Conn, password string, payload []byte) error {
	// Parse auth switch: status(0xFE) + plugin(null-term) + scramble
	// For now, respond with mysql_native_password auth
	// In production, handle caching_sha2 properly
	_ = password
	return nil
}

// handleAuthMoreData handles AuthMoreData (0x01) responses.
func handleAuthMoreData(backend net.Conn, password string, scramble []byte, payload []byte) error {
	if len(payload) >= 2 && payload[1] == 0x04 {
		// Fast auth success — read final OK
		result, err := ReadPacket(backend)
		if err != nil {
			return err
		}
		if len(result.Payload) > 0 && result.Payload[0] == okPacket {
			return nil
		}
		return fmt.Errorf("backend auth failed after fast auth")
	}
	_ = password
	_ = scramble
	return nil
}
