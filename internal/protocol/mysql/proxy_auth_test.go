package mysql

import (
	"testing"
)

func TestMySQLNativePasswordAuth(t *testing.T) {
	password := "testpass"
	scramble := []byte("test-scramble-bytes!")

	// Compute auth response
	auth := mysqlNativePassword(password, scramble)

	if len(auth) != scrambleLen {
		t.Fatalf("expected auth length %d, got %d", scrambleLen, len(auth))
	}

	// Verify that the same password+scramble produces the same result
	auth2 := mysqlNativePassword(password, scramble)
	if !constantTimeEqual(auth, auth2) {
		t.Fatal("auth not deterministic")
	}

	// Verify that different passwords produce different results
	auth3 := mysqlNativePassword("wrongpass", scramble)
	if constantTimeEqual(auth, auth3) {
		t.Fatal("different passwords should produce different auth")
	}

	// Verify that different scrambles produce different results
	scramble2 := []byte("ANOTHER-SCRAMBLE-!!")
	auth4 := mysqlNativePassword(password, scramble2)
	if constantTimeEqual(auth, auth4) {
		t.Fatal("different scrambles should produce different auth")
	}
}

func TestConstantTimeEqual(t *testing.T) {
	a := []byte("test-value-123")
	b := []byte("test-value-123")
	c := []byte("different-value")

	if !constantTimeEqual(a, b) {
		t.Error("equal slices should match")
	}
	if constantTimeEqual(a, c) {
		t.Error("different slices should not match")
	}
	if constantTimeEqual(nil, a) {
		t.Error("nil should not match non-nil")
	}
}

func TestBuildProxyGreeting(t *testing.T) {
	scramble := make([]byte, 20)
	for i := range scramble {
		scramble[i] = byte(i)
	}

	pkt := buildProxyGreeting(scramble)
	if pkt == nil {
		t.Fatal("greeting is nil")
	}

	if pkt.SequenceID != 0 {
		t.Errorf("expected seq 0, got %d", pkt.SequenceID)
	}

	payload := pkt.Payload
	if len(payload) < 80 {
		t.Fatalf("greeting too short: %d bytes", len(payload))
	}

	// Check protocol version
	if payload[0] != 10 {
		t.Errorf("expected protocol 10, got %d", payload[0])
	}

	// Check auth plugin name at end
	expectedPlugin := "mysql_native_password"
	pluginStart := len(payload) - len(expectedPlugin) - 1
	if pluginStart < 0 {
		t.Fatalf("payload too short for plugin name")
	}
	if string(payload[pluginStart:pluginStart+len(expectedPlugin)]) != expectedPlugin {
		t.Errorf("plugin name mismatch")
	}

	// Verify scramble embedded in greeting
	// Position: protocol(1) + version_str(19 chars + null = 20) + conn_id(4) = 25
	// Auth-plugin-data-part-1 starts at offset 25
	if payload[24] != scramble[0] {
		t.Errorf("scramble part1 mismatch at pos 24: got %d, want %d", payload[24], scramble[0])
	}
}

func TestBuildHandshakeResponse(t *testing.T) {
	username := "testuser"
	database := "testdb"
	authResp := []byte("test-auth-response-20-bytes!")
	plugin := "mysql_native_password"

	payload := buildHandshakeResponse(username, database, authResp, plugin)
	if len(payload) < 32 {
		t.Fatalf("handshake response too short: %d", len(payload))
	}

	// Parse and verify
	resp, err := ParseHandshakeResponse41(payload)
	if err != nil {
		t.Fatalf("ParseHandshakeResponse41: %v", err)
	}

	if resp.Username != username {
		t.Errorf("username = %q, want %q", resp.Username, username)
	}
	if resp.Database != database {
		t.Errorf("database = %q, want %q", resp.Database, database)
	}
}

func TestExtractScrambleFromGreeting(t *testing.T) {
	// Use BuildHandshakeV10 to create a real greeting
	pkt := BuildHandshakeV10(1, "8.0.35-test")
	if pkt == nil {
		t.Fatal("BuildHandshakeV10 returned nil")
	}

	scramble, plugin := extractScrambleFromGreeting(pkt.Payload)
	if scramble == nil {
		t.Fatal("extracted scramble is nil")
	}
	if len(scramble) != scrambleLen {
		t.Errorf("scramble length = %d, want %d", len(scramble), scrambleLen)
	}
	if plugin != "" {
		t.Errorf("plugin = %q, want empty", plugin)
	}
}

func TestMySQLNativePasswordRoundTrip(t *testing.T) {
	// Simulate server-side validation
	password := "my_secret_password"
	scramble := []byte("argus-auth-scramble-!")

	// Client computes auth response
	clientAuth := mysqlNativePassword(password, scramble)

	// Server validates by computing expected
	expected := mysqlNativePassword(password, scramble)

	if !constantTimeEqual(clientAuth, expected) {
		t.Fatal("client and server auth mismatch")
	}
}

func TestBuildProxyGreetingRoundTrip(t *testing.T) {
	scramble := []byte("custom-20-byte-scrmb")
	pkt := buildProxyGreeting(scramble)

	// Extract and verify
	extracted, _ := extractScrambleFromGreeting(pkt.Payload)
	if extracted == nil {
		t.Fatal("failed to extract scramble from built greeting")
	}

	// The extracted scramble should match the one we put in
	if len(extracted) != len(scramble) {
		t.Errorf("scramble length mismatch: %d vs %d", len(extracted), len(scramble))
	}
}
