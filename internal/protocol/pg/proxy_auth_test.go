package pg

import (
	"testing"
)

// TestProxyAuthMessageBuilders tests the auth message construction helpers.
func TestProxyAuthMessageBuilders(t *testing.T) {
	// Test buildAuthSASL
	msg := buildAuthSASL("SCRAM-SHA-256")
	if msg.Type != MsgAuth {
		t.Errorf("expected MsgAuth, got %c", msg.Type)
	}
	if len(msg.Payload) < 5 {
		t.Fatal("payload too short")
	}

	// Verify auth type is AuthSASL (10)
	authType := int32(msg.Payload[0])<<24 | int32(msg.Payload[1])<<16 |
		int32(msg.Payload[2])<<8 | int32(msg.Payload[3])
	if authType != AuthSASL {
		t.Errorf("expected AuthSASL (10), got %d", authType)
	}

	// Verify SASL mechanisms in payload
	mechPayload := string(msg.Payload[4:])
	if mechPayload != "SCRAM-SHA-256\x00\x00" {
		t.Errorf("unexpected mechanisms: %q", mechPayload)
	}

	// Test buildAuthSASLContinue
	contMsg := buildAuthSASLContinue("r=test,s=dGVzdHNhbHQ=,i=4096")
	if contMsg.Type != MsgAuth {
		t.Errorf("expected MsgAuth, got %c", contMsg.Type)
	}
	contAT := int32(contMsg.Payload[0])<<24 | int32(contMsg.Payload[1])<<16 |
		int32(contMsg.Payload[2])<<8 | int32(contMsg.Payload[3])
	if contAT != AuthSASLContinue {
		t.Errorf("expected AuthSASLContinue (11), got %d", contAT)
	}
	if string(contMsg.Payload[4:]) != "r=test,s=dGVzdHNhbHQ=,i=4096" {
		t.Errorf("unexpected payload: %q", string(contMsg.Payload[4:]))
	}

	// Test buildAuthSASLFinal
	finalMsg := buildAuthSASLFinal("v=dGVzdHNpZw==")
	if finalMsg.Type != MsgAuth {
		t.Errorf("expected MsgAuth, got %c", finalMsg.Type)
	}
	finalAT := int32(finalMsg.Payload[0])<<24 | int32(finalMsg.Payload[1])<<16 |
		int32(finalMsg.Payload[2])<<8 | int32(finalMsg.Payload[3])
	if finalAT != AuthSASLFinal {
		t.Errorf("expected AuthSASLFinal (12), got %d", finalAT)
	}
	if string(finalMsg.Payload[4:]) != "v=dGVzdHNpZw==" {
		t.Errorf("unexpected payload: %q", string(finalMsg.Payload[4:]))
	}
}

// TestBuildAuthSASLMultipleMechanisms tests sending multiple SASL mechanisms.
func TestBuildAuthSASLMultipleMechanisms(t *testing.T) {
	msg := buildAuthSASL("SCRAM-SHA-256", "SCRAM-SHA-256-PLUS")
	payload := string(msg.Payload[4:])

	if payload != "SCRAM-SHA-256\x00SCRAM-SHA-256-PLUS\x00\x00" {
		t.Errorf("unexpected mechanisms: %q", payload)
	}
}
