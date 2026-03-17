package mysql

import (
	"testing"

	"github.com/ersinkoc/argus/internal/masking"
)

func TestHandlerClose(t *testing.T) {
	h := New()
	if err := h.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestEncodePacketRoundtrip(t *testing.T) {
	pkt := &Packet{SequenceID: 5, Payload: []byte("test data")}
	encoded := EncodePacket(pkt)

	parsed, err := ReadPacketFromBytes(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.SequenceID != 5 {
		t.Errorf("seq = %d", parsed.SequenceID)
	}
	if string(parsed.Payload) != "test data" {
		t.Errorf("payload = %q", parsed.Payload)
	}
}

func TestBuildOKPacketContent(t *testing.T) {
	pkt := BuildOKPacket(1, 5, 10)
	if pkt.Payload[0] != 0x00 {
		t.Error("should start with 0x00")
	}
	if pkt.SequenceID != 1 {
		t.Errorf("seq = %d", pkt.SequenceID)
	}
}

func TestBuildEOFPacketContent(t *testing.T) {
	pkt := BuildEOFPacket(3)
	if pkt.Payload[0] != 0xFE {
		t.Error("should start with 0xFE")
	}
}

func TestEncodeLenEnc(t *testing.T) {
	// Small value
	b := encodeLenEnc(42)
	if len(b) != 1 || b[0] != 42 {
		t.Errorf("small = %v", b)
	}

	// Medium value
	b = encodeLenEnc(1000)
	if len(b) != 3 || b[0] != 0xfc {
		t.Errorf("medium = %v", b)
	}

	// Large value
	b = encodeLenEnc(100000)
	if len(b) != 4 || b[0] != 0xfd {
		t.Errorf("large = %v", b)
	}

	// Very large
	b = encodeLenEnc(1 << 24)
	if len(b) != 9 || b[0] != 0xfe {
		t.Errorf("very large = %v", b)
	}
}

func TestExtractColumnNameEdge(t *testing.T) {
	// Test with empty payload
	name := extractColumnName(nil)
	if name != "" {
		t.Errorf("nil should be empty, got %q", name)
	}

	// Short payload
	name = extractColumnName([]byte{1, 'x'})
	if name != "" {
		t.Errorf("short should be empty, got %q", name)
	}
}

func TestParseMySQLTextRowNULL(t *testing.T) {
	// Row with NULLs
	payload := []byte{0xFB, 0xFB}
	fields := parseMySQLTextRow(payload, 2)

	if fields[0] != nil {
		t.Error("field 0 should be nil")
	}
	if fields[1] != nil {
		t.Error("field 1 should be nil")
	}
}

func TestBuildMySQLTextRow(t *testing.T) {
	fields := []masking.FieldValue{
		{Data: []byte("hello")},
		{IsNull: true},
		{Data: []byte("world")},
	}

	row := buildMySQLTextRow(fields)
	if len(row) == 0 {
		t.Error("should not be empty")
	}
	// First byte: length of "hello" = 5
	if row[0] != 5 {
		t.Errorf("first length = %d, want 5", row[0])
	}
}
