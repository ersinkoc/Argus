package mssql

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/policy"
)

// --- MaskTDSRow direct tests (not covered by result_full_test.go) ---

func TestMaskTDSRowNBCRowToken(t *testing.T) {
	// NBCRow token should be recognized as a row
	data := []byte{TokenNBCRow, 0x04, 0x00, 't', 'e', 's', 't'}
	result := MaskTDSRow(data, nil, nil)
	if len(result) != len(data) {
		t.Error("NBCRow with nil pipeline should return unchanged")
	}
}

func TestMaskTDSRowWithTextColumn(t *testing.T) {
	cols := []TDSColumnMeta{
		{Name: "email", TypeID: 0xE7, MaxLen: 256, Index: 0, IsText: true},
	}

	// Build row: TokenRow + 2-byte len + field data
	var data []byte
	data = append(data, TokenRow)
	fieldData := []byte("alice@example.com")
	lenBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBuf, uint16(len(fieldData)))
	data = append(data, lenBuf...)
	data = append(data, fieldData...)

	rules := []policy.MaskingRule{{Column: "email", Transformer: "partial_email"}}
	pipeline := masking.NewPipeline(rules, []masking.ColumnInfo{{Name: "email", Index: 0}}, 0)

	result := MaskTDSRow(data, cols, pipeline)
	if len(result) == 0 {
		t.Fatal("result should not be empty")
	}
}

func TestMaskTDSRowNullField(t *testing.T) {
	cols := []TDSColumnMeta{
		{Name: "name", TypeID: 0xE7, MaxLen: 256, Index: 0, IsText: true},
	}

	// Build row with NULL field (0xFFFF length)
	var data []byte
	data = append(data, TokenRow)
	data = append(data, 0xFF, 0xFF) // NULL marker

	rules := []policy.MaskingRule{{Column: "name", Transformer: "redact"}}
	pipeline := masking.NewPipeline(rules, []masking.ColumnInfo{{Name: "name", Index: 0}}, 0)

	result := MaskTDSRow(data, cols, pipeline)
	if len(result) == 0 {
		t.Fatal("result should not be empty")
	}
}

func TestMaskTDSRowFixedLenColumn(t *testing.T) {
	cols := []TDSColumnMeta{
		{Name: "id", TypeID: 0x38, MaxLen: 4, Index: 0, IsText: false}, // INT
	}

	var data []byte
	data = append(data, TokenRow)
	data = append(data, 0x01, 0x00, 0x00, 0x00) // INT value 1

	rules := []policy.MaskingRule{{Column: "id", Transformer: "redact"}}
	pipeline := masking.NewPipeline(rules, []masking.ColumnInfo{{Name: "id", Index: 0}}, 0)

	result := MaskTDSRow(data, cols, pipeline)
	if len(result) == 0 {
		t.Fatal("result should not be empty")
	}
}

func TestMaskTDSRowTruncatedText(t *testing.T) {
	cols := []TDSColumnMeta{
		{Name: "val", TypeID: 0xE7, MaxLen: 256, Index: 0, IsText: true},
	}

	// Length says 100 but only 3 bytes available
	var data []byte
	data = append(data, TokenRow)
	data = append(data, 100, 0) // length 100
	data = append(data, 'a', 'b', 'c')

	rules := []policy.MaskingRule{{Column: "val", Transformer: "redact"}}
	pipeline := masking.NewPipeline(rules, []masking.ColumnInfo{{Name: "val", Index: 0}}, 0)

	result := MaskTDSRow(data, cols, pipeline)
	if len(result) == 0 {
		t.Fatal("should handle truncated data gracefully")
	}
}

func TestMaskTDSRowEmptyData(t *testing.T) {
	result := MaskTDSRow(nil, nil, nil)
	if result != nil {
		t.Error("nil data should return nil")
	}
	result = MaskTDSRow([]byte{}, nil, nil)
	if len(result) != 0 {
		t.Error("empty data should return empty")
	}
}

func TestMaskTDSRowMixedColumns(t *testing.T) {
	cols := []TDSColumnMeta{
		{Name: "id", TypeID: 0x38, MaxLen: 4, Index: 0, IsText: false},
		{Name: "name", TypeID: 0xE7, MaxLen: 256, Index: 1, IsText: true},
	}

	var data []byte
	data = append(data, TokenRow)
	// INT column: 4 bytes
	data = append(data, 0x01, 0x00, 0x00, 0x00)
	// NVARCHAR column: 2-byte len + data
	text := []byte("hello")
	lenBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBuf, uint16(len(text)))
	data = append(data, lenBuf...)
	data = append(data, text...)

	rules := []policy.MaskingRule{{Column: "name", Transformer: "redact"}}
	pipeline := masking.NewPipeline(rules, []masking.ColumnInfo{{Name: "name", Index: 1}}, 0)

	result := MaskTDSRow(data, cols, pipeline)
	if len(result) == 0 {
		t.Fatal("result should not be empty")
	}
}

func TestMaskTDSRowTruncatedLength(t *testing.T) {
	cols := []TDSColumnMeta{
		{Name: "val", TypeID: 0xE7, MaxLen: 256, Index: 0, IsText: true},
	}

	// Only 1 byte after token — not enough for 2-byte length
	data := []byte{TokenRow, 0x05}

	rules := []policy.MaskingRule{{Column: "val", Transformer: "redact"}}
	pipeline := masking.NewPipeline(rules, []masking.ColumnInfo{{Name: "val", Index: 0}}, 0)

	result := MaskTDSRow(data, cols, pipeline)
	if len(result) == 0 {
		t.Fatal("should handle gracefully")
	}
}

// --- ParseColMetadata for additional column types ---

func TestParseColMetadataBIGVARBIN(t *testing.T) {
	var data []byte
	data = append(data, TokenColMetadata)
	data = append(data, 1, 0)
	data = append(data, 0, 0, 0, 0, 0, 0)
	data = append(data, 0xA5) // BIGVARBIN
	data = append(data, 0x00, 0x02) // max len 512
	data = append(data, 3)
	data = append(data, 'b', 0, 'i', 0, 'n', 0)

	cols, consumed := ParseColMetadata(data)
	if consumed == 0 {
		t.Fatal("should consume bytes")
	}
	if len(cols) != 1 {
		t.Fatalf("got %d cols", len(cols))
	}
	if cols[0].IsText {
		t.Error("BIGVARBIN should not be text")
	}
	if cols[0].MaxLen != 512 {
		t.Errorf("maxLen = %d, want 512", cols[0].MaxLen)
	}
}

func TestParseColMetadataBIGVARCHR(t *testing.T) {
	var data []byte
	data = append(data, TokenColMetadata)
	data = append(data, 1, 0)
	data = append(data, 0, 0, 0, 0, 0, 0)
	data = append(data, 0xAD) // BIGVARCHR
	data = append(data, 0x00, 0x01)
	data = append(data, 2)
	data = append(data, 'c', 0, 'h', 0)

	cols, _ := ParseColMetadata(data)
	if len(cols) != 1 {
		t.Fatalf("got %d cols", len(cols))
	}
	if !cols[0].IsText {
		t.Error("BIGVARCHR should be text")
	}
}

func TestParseColMetadataIMAGE(t *testing.T) {
	var data []byte
	data = append(data, TokenColMetadata)
	data = append(data, 1, 0)
	data = append(data, 0, 0, 0, 0, 0, 0)
	data = append(data, 0x22) // IMAGE
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, 65536)
	data = append(data, lenBuf...)
	data = append(data, 3)
	data = append(data, 'i', 0, 'm', 0, 'g', 0)

	cols, _ := ParseColMetadata(data)
	if len(cols) != 1 {
		t.Fatalf("got %d cols", len(cols))
	}
	if cols[0].MaxLen != 65536 {
		t.Errorf("maxLen = %d", cols[0].MaxLen)
	}
}

func TestParseColMetadataTEXT(t *testing.T) {
	var data []byte
	data = append(data, TokenColMetadata)
	data = append(data, 1, 0)
	data = append(data, 0, 0, 0, 0, 0, 0)
	data = append(data, 0x23) // TEXT
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, 4096)
	data = append(data, lenBuf...)
	data = append(data, 3)
	data = append(data, 't', 0, 'x', 0, 't', 0)

	cols, _ := ParseColMetadata(data)
	if len(cols) != 1 {
		t.Fatalf("got %d cols", len(cols))
	}
}

func TestParseColMetadataUNIQUEIDENTIFIER(t *testing.T) {
	var data []byte
	data = append(data, TokenColMetadata)
	data = append(data, 1, 0)
	data = append(data, 0, 0, 0, 0, 0, 0)
	data = append(data, 0x24) // UNIQUEIDENTIFIER
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, 16)
	data = append(data, lenBuf...)
	data = append(data, 2)
	data = append(data, 'i', 0, 'd', 0)

	cols, _ := ParseColMetadata(data)
	if len(cols) != 1 {
		t.Fatalf("got %d cols", len(cols))
	}
}

func TestParseColMetadataDefaultVarType(t *testing.T) {
	// Type 0x26 (INTN) hits the default branch
	var data []byte
	data = append(data, TokenColMetadata)
	data = append(data, 1, 0)
	data = append(data, 0, 0, 0, 0, 0, 0)
	data = append(data, 0x26) // INTN
	data = append(data, 4)    // 1-byte variable length
	data = append(data, 1)
	data = append(data, 'n', 0)

	cols, _ := ParseColMetadata(data)
	if len(cols) != 1 {
		t.Fatalf("got %d cols", len(cols))
	}
	if cols[0].MaxLen != 4 {
		t.Errorf("maxLen = %d, want 4", cols[0].MaxLen)
	}
	if !cols[0].IsText {
		t.Error("default case should set IsText=true")
	}
}

func TestParseColMetadataNChar(t *testing.T) {
	var data []byte
	data = append(data, TokenColMetadata)
	data = append(data, 1, 0)
	data = append(data, 0, 0, 0, 0, 0, 0)
	data = append(data, 0xEF) // NCHAR
	data = append(data, 0x14, 0x00) // max 20
	data = append(data, 0, 0, 0, 0, 0) // collation
	data = append(data, 1)
	data = append(data, 'c', 0)

	cols, _ := ParseColMetadata(data)
	if len(cols) != 1 {
		t.Fatalf("got %d cols", len(cols))
	}
	if !cols[0].IsText {
		t.Error("NCHAR should be text")
	}
}

func TestParseColMetadataTruncatedColData(t *testing.T) {
	// Data too short for user type + flags
	data := []byte{TokenColMetadata, 1, 0, 0, 0}
	cols, _ := ParseColMetadata(data)
	if len(cols) != 0 {
		t.Error("truncated data should return empty cols")
	}
}

func TestParseColMetadataBadToken(t *testing.T) {
	data := []byte{0x00, 1, 0}
	cols, consumed := ParseColMetadata(data)
	if cols != nil || consumed != 0 {
		t.Error("wrong token should fail")
	}
}

// --- Handshake helper edge cases ---

func TestExtractLogin7UsernameValid(t *testing.T) {
	data := make([]byte, 120)
	binary.LittleEndian.PutUint16(data[48:50], 94)
	binary.LittleEndian.PutUint16(data[50:52], 4)
	copy(data[94:], []byte{'t', 0, 'e', 0, 's', 0, 't', 0})

	got := extractLogin7Username(data)
	if got != "test" {
		t.Errorf("username = %q, want 'test'", got)
	}
}

func TestExtractSQLBatchWithHeaders(t *testing.T) {
	// ALL_HEADERS totalLen=4 means skip 4 bytes
	data := []byte{4, 0, 0, 0, 'S', 0, 'Q', 0, 'L', 0}
	got := extractSQLBatch(data)
	if got != "SQL" {
		t.Errorf("got %q, want 'SQL'", got)
	}
}

func TestExtractSQLBatchZeroHeaders(t *testing.T) {
	// ALL_HEADERS totalLen=0 means no valid header, data decoded from start
	data := []byte{0, 0, 0, 0, 'S', 0, 'Q', 0, 'L', 0}
	got := extractSQLBatch(data)
	// totalLen=0, condition 0>0 is false, so entire data decoded as UTF-16LE
	if len(got) == 0 {
		t.Error("should decode something")
	}
}

// --- ReadPacket edge cases ---

func TestReadPacketInvalidLength(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		header := make([]byte, 8)
		header[0] = PacketSQLBatch
		header[1] = StatusEOM
		binary.BigEndian.PutUint16(header[2:4], 4) // < headerSize
		clientConn.Write(header)
	}()

	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadPacket(serverConn)
	if err == nil {
		t.Error("should fail for invalid length")
	}
}

// --- ReadAllPackets multi-packet ---

func TestReadAllPacketsMulti(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		// First packet without EOM
		pkt1 := &Packet{Type: PacketSQLBatch, Status: StatusNormal, Data: []byte("hello")}
		WritePacket(clientConn, pkt1)
		// Second packet with EOM
		pkt2 := &Packet{Type: PacketSQLBatch, Status: StatusEOM, Data: []byte(" world")}
		WritePacket(clientConn, pkt2)
	}()

	serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	data, pktType, err := ReadAllPackets(serverConn)
	if err != nil {
		t.Fatalf("ReadAllPackets: %v", err)
	}
	if pktType != PacketSQLBatch {
		t.Errorf("type = 0x%02x", pktType)
	}
	if string(data) != "hello world" {
		t.Errorf("data = %q", data)
	}
}

// --- decodeUTF16LESlice ---

func TestDecodeUTF16LESliceValid(t *testing.T) {
	data := []byte{'H', 0, 'i', 0}
	if got := decodeUTF16LESlice(data); got != "Hi" {
		t.Errorf("got %q", got)
	}
}

func TestDecodeUTF16LESliceNil(t *testing.T) {
	if decodeUTF16LESlice(nil) != "" {
		t.Error("nil should return empty")
	}
}

// --- Handshake full test with wrong packet type ---

func TestHandshakeWrongPreLoginType(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()

	backendConn, proxyBackend := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()

	h := New()

	// Send non-PreLogin packet from client
	go func() {
		pkt := &Packet{Type: PacketSQLBatch, Status: StatusEOM, Data: []byte("bad")}
		WritePacket(clientConn, pkt)
	}()

	proxyClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("wrong packet type should fail handshake")
	}
}

// --- BuildErrorToken verification ---

func TestBuildErrorTokenContent(t *testing.T) {
	token := BuildErrorToken(12345, 1, 16, "test error", "server", "proc", 42)
	if len(token) == 0 {
		t.Fatal("empty token")
	}
	if token[0] != TokenError {
		t.Errorf("first byte = 0x%02x, want TokenError", token[0])
	}
	// Verify number field (bytes 3-6 after token byte + 2-byte length)
	number := binary.LittleEndian.Uint32(token[3:7])
	if number != 12345 {
		t.Errorf("number = %d, want 12345", number)
	}
}
