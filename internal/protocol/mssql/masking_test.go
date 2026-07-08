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

// --- ReadPacket: header read error ---

func TestReadPacketHeaderReadError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	clientConn.Close()
	defer serverConn.Close()

	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadPacket(serverConn)
	if err == nil {
		t.Error("header read error should fail")
	}
}

// --- ReadPacket: data read error (valid header but connection closes before data) ---

func TestReadPacketDataReadError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	go func() {
		header := make([]byte, headerSize)
		header[0] = PacketSQLBatch
		header[1] = StatusEOM
		binary.BigEndian.PutUint16(header[2:4], 100) // claims 92 bytes of data
		clientConn.Write(header)
		clientConn.Write([]byte("short")) // only 5 bytes
		clientConn.Close()
	}()

	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := ReadPacket(serverConn)
	if err == nil {
		t.Error("data read error should fail")
	}
}

// --- ReadAllPackets: read error ---

func TestReadAllPacketsReadError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	clientConn.Close()
	defer serverConn.Close()

	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	_, _, err := ReadAllPackets(serverConn)
	if err == nil {
		t.Error("read error should fail")
	}
}

// --- ReadAllPackets: reassembly size exceeded ---

func TestReadAllPacketsReassemblySizeExceeded(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		// Send many packets without EOM to exceed reassembly limit
		// Each packet can have up to 32768-8 = 32760 bytes
		// MaxReassemblySize = 16MB = 16*1024*1024 = 16777216
		// Need ~512 packets of 32760 bytes
		// Easier: just send enough to exceed the limit
		bigData := make([]byte, 32760)
		for i := 0; i < 600; i++ {
			pkt := &Packet{Type: PacketSQLBatch, Status: StatusNormal, Data: bigData}
			if err := WritePacket(clientConn, pkt); err != nil {
				return
			}
		}
	}()

	serverConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, _, err := ReadAllPackets(serverConn)
	if err == nil {
		t.Error("reassembly size exceeded should fail")
	}
}

// --- Handshake: backend pre-login response read error ---

func TestHandshakeBackendPreLoginReadError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()

	go func() {
		pkt := &Packet{Type: PacketPreLogin, Status: StatusEOM, Data: []byte("prelogin")}
		WritePacket(clientConn, pkt)
	}()

	go func() {
		ReadPacket(backendConn)
		backendConn.Close() // close before sending response
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("backend pre-login read error should fail")
	}
}

// --- Handshake: forward pre-login response to client write error ---

func TestHandshakeForwardPreLoginRespWriteError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		pkt := &Packet{Type: PacketPreLogin, Status: StatusEOM, Data: []byte("prelogin")}
		WritePacket(clientConn, pkt)
		clientConn.Close() // close before response can be forwarded
	}()

	go func() {
		ReadPacket(backendConn)
		WritePacket(backendConn, BuildPreLoginResponse())
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("forward pre-login response write error should fail")
	}
}

// --- Handshake: client login read error ---

func TestHandshakeClientLoginReadError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		pkt := &Packet{Type: PacketPreLogin, Status: StatusEOM, Data: []byte("prelogin")}
		WritePacket(clientConn, pkt)
		ReadPacket(clientConn) // read pre-login response
		clientConn.Close()     // close before login
	}()

	go func() {
		ReadPacket(backendConn)
		WritePacket(backendConn, BuildPreLoginResponse())
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("client login read error should fail")
	}
}

// --- Handshake: forward login to backend write error ---

func TestHandshakeForwardLoginWriteError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()

	go func() {
		pkt := &Packet{Type: PacketPreLogin, Status: StatusEOM, Data: []byte("prelogin")}
		WritePacket(clientConn, pkt)
		ReadPacket(clientConn) // read pre-login response
		loginPkt := &Packet{Type: PacketTDS7Login, Status: StatusEOM, Data: buildTestLogin7("test")}
		WritePacket(clientConn, loginPkt)
	}()

	go func() {
		ReadPacket(backendConn)
		WritePacket(backendConn, BuildPreLoginResponse())
		backendConn.Close() // close before login forward
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("forward login write error should fail")
	}
}

// --- Handshake: login response read error ---

func TestHandshakeLoginRespReadError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()

	go func() {
		pkt := &Packet{Type: PacketPreLogin, Status: StatusEOM, Data: []byte("prelogin")}
		WritePacket(clientConn, pkt)
		ReadPacket(clientConn)
		loginPkt := &Packet{Type: PacketTDS7Login, Status: StatusEOM, Data: buildTestLogin7("test")}
		WritePacket(clientConn, loginPkt)
	}()

	go func() {
		ReadPacket(backendConn)
		WritePacket(backendConn, BuildPreLoginResponse())
		ReadPacket(backendConn)
		backendConn.Close() // close before sending login response
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("login response read error should fail")
	}
}

// --- Handshake: forward login response write error ---

func TestHandshakeForwardLoginRespWriteError(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	backendConn, proxyBackend := net.Pipe()
	defer proxyClient.Close()
	defer backendConn.Close()
	defer proxyBackend.Close()

	go func() {
		pkt := &Packet{Type: PacketPreLogin, Status: StatusEOM, Data: []byte("prelogin")}
		WritePacket(clientConn, pkt)
		ReadPacket(clientConn)
		loginPkt := &Packet{Type: PacketTDS7Login, Status: StatusEOM, Data: buildTestLogin7("test")}
		WritePacket(clientConn, loginPkt)
		clientConn.Close() // close before login response can be forwarded
	}()

	go func() {
		ReadPacket(backendConn)
		WritePacket(backendConn, BuildPreLoginResponse())
		ReadPacket(backendConn)
		var loginResp []byte
		loginResp = append(loginResp, TokenLoginAck, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
		loginResp = append(loginResp, TokenDone, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
		WritePacket(backendConn, &Packet{Type: PacketReply, Status: StatusEOM, Data: loginResp})
	}()

	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))
	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))

	h := New()
	_, err := h.Handshake(context.Background(), proxyClient, proxyBackend)
	if err == nil {
		t.Error("forward login response write error should fail")
	}
}

// --- ReadCommand: read error ---

func TestReadCommandError(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	clientConn.Close()
	defer proxyConn.Close()

	h := New()
	proxyConn.SetReadDeadline(time.Now().Add(time.Second))
	_, _, err := h.ReadCommand(context.Background(), proxyConn)
	if err == nil {
		t.Error("read error should fail")
	}
}

// --- ReadAndForwardResult: multi-packet without EOM then EOM ---

func TestReadAndForwardResultMultiPacket(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()

	go func() {
		// First packet without EOM
		var data1 []byte
		data1 = append(data1, TokenRow)
		data1 = append(data1, 0x00, 0x00)
		WritePacket(backendConn, &Packet{Type: PacketReply, Status: StatusNormal, Data: data1})

		// Second packet with EOM and Done token
		var data2 []byte
		data2 = append(data2, TokenDone, 0, 0, 0, 0, 0, 0, 0, 0)
		WritePacket(backendConn, &Packet{Type: PacketReply, Status: StatusEOM, Data: data2})
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadPacket(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	stats, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if stats.RowCount != 1 {
		t.Errorf("rows = %d, want 1", stats.RowCount)
	}
}

// --- ReadAndForwardResult: with COLMETADATA and masking pipeline ---

func TestReadAndForwardResultWithMasking(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()

	go func() {
		// Build COLMETADATA + ROW + Done in one packet
		var data []byte

		// COLMETADATA: 1 NVARCHAR column named "email"
		data = append(data, TokenColMetadata)
		data = append(data, 1, 0) // 1 column
		data = append(data, 0, 0, 0, 0, 0, 0) // user type + flags
		data = append(data, 0xE7)               // NVARCHAR
		data = append(data, 0x00, 0x01)         // max length 256
		data = append(data, 0, 0, 0, 0, 0)     // collation
		emailName := toUTF16LE("email")
		data = append(data, byte(len("email"))) // name length in chars
		data = append(data, emailName...)

		// ROW token + 2-byte len + field data
		data = append(data, TokenRow)
		fieldData := []byte("alice@test.com")
		lenBuf := make([]byte, 2)
		binary.LittleEndian.PutUint16(lenBuf, uint16(len(fieldData)))
		data = append(data, lenBuf...)
		data = append(data, fieldData...)

		// Done token
		data = append(data, TokenDone, 0, 0, 0, 0, 0, 0, 0, 0)

		WritePacket(backendConn, &Packet{Type: PacketReply, Status: StatusEOM, Data: data})
	}()

	go func() {
		for {
			clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := ReadPacket(clientConn)
			if err != nil {
				return
			}
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	rules := []policy.MaskingRule{{Column: "email", Transformer: "redact"}}
	pipeline := masking.NewPipeline(rules, []masking.ColumnInfo{{Name: "email", Index: 0}}, 0)

	stats, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, pipeline)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if stats.RowCount != 1 {
		t.Errorf("rows = %d, want 1", stats.RowCount)
	}
}

// --- ReadAndForwardResult: NBCRow tokens ---

func TestReadAndForwardResultNBCRow(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()

	go func() {
		var data []byte
		data = append(data, TokenNBCRow, 0x00, 0x00)
		data = append(data, TokenDone, 0, 0, 0, 0, 0, 0, 0, 0)
		WritePacket(backendConn, &Packet{Type: PacketReply, Status: StatusEOM, Data: data})
	}()

	go func() {
		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		ReadPacket(clientConn)
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	stats, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if stats.RowCount != 1 {
		t.Errorf("rows = %d, want 1", stats.RowCount)
	}
}

// --- ParseColMetadata: 0xFFFF (no metadata) ---

func TestParseColMetadataNoMetadata(t *testing.T) {
	data := []byte{TokenColMetadata, 0xFF, 0xFF} // count = 0xFFFF
	cols, consumed := ParseColMetadata(data)
	if cols != nil {
		t.Error("0xFFFF should return nil cols")
	}
	if consumed != 3 {
		t.Errorf("consumed = %d, want 3", consumed)
	}
}

// --- ParseColMetadata: truncated at typeID ---

func TestParseColMetadataTruncatedTypeID(t *testing.T) {
	var data []byte
	data = append(data, TokenColMetadata)
	data = append(data, 1, 0)             // 1 column
	data = append(data, 0, 0, 0, 0, 0, 0) // user type + flags
	// No type ID byte

	cols, _ := ParseColMetadata(data)
	if len(cols) != 0 {
		t.Error("truncated at typeID should return empty cols")
	}
}

// --- ParseColMetadata: NVARCHAR truncated at length ---

func TestParseColMetadataNVARCHARTruncatedLen(t *testing.T) {
	var data []byte
	data = append(data, TokenColMetadata)
	data = append(data, 1, 0)
	data = append(data, 0, 0, 0, 0, 0, 0)
	data = append(data, 0xE7) // NVARCHAR
	// No length bytes

	cols, _ := ParseColMetadata(data)
	if len(cols) != 0 {
		t.Error("truncated NVARCHAR len should return empty cols")
	}
}

// --- ParseColMetadata: BIGVARBIN truncated at length ---

func TestParseColMetadataBIGVARBINTruncatedLen(t *testing.T) {
	var data []byte
	data = append(data, TokenColMetadata)
	data = append(data, 1, 0)
	data = append(data, 0, 0, 0, 0, 0, 0)
	data = append(data, 0xA5) // BIGVARBIN
	// No length bytes

	cols, _ := ParseColMetadata(data)
	if len(cols) != 0 {
		t.Error("truncated BIGVARBIN len should return empty cols")
	}
}

// --- ParseColMetadata: truncated at column name ---

func TestParseColMetadataTruncatedName(t *testing.T) {
	var data []byte
	data = append(data, TokenColMetadata)
	data = append(data, 1, 0)
	data = append(data, 0, 0, 0, 0, 0, 0)
	data = append(data, 0x38) // INT (fixed)
	data = append(data, 5)    // name length 5 chars
	data = append(data, 'a', 0) // only 1 char (2 bytes), not 5

	cols, _ := ParseColMetadata(data)
	if len(cols) != 0 {
		t.Error("truncated name should return empty cols")
	}
}

// --- ParseColMetadata: truncated at name length byte ---

func TestParseColMetadataTruncatedNameLen(t *testing.T) {
	var data []byte
	data = append(data, TokenColMetadata)
	data = append(data, 1, 0)
	data = append(data, 0, 0, 0, 0, 0, 0)
	data = append(data, 0x38) // INT (fixed len = 4)
	// No name length byte — offset == len(data)

	cols, _ := ParseColMetadata(data)
	if len(cols) != 0 {
		t.Error("truncated at name len should return empty")
	}
}

// --- MaskTDSRow: non-Row token ---

func TestMaskTDSRowNonRowTokenType(t *testing.T) {
	data := []byte{TokenDone, 0, 0, 0, 0}
	result := MaskTDSRow(data, nil, nil)
	if string(result) != string(data) {
		t.Error("non-row token should return unchanged")
	}
}

// --- MaskTDSRow: no masking (pipeline without HasMasking) ---

func TestMaskTDSRowNoMasking(t *testing.T) {
	data := []byte{TokenRow, 0x01, 0x00, 0x00, 0x00}
	cols := []TDSColumnMeta{{Name: "id", TypeID: 0x38, MaxLen: 4, IsText: false}}
	// Pipeline with no rules
	pipeline := masking.NewPipeline(nil, nil, 0)

	result := MaskTDSRow(data, cols, pipeline)
	if string(result) != string(data) {
		t.Error("no masking pipeline should return unchanged")
	}
}

// --- MaskTDSRow: offset exceeds data for fixed column ---

func TestMaskTDSRowFixedColumnTruncated(t *testing.T) {
	cols := []TDSColumnMeta{
		{Name: "id", TypeID: 0x38, MaxLen: 4, IsText: false},
	}

	// TokenRow + only 2 bytes instead of 4 for INT
	data := []byte{TokenRow, 0x01, 0x00}

	rules := []policy.MaskingRule{{Column: "id", Transformer: "redact"}}
	pipeline := masking.NewPipeline(rules, []masking.ColumnInfo{{Name: "id", Index: 0}}, 0)

	result := MaskTDSRow(data, cols, pipeline)
	if len(result) == 0 {
		t.Error("should handle truncated fixed column gracefully")
	}
}

// --- MaskTDSRow: offset exceeds data at start of col ---

func TestMaskTDSRowOffsetExceedsData(t *testing.T) {
	cols := []TDSColumnMeta{
		{Name: "col1", TypeID: 0x38, MaxLen: 4, IsText: false},
		{Name: "col2", TypeID: 0xE7, MaxLen: 256, IsText: true},
	}

	// Only enough data for first column
	data := []byte{TokenRow, 0x01, 0x00, 0x00, 0x00}

	rules := []policy.MaskingRule{{Column: "col2", Transformer: "redact"}}
	pipeline := masking.NewPipeline(rules, []masking.ColumnInfo{{Name: "col2", Index: 1}}, 0)

	result := MaskTDSRow(data, cols, pipeline)
	if len(result) == 0 {
		t.Error("should handle gracefully")
	}
}

// --- MaskTDSRow: masked result is empty (triggers else branch via truncation) ---

func TestMaskTDSRowTruncatedProcessRow(t *testing.T) {
	// 2 text columns, maxRows=1 so second ProcessRow returns nil (truncated)
	cols := []TDSColumnMeta{
		{Name: "col1", TypeID: 0xE7, MaxLen: 256, Index: 0, IsText: true},
		{Name: "col2", TypeID: 0xE7, MaxLen: 256, Index: 1, IsText: true},
	}

	// Build row: TokenRow + col1(2-byte len + data) + col2(2-byte len + data)
	var data []byte
	data = append(data, TokenRow)

	field1 := []byte("first")
	lenBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenBuf, uint16(len(field1)))
	data = append(data, lenBuf...)
	data = append(data, field1...)

	field2 := []byte("second")
	binary.LittleEndian.PutUint16(lenBuf, uint16(len(field2)))
	data = append(data, lenBuf...)
	data = append(data, field2...)

	// maxRows=1 means first ProcessRow call succeeds, second is truncated
	rules := []policy.MaskingRule{{Column: "col1", Transformer: "redact"}, {Column: "col2", Transformer: "redact"}}
	pipeline := masking.NewPipeline(rules, []masking.ColumnInfo{{Name: "col1", Index: 0}, {Name: "col2", Index: 1}}, 1)

	result := MaskTDSRow(data, cols, pipeline)
	if len(result) == 0 {
		t.Fatal("result should not be empty")
	}
}

// --- isFixedLenType and fixedTypeLen ---

func TestFixedTypeLenAllTypes(t *testing.T) {
	fixedTypes := []byte{0x30, 0x32, 0x34, 0x38, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x7A, 0x7F}
	for _, typ := range fixedTypes {
		if !isFixedLenType(typ) {
			t.Errorf("0x%02x should be fixed type", typ)
		}
		if fixedTypeLen(typ) == 0 {
			t.Errorf("0x%02x should have non-zero length", typ)
		}
	}

	if isFixedLenType(0xE7) {
		t.Error("NVARCHAR should not be fixed type")
	}
	if fixedTypeLen(0xE7) != 0 {
		t.Error("non-fixed type should return 0")
	}
}

// --- ReadPacket: zero-length data (packet with length == headerSize) ---

func TestReadPacketZeroData(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		header := make([]byte, headerSize)
		header[0] = PacketReply
		header[1] = StatusEOM
		binary.BigEndian.PutUint16(header[2:4], headerSize) // length = headerSize, no data
		clientConn.Write(header)
	}()

	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	pkt, err := ReadPacket(serverConn)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if len(pkt.Data) != 0 {
		t.Errorf("data length = %d, want 0", len(pkt.Data))
	}
}

// --- ParseColMetadata: IMAGE type truncated (less than 4 bytes for length) ---

func TestParseColMetadataIMAGETruncatedLen(t *testing.T) {
	var data []byte
	data = append(data, TokenColMetadata)
	data = append(data, 1, 0)
	data = append(data, 0, 0, 0, 0, 0, 0)
	data = append(data, 0x22) // IMAGE
	data = append(data, 0, 0) // only 2 bytes, need 4

	cols, _ := ParseColMetadata(data)
	// Should handle gracefully (IMAGE gets 0 maxLen)
	_ = cols
}

func TestPatchPreLoginEncryption(t *testing.T) {
	// Build a valid pre-login response with ENCRYPTION token
	// Token header: [type(1) offset(2) length(2)] ...  0xFF terminator, then data
	var data []byte
	// VERSION token: type=0x00, offset=11, length=6
	data = append(data, 0x00, 0, 11, 0, 6)
	// ENCRYPTION token: type=0x01, offset=17, length=1
	data = append(data, 0x01, 0, 17, 0, 1)
	// Terminator
	data = append(data, 0xFF)
	// VERSION data at offset 11 (6 bytes)
	data = append(data, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00)
	// ENCRYPTION data at offset 17: 0x01 = ENCRYPT_ON
	data = append(data, 0x01)

	if data[17] != 0x01 {
		t.Fatalf("pre-condition: encryption byte should be 0x01, got 0x%02x", data[17])
	}

	patchPreLoginEncryption(data)

	if data[17] != 0x02 {
		t.Errorf("encryption byte should be 0x02 (NOT_SUP) after patch, got 0x%02x", data[17])
	}
}

func TestPatchPreLoginEncryptionNoToken(t *testing.T) {
	// Pre-login with only VERSION, no ENCRYPTION token
	var data []byte
	data = append(data, 0x00, 0, 6, 0, 6) // VERSION
	data = append(data, 0xFF)              // terminator
	data = append(data, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00)

	orig := make([]byte, len(data))
	copy(orig, data)

	patchPreLoginEncryption(data)

	// Should not modify anything
	for i := range data {
		if data[i] != orig[i] {
			t.Errorf("byte %d changed: 0x%02x -> 0x%02x", i, orig[i], data[i])
		}
	}
}

func TestPatchPreLoginEncryptionTruncated(t *testing.T) {
	// Truncated data - less than 5 bytes
	data := []byte{0x01, 0x00}
	patchPreLoginEncryption(data) // should not panic
}

func TestPatchPreLoginEncryptionEmpty(t *testing.T) {
	patchPreLoginEncryption(nil)      // should not panic
	patchPreLoginEncryption([]byte{}) // should not panic
}

func TestDisableMARS(t *testing.T) {
	// Build a Login7 with fExtension=1 and FeatureExt block
	data := make([]byte, 240)
	data[0], data[1], data[2], data[3] = 240, 0, 0, 0 // Length=240
	data[25] = 0x07                                      // OptionFlags2: MARS (0x04) + others
	data[27] = 0x1A                                      // OptionFlags3: fExtension (0x10) + others
	data[56], data[57] = 200, 0                          // ibExtension -> offset 200
	data[200], data[201], data[202], data[203] = 210, 0, 0, 0 // ptr -> FeatureExt at 210
	data[210] = 0x01                                      // Feature SESSION_RECOVERY
	data[211], data[212], data[213], data[214] = 0, 0, 0, 0
	data[215] = 0xFF // terminator

	result := disableMARS(data)

	if result[25]&0x04 != 0 {
		t.Errorf("MARS bit should be cleared, got 0x%02x", result[25])
	}
	if result[27]&0x10 != 0 {
		t.Errorf("fExtension should be cleared, got 0x%02x", result[27])
	}
	if len(result) != 211 {
		t.Errorf("expected truncated to 211, got %d", len(result))
	}
	if result[210] != 0xFF {
		t.Errorf("FeatureExt should be 0xFF, got 0x%02x", result[210])
	}
	newLen := int(result[0]) | int(result[1])<<8
	if newLen != 211 {
		t.Errorf("Login7 length should be 211, got %d", newLen)
	}
}

func TestDisableMARSNoExtension(t *testing.T) {
	data := make([]byte, 94)
	data[0] = 94
	data[25] = 0x04 // MARS on
	data[27] = 0x00 // no fExtension
	result := disableMARS(data)
	if result[25]&0x04 != 0 {
		t.Errorf("MARS should be cleared")
	}
}

func TestDisableMARSShortData(t *testing.T) {
	r := disableMARS(nil)
	if r != nil {
		t.Error("nil should return nil")
	}
	r = disableMARS([]byte{1, 2, 3})
	if len(r) != 3 {
		t.Error("short data returned wrong length")
	}
}

func TestPatchPreLoginMARS(t *testing.T) {
	// Build pre-login with MARS token (0x04) set to ON (0x01)
	var data []byte
	data = append(data, 0x00, 0, 11, 0, 6) // VERSION token
	data = append(data, 0x04, 0, 17, 0, 1) // MARS token at offset 17
	data = append(data, 0xFF)               // terminator
	for len(data) < 11 {
		data = append(data, 0)
	}
	data = append(data, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00) // VERSION data
	data = append(data, 0x01)                                  // MARS = ON

	patchPreLoginMARS(data)

	if data[17] != 0x00 {
		t.Errorf("MARS should be 0x00 after patch, got 0x%02x", data[17])
	}
}

func TestPatchPreLoginMARSNoToken(t *testing.T) {
	var data []byte
	data = append(data, 0x00, 0, 6, 0, 6) // only VERSION
	data = append(data, 0xFF)
	data = append(data, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00)
	orig := make([]byte, len(data))
	copy(orig, data)
	patchPreLoginMARS(data)
	for i := range data {
		if data[i] != orig[i] {
			t.Errorf("byte %d changed", i)
		}
	}
}

func TestDisableMARSAlreadyDisabled(t *testing.T) {
	data := make([]byte, 94)
	data[0] = 94
	result := disableMARS(data)
	if result[25] != 0x00 || result[27] != 0x00 {
		t.Errorf("should remain 0x00, got OF2=0x%02x OF3=0x%02x", result[25], result[27])
	}
}
