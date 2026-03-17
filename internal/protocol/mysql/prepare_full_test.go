package mysql

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestHandlePrepareResponseWithParams(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()
	h.lastCmdByte = ComStmtPrepare

	// Backend: PREPARE OK with 2 params, 1 col
	go func() {
		var resp []byte
		resp = append(resp, 0x00)
		stmtID := make([]byte, 4)
		binary.LittleEndian.PutUint32(stmtID, 99)
		resp = append(resp, stmtID...)
		cols := make([]byte, 2)
		binary.LittleEndian.PutUint16(cols, 1) // 1 column
		resp = append(resp, cols...)
		params := make([]byte, 2)
		binary.LittleEndian.PutUint16(params, 2) // 2 params
		resp = append(resp, params...)
		resp = append(resp, 0)    // filler
		resp = append(resp, 0, 0) // warnings
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: resp})

		// 2 param definitions
		WritePacket(backendConn, &Packet{SequenceID: 2, Payload: []byte("param1_def")})
		WritePacket(backendConn, &Packet{SequenceID: 3, Payload: []byte("param2_def")})
		// EOF after params
		WritePacket(backendConn, BuildEOFPacket(4))

		// 1 column definition
		WritePacket(backendConn, &Packet{SequenceID: 5, Payload: []byte("col1_def")})
		// EOF after columns
		WritePacket(backendConn, BuildEOFPacket(6))
	}()

	// Client reads all forwarded packets
	go func() {
		for range 6 {
			ReadPacket(clientConn)
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(3 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(3 * time.Second))

	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	stmt := h.stmtStore.Get(99)
	if stmt == nil {
		t.Fatal("stmt 99 should be stored")
	}
	if stmt.NumParams != 2 {
		t.Errorf("params = %d, want 2", stmt.NumParams)
	}
	if stmt.NumCols != 1 {
		t.Errorf("cols = %d, want 1", stmt.NumCols)
	}
}
