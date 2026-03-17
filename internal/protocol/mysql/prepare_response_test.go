package mysql

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestHandlePrepareResponseOK(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()
	h.lastCmdByte = ComStmtPrepare

	// Backend: PREPARE OK response (stmt_id=42, 0 params, 0 cols)
	go func() {
		var resp []byte
		resp = append(resp, 0x00) // OK marker
		stmtID := make([]byte, 4)
		binary.LittleEndian.PutUint32(stmtID, 42)
		resp = append(resp, stmtID...)
		numCols := make([]byte, 2)
		binary.LittleEndian.PutUint16(numCols, 0)
		resp = append(resp, numCols...) // num_cols
		numParams := make([]byte, 2)
		binary.LittleEndian.PutUint16(numParams, 0)
		resp = append(resp, numParams...) // num_params
		resp = append(resp, 0)            // filler
		resp = append(resp, 0, 0)         // warnings
		WritePacket(backendConn, &Packet{SequenceID: 1, Payload: resp})
	}()

	// Client reads
	go func() { ReadPacket(clientConn) }()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))

	stats, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	_ = stats

	// Verify stmt was stored
	stmt := h.stmtStore.Get(42)
	if stmt == nil {
		t.Error("statement 42 should be stored")
	}

	// lastCmdByte should be reset
	if h.lastCmdByte != 0 {
		t.Error("lastCmdByte should be reset after prepare response")
	}
}

func TestHandlePrepareResponseError(t *testing.T) {
	backendConn, proxyBackend := net.Pipe()
	proxyClient, clientConn := net.Pipe()
	defer backendConn.Close()
	defer proxyBackend.Close()
	defer proxyClient.Close()
	defer clientConn.Close()

	h := New()
	h.lastCmdByte = ComStmtPrepare

	// Backend: ERR response
	go func() {
		WritePacket(backendConn, BuildErrPacket(1, 1064, "syntax error"))
	}()

	go func() { ReadPacket(clientConn) }()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))

	_, err := h.ReadAndForwardResult(context.Background(), proxyBackend, proxyClient, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// No stmt should be stored
	if h.stmtStore.Get(42) != nil {
		t.Error("no statement should be stored on error")
	}
}
