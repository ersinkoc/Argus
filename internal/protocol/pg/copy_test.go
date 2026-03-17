package pg

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestHandleCopyIn(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	// Client sends CopyData + CopyDone
	go func() {
		WriteMessage(clientConn, &Message{Type: MsgCopyData, Payload: []byte("row1\n")})
		WriteMessage(clientConn, &Message{Type: MsgCopyData, Payload: []byte("row2\n")})
		WriteMessage(clientConn, &Message{Type: MsgCopyDone, Payload: nil})
	}()

	// Backend reads forwarded data
	go func() {
		for i := 0; i < 3; i++ {
			ReadMessage(backendConn)
		}
	}()

	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))
	err := HandleCopyIn(context.Background(), proxyClient, proxyBackend)
	if err != nil {
		t.Fatalf("HandleCopyIn: %v", err)
	}
}

func TestHandleCopyInFail(t *testing.T) {
	clientConn, proxyClient := net.Pipe()
	proxyBackend, backendConn := net.Pipe()
	defer clientConn.Close()
	defer proxyClient.Close()
	defer proxyBackend.Close()
	defer backendConn.Close()

	go func() {
		WriteMessage(clientConn, &Message{Type: MsgCopyFail, Payload: []byte("abort")})
	}()

	go func() {
		ReadMessage(backendConn)
	}()

	proxyClient.SetDeadline(time.Now().Add(2 * time.Second))
	err := HandleCopyIn(context.Background(), proxyClient, proxyBackend)
	if err != nil {
		t.Fatalf("HandleCopyIn with fail: %v", err)
	}
}

func TestHandleCopyOut(t *testing.T) {
	proxyBackend, backendConn := net.Pipe()
	clientConn, proxyClient := net.Pipe()
	defer proxyBackend.Close()
	defer backendConn.Close()
	defer clientConn.Close()
	defer proxyClient.Close()

	// Backend sends CopyData + CopyDone
	go func() {
		WriteMessage(backendConn, &Message{Type: MsgCopyData, Payload: []byte("data1\n")})
		WriteMessage(backendConn, &Message{Type: MsgCopyDone, Payload: nil})
	}()

	// Client reads forwarded data
	go func() {
		for i := 0; i < 2; i++ {
			ReadMessage(clientConn)
		}
	}()

	proxyBackend.SetDeadline(time.Now().Add(2 * time.Second))
	err := HandleCopyOut(context.Background(), proxyBackend, proxyClient)
	if err != nil {
		t.Fatalf("HandleCopyOut: %v", err)
	}
}

func TestIsCopyMessage(t *testing.T) {
	if !IsCopyMessage(MsgCopyInResponse) {
		t.Error("CopyInResponse should be copy message")
	}
	if !IsCopyMessage(MsgCopyData) {
		t.Error("CopyData should be copy message")
	}
	if IsCopyMessage(MsgQuery) {
		t.Error("Query should not be copy message")
	}
}
