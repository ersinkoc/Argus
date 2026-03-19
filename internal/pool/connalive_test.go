package pool

import (
	"net"
	"testing"
	"time"
)

func TestIsConnAliveHealthy(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() { c, _ := ln.Accept(); if c != nil { time.Sleep(5 * time.Second); c.Close() } }()

	conn, _ := net.Dial("tcp", ln.Addr().String())
	defer conn.Close()

	if !isConnAlive(conn) {
		t.Error("fresh connection should be alive")
	}
}

func TestIsConnAliveClosed(t *testing.T) {
	// Use net.Pipe so the close is synchronous (no TCP FIN propagation delay on Windows).
	client, server := net.Pipe()
	server.Close() // immediate EOF on client's next Read

	// Small sleep to let the OS surface the close, then check.
	time.Sleep(50 * time.Millisecond)

	if isConnAlive(client) {
		client.Close()
		t.Error("closed connection should not be alive")
	}
	client.Close()
}

func TestIsConnAliveNil(t *testing.T) {
	if isConnAlive(nil) {
		t.Error("nil should not be alive")
	}
}
