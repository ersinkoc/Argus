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
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() { c, _ := ln.Accept(); if c != nil { c.Close() } }()

	conn, _ := net.Dial("tcp", ln.Addr().String())
	time.Sleep(50 * time.Millisecond) // let server close

	if isConnAlive(conn) {
		t.Error("closed connection should not be alive")
	}
}

func TestIsConnAliveNil(t *testing.T) {
	if isConnAlive(nil) {
		t.Error("nil should not be alive")
	}
}
