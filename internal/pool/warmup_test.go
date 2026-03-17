package pool

import (
	"net"
	"testing"
	"time"
)

func TestPoolWarmupSuccess(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() { for { c, _ := ln.Accept(); if c != nil { _ = c } } }()

	p := NewPool(ln.Addr().String(), 10, 3, time.Hour, 5*time.Second, 0)
	p.warmup()

	stats := p.Stats()
	if stats.Idle != 3 {
		t.Errorf("idle = %d, want 3 (warmup)", stats.Idle)
	}
	if stats.Total != 3 {
		t.Errorf("total = %d, want 3", stats.Total)
	}
	p.Close()
}

func TestPoolWarmupZero(t *testing.T) {
	p := NewPool("127.0.0.1:1", 5, 0, time.Hour, time.Second, 0)
	// warmup with minIdle=0 should be skipped in Start
	p.Start()
	time.Sleep(50 * time.Millisecond)
	stats := p.Stats()
	if stats.Idle != 0 {
		t.Errorf("idle = %d, want 0 (no warmup)", stats.Idle)
	}
	p.Close()
}
