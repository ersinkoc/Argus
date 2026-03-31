package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/ersinkoc/argus/internal/config"
)

// maxConcurrentConns limits simultaneous connections per listener to prevent DoS.
const maxConcurrentConns = 10000

// Listener manages TCP listeners for incoming connections.
type Listener struct {
	cfg       config.ListenerConfig
	listener  net.Listener
	handler   func(net.Conn)
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
	connSem   chan struct{} // connection semaphore
}

// NewListener creates a new TCP listener.
func NewListener(cfg config.ListenerConfig) *Listener {
	ctx, cancel := context.WithCancel(context.Background())
	return &Listener{
		cfg:     cfg,
		ctx:     ctx,
		cancel:  cancel,
		connSem: make(chan struct{}, maxConcurrentConns),
	}
}

// OnConnection sets the handler for new connections.
func (l *Listener) OnConnection(handler func(net.Conn)) {
	l.handler = handler
}

// Start begins listening for connections.
func (l *Listener) Start() error {
	var err error

	if l.cfg.TLS.Enabled {
		tlsCfg, tlsErr := MakeServerTLSConfig(l.cfg.TLS)
		if tlsErr != nil {
			return fmt.Errorf("TLS config: %w", tlsErr)
		}
		l.listener, err = tls.Listen("tcp", l.cfg.Address, tlsCfg)
	} else {
		l.listener, err = net.Listen("tcp", l.cfg.Address)
	}
	if err != nil {
		return fmt.Errorf("listen on %s: %w", l.cfg.Address, err)
	}

	tlsStr := ""
	if l.cfg.TLS.Enabled {
		tlsStr = " [TLS]"
	}
	log.Printf("[argus] listening on %s (protocol: %s)%s", l.cfg.Address, l.cfg.Protocol, tlsStr)

	l.wg.Add(1)
	go l.acceptLoop()

	return nil
}

// Stop stops the listener and waits for all connections to close.
func (l *Listener) Stop() {
	l.cancel()
	if l.listener != nil {
		l.listener.Close()
	}
	l.wg.Wait()
}

func (l *Listener) acceptLoop() {
	defer l.wg.Done()

	for {
		conn, err := l.listener.Accept()
		if err != nil {
			select {
			case <-l.ctx.Done():
				return
			default:
				log.Printf("[argus] accept error: %v", err)
				continue
			}
		}

		// Enforce connection limit
		select {
		case l.connSem <- struct{}{}:
		default:
			log.Printf("[argus] connection limit reached (%d), rejecting %v", maxConcurrentConns, conn.RemoteAddr())
			conn.Close()
			continue
		}

		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			defer func() { <-l.connSem }()
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[argus] panic in connection handler: %v", r)
				}
			}()
			if l.handler != nil {
				l.handler(conn)
			} else {
				conn.Close()
			}
		}()
	}
}
