package pool

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// SharedPool implements connection pooling where connections are shared
// between sessions (transaction-mode pooling). Unlike session-dedicated
// pooling, connections are returned to the pool after each transaction.
//
// This mode is more efficient but requires session state reset between uses.
type SharedPool struct {
	target         string
	maxConns       int
	maxLifetime    time.Duration
	connectTimeout time.Duration
	healthInterval time.Duration

	mu       sync.Mutex
	idle     []*Conn
	active   int
	total    int
	healthy  bool
	closed   bool
	stopCh   chan struct{}
	wg       sync.WaitGroup
	waiters  []chan *Conn
	connectFn func(ctx context.Context) (net.Conn, error)
}

// NewSharedPool creates a shared connection pool.
func NewSharedPool(target string, maxConns int, maxLifetime, connectTimeout, healthInterval time.Duration) *SharedPool {
	p := &SharedPool{
		target:         target,
		maxConns:       maxConns,
		maxLifetime:    maxLifetime,
		connectTimeout: connectTimeout,
		healthInterval: healthInterval,
		healthy:        true,
		stopCh:         make(chan struct{}),
	}
	p.connectFn = p.defaultConnect
	return p
}

// SetConnectFunc sets a custom connect function.
func (p *SharedPool) SetConnectFunc(fn func(ctx context.Context) (net.Conn, error)) {
	p.connectFn = fn
}

// Start begins health checking.
func (p *SharedPool) Start() {
	if p.healthInterval > 0 {
		p.wg.Add(1)
		go p.healthLoop()
	}
}

// Acquire gets a connection, waiting if necessary.
func (p *SharedPool) Acquire(ctx context.Context) (*Conn, error) {
	p.mu.Lock()

	if p.closed {
		p.mu.Unlock()
		return nil, fmt.Errorf("pool is closed")
	}

	// Try idle connections
	for len(p.idle) > 0 {
		conn := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]

		if conn.isExpired(p.maxLifetime) {
			conn.Close()
			p.total--
			continue
		}

		p.active++
		p.mu.Unlock()
		return conn, nil
	}

	// Create new if under limit
	if p.total < p.maxConns {
		p.total++
		p.active++
		p.mu.Unlock()

		conn, err := p.createConn(ctx)
		if err != nil {
			p.mu.Lock()
			p.total--
			p.active--
			p.mu.Unlock()
			return nil, err
		}
		return conn, nil
	}

	// Wait for a connection to become available
	waiter := make(chan *Conn, 1)
	p.waiters = append(p.waiters, waiter)
	p.mu.Unlock()

	select {
	case conn := <-waiter:
		return conn, nil
	case <-ctx.Done():
		// Remove waiter
		p.mu.Lock()
		for i, w := range p.waiters {
			if w == waiter {
				p.waiters = append(p.waiters[:i], p.waiters[i+1:]...)
				break
			}
		}
		p.mu.Unlock()
		return nil, ctx.Err()
	}
}

// Release returns a connection to the pool or gives it to a waiter.
func (p *SharedPool) Release(conn *Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.active--

	if p.closed || conn.isExpired(p.maxLifetime) {
		conn.Close()
		p.total--
		return
	}

	// Give to a waiter if any
	if len(p.waiters) > 0 {
		waiter := p.waiters[0]
		p.waiters = p.waiters[1:]
		p.active++
		waiter <- conn
		return
	}

	// Return to idle pool
	p.idle = append(p.idle, conn)
}

// Stats returns pool statistics.
func (p *SharedPool) Stats() PoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return PoolStats{
		Target:  p.target,
		Active:  p.active,
		Idle:    len(p.idle),
		Total:   p.total,
		Max:     p.maxConns,
		Healthy: p.healthy,
	}
}

// Close closes all connections.
func (p *SharedPool) Close() error {
	p.mu.Lock()
	p.closed = true
	idle := p.idle
	p.idle = nil
	// Cancel all waiters
	for _, w := range p.waiters {
		close(w)
	}
	p.waiters = nil
	p.mu.Unlock()

	close(p.stopCh)
	p.wg.Wait()

	for _, c := range idle {
		c.Close()
	}
	return nil
}

func (p *SharedPool) createConn(ctx context.Context) (*Conn, error) {
	if p.connectTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.connectTimeout)
		defer cancel()
	}
	netConn, err := p.connectFn(ctx)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", p.target, err)
	}
	return &Conn{conn: netConn, createdAt: time.Now()}, nil
}

func (p *SharedPool) defaultConnect(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", p.target)
}

func (p *SharedPool) healthLoop() {
	defer p.wg.Done()
	ticker := time.NewTicker(p.healthInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.checkHealth()
		case <-p.stopCh:
			return
		}
	}
}

func (p *SharedPool) checkHealth() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := p.connectFn(ctx)
	if err != nil {
		p.mu.Lock()
		if p.healthy {
			log.Printf("[argus] shared pool target %s is unhealthy: %v", p.target, err)
		}
		p.healthy = false
		p.mu.Unlock()
		return
	}
	conn.Close()
	p.mu.Lock()
	if !p.healthy {
		log.Printf("[argus] shared pool target %s is healthy again", p.target)
	}
	p.healthy = true
	p.mu.Unlock()
}
