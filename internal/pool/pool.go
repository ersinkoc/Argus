package pool

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Pool manages backend connections for a single target.
type Pool struct {
	target          string // host:port
	maxConns        int
	minIdle         int
	maxLifetime     time.Duration
	connectTimeout  time.Duration
	healthInterval  time.Duration

	mu          sync.Mutex
	idle        []*Conn
	active      int
	total       int
	healthy     bool
	closed      bool
	stopCh      chan struct{}
	wg          sync.WaitGroup
	connectFn   func(ctx context.Context) (net.Conn, error)
	breaker     *CircuitBreaker
}

// NewPool creates a new connection pool for a target.
func NewPool(target string, maxConns, minIdle int, maxLifetime, connectTimeout, healthInterval time.Duration) *Pool {
	p := &Pool{
		target:         target,
		maxConns:       maxConns,
		minIdle:        minIdle,
		maxLifetime:    maxLifetime,
		connectTimeout: connectTimeout,
		healthInterval: healthInterval,
		healthy:        true,
		stopCh:         make(chan struct{}),
	}
	p.connectFn = p.defaultConnect
	p.breaker = NewCircuitBreaker(5, 30*time.Second)
	return p
}

// SetConnectFunc sets a custom connect function (useful for TLS).
func (p *Pool) SetConnectFunc(fn func(ctx context.Context) (net.Conn, error)) {
	p.connectFn = fn
}

// SetCircuitBreaker replaces the circuit breaker with custom thresholds.
// Must be called before Start().
func (p *Pool) SetCircuitBreaker(threshold int, resetTimeout time.Duration) {
	p.breaker = NewCircuitBreaker(threshold, resetTimeout)
}

// Start begins background health checking and warms up idle connections.
func (p *Pool) Start() {
	p.wg.Add(1)
	go p.healthCheckLoop()

	// Warmup: pre-create minimum idle connections
	if p.minIdle > 0 {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.warmup()
		}()
	}
}

func (p *Pool) warmup() {
	for i := 0; i < p.minIdle; i++ {
		conn, err := p.createConn(context.Background())
		if err != nil {
			log.Printf("[argus] pool warmup failed for %s: %v", p.target, err)
			return
		}
		p.mu.Lock()
		p.idle = append(p.idle, conn)
		p.total++
		p.mu.Unlock()
	}
	if p.minIdle > 0 {
		log.Printf("[argus] pool warmup: %d idle connections for %s", p.minIdle, p.target)
	}
}

// Acquire gets a connection from the pool or creates a new one.
func (p *Pool) Acquire(ctx context.Context) (*Conn, error) {
	acquireStart := time.Now()
	defer func() {
		WaitHistogram.Observe(float64(time.Since(acquireStart).Microseconds()))
	}()

	p.mu.Lock()

	if p.closed {
		p.mu.Unlock()
		return nil, fmt.Errorf("pool is closed")
	}

	if !p.healthy {
		p.mu.Unlock()
		return nil, fmt.Errorf("target %s is unhealthy", p.target)
	}

	// Circuit breaker check
	if p.breaker != nil && !p.breaker.Allow() {
		p.mu.Unlock()
		return nil, fmt.Errorf("target %s circuit breaker open", p.target)
	}

	// Try to reuse an idle connection
	for len(p.idle) > 0 {
		conn := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]

		if conn.isExpired(p.maxLifetime) {
			conn.Close()
			p.total--
			continue
		}

		// Verify connection is still alive (TCP probe)
		if !isConnAlive(conn.conn) {
			conn.Close()
			p.total--
			log.Printf("[argus] pool: discarded stale idle connection to %s", p.target)
			continue
		}

		p.active++
		p.mu.Unlock()
		return conn, nil
	}

	// Check if we can create a new connection
	if p.total >= p.maxConns {
		p.mu.Unlock()
		return nil, fmt.Errorf("connection limit reached for target %s (%d/%d)", p.target, p.total, p.maxConns)
	}

	p.total++
	p.active++
	p.mu.Unlock()

	// Create new connection outside the lock
	conn, err := p.createConn(ctx)
	if err != nil {
		p.mu.Lock()
		p.total--
		p.active--
		p.mu.Unlock()
		if p.breaker != nil {
			p.breaker.RecordFailure()
		}
		return nil, err
	}

	if p.breaker != nil {
		p.breaker.RecordSuccess()
	}
	return conn, nil
}

// Release returns a connection to the pool.
func (p *Pool) Release(conn *Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.active--

	if p.closed || conn.isExpired(p.maxLifetime) {
		conn.Close()
		p.total--
		return
	}

	p.idle = append(p.idle, conn)
}

// Remove closes and removes a connection without returning it to the pool.
func (p *Pool) Remove(conn *Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.active--
	p.total--
	conn.Close()
}

// Stats returns pool statistics.
func (p *Pool) Stats() PoolStats {
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

// PoolStats holds pool metrics.
type PoolStats struct {
	Target  string
	Active  int
	Idle    int
	Total   int
	Max     int
	Healthy bool
}

// IsHealthy returns the health status of the target.
func (p *Pool) IsHealthy() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.healthy
}

// Close closes all connections and stops the pool.
func (p *Pool) Close() error {
	p.mu.Lock()
	p.closed = true
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()

	close(p.stopCh)
	p.wg.Wait()

	for _, conn := range idle {
		conn.Close()
	}

	return nil
}

func (p *Pool) createConn(ctx context.Context) (*Conn, error) {
	if p.connectTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.connectTimeout)
		defer cancel()
	}

	netConn, err := p.connectFn(ctx)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", p.target, err)
	}

	return &Conn{
		conn:      netConn,
		createdAt: time.Now(),
	}, nil
}

func (p *Pool) defaultConnect(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", p.target)
}

func (p *Pool) healthCheckLoop() {
	defer p.wg.Done()

	if p.healthInterval <= 0 {
		return
	}

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

func (p *Pool) checkHealth() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := p.connectFn(ctx)
	if err != nil {
		p.mu.Lock()
		if p.healthy {
			log.Printf("[argus] target %s is now unhealthy: %v", p.target, err)
		}
		p.healthy = false
		p.mu.Unlock()
		return
	}

	// For server-speaks-first protocols (MySQL, MSSQL), drain the greeting
	// before closing to avoid "aborted connection" warnings on the server.
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1024)
	conn.Read(buf) // best-effort: read greeting if any
	conn.Close()

	p.mu.Lock()
	if !p.healthy {
		log.Printf("[argus] target %s is now healthy", p.target)
	}
	p.healthy = true
	p.mu.Unlock()
}
