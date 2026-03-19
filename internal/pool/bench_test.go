package pool

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// pipePool creates a Pool wired to net.Pipe() connections (no real TCP socket needed).
func pipePool(maxConns int) *Pool {
	p := NewPool("pipe://test", maxConns, 0, time.Hour, time.Second, 0)
	p.SetConnectFunc(func(ctx context.Context) (net.Conn, error) {
		c1, c2 := net.Pipe()
		// Keep c2 alive by draining it in background; release when c1 closes.
		go func() {
			buf := make([]byte, 1024)
			for {
				_, err := c2.Read(buf)
				if err != nil {
					return
				}
			}
		}()
		return c1, nil
	})
	return p
}

// BenchmarkPoolAcquireRelease measures the Acquire+Release hot path on a pre-warmed pool.
func BenchmarkPoolAcquireRelease(b *testing.B) {
	const maxConns = 1000
	p := pipePool(maxConns)

	// Pre-warm: fill the idle list so Acquire never dials
	const prewarm = 32
	conns := make([]*Conn, prewarm)
	for i := range conns {
		c, err := p.Acquire(context.Background())
		if err != nil {
			b.Fatalf("warmup acquire: %v", err)
		}
		conns[i] = c
	}
	for _, c := range conns {
		p.Release(c)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		c, err := p.Acquire(context.Background())
		if err != nil {
			b.Fatalf("acquire: %v", err)
		}
		p.Release(c)
	}
}

// BenchmarkPoolAcquireRelease_Parallel measures concurrent Acquire+Release throughput.
func BenchmarkPoolAcquireRelease_Parallel(b *testing.B) {
	const maxConns = 64
	p := pipePool(maxConns)

	// Pre-warm
	conns := make([]*Conn, maxConns)
	for i := range conns {
		c, err := p.Acquire(context.Background())
		if err != nil {
			b.Fatalf("warmup acquire: %v", err)
		}
		conns[i] = c
	}
	for _, c := range conns {
		p.Release(c)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c, err := p.Acquire(context.Background())
			if err != nil {
				continue // pool limit reached under high concurrency, skip
			}
			p.Release(c)
		}
	})
}

// BenchmarkSharedPoolAcquireRelease measures SharedPool Acquire+Release.
func BenchmarkSharedPoolAcquireRelease(b *testing.B) {
	p := NewSharedPool("pipe://shared", 1000, time.Hour, time.Second, 0)
	p.SetConnectFunc(func(ctx context.Context) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() {
			buf := make([]byte, 1024)
			for {
				if _, err := c2.Read(buf); err != nil {
					return
				}
			}
		}()
		return c1, nil
	})

	// Pre-warm
	const prewarm = 32
	conns := make([]*Conn, prewarm)
	for i := range conns {
		c, err := p.Acquire(context.Background())
		if err != nil {
			b.Fatalf("warmup: %v", err)
		}
		conns[i] = c
	}
	for _, c := range conns {
		p.Release(c)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		c, err := p.Acquire(context.Background())
		if err != nil {
			b.Fatalf("acquire: %v", err)
		}
		p.Release(c)
	}
}

// BenchmarkSharedPoolConcurrent measures SharedPool under concurrent load with waiters.
func BenchmarkSharedPoolConcurrent(b *testing.B) {
	const maxConns = 8 // intentionally low to force waiter queue
	p := NewSharedPool("pipe://shared-concurrent", maxConns, time.Hour, time.Second, 0)
	p.SetConnectFunc(func(ctx context.Context) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() {
			buf := make([]byte, 1024)
			for {
				if _, err := c2.Read(buf); err != nil {
					return
				}
			}
		}()
		return c1, nil
	})

	b.ResetTimer()
	b.ReportAllocs()

	const goroutines = 32
	var wg sync.WaitGroup
	work := make(chan struct{}, b.N)
	for i := 0; i < b.N; i++ {
		work <- struct{}{}
	}
	close(work)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range work {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				c, err := p.Acquire(ctx)
				cancel()
				if err != nil {
					continue
				}
				p.Release(c)
			}
		}()
	}
	wg.Wait()
}

// BenchmarkCircuitBreaker measures the Allow+RecordSuccess hot path.
func BenchmarkCircuitBreaker(b *testing.B) {
	cb := NewCircuitBreaker(5, 30*time.Second)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if cb.Allow() {
			cb.RecordSuccess()
		}
	}
}

// BenchmarkPoolStats measures the Stats() call overhead (read-only with lock).
func BenchmarkPoolStats(b *testing.B) {
	p := pipePool(100)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = p.Stats()
	}
}

// BenchmarkPoolStats_Parallel measures Stats() under concurrent read.
func BenchmarkPoolStats_Parallel(b *testing.B) {
	p := pipePool(100)
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = p.Stats()
		}
	})
}
