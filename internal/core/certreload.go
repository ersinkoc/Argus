package core

import (
	"crypto/tls"
	"log"
	"sync"
	"time"
)

// CertReloader watches TLS certificate files and reloads them periodically.
// This enables certificate rotation without process restart.
type CertReloader struct {
	certFile string
	keyFile  string
	mu       sync.RWMutex
	cert     *tls.Certificate
	stopCh   chan struct{}
	wg       sync.WaitGroup
	interval time.Duration
}

// NewCertReloader creates a certificate reloader.
func NewCertReloader(certFile, keyFile string, interval time.Duration) (*CertReloader, error) {
	if interval <= 0 {
		interval = 1 * time.Hour
	}

	r := &CertReloader{
		certFile: certFile,
		keyFile:  keyFile,
		interval: interval,
		stopCh:   make(chan struct{}),
	}

	// Initial load
	if err := r.reload(); err != nil {
		return nil, err
	}

	return r, nil
}

// GetCertificate returns the current certificate. Suitable for tls.Config.GetCertificate.
func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

// TLSConfig returns a tls.Config that uses the reloader for certificates.
func (r *CertReloader) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: r.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
}

// Start begins periodic certificate checking.
func (r *CertReloader) Start() {
	r.wg.Add(1)
	go r.watchLoop()
}

// Stop stops the reloader.
func (r *CertReloader) Stop() {
	close(r.stopCh)
	r.wg.Wait()
}

func (r *CertReloader) reload() error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.cert = &cert
	r.mu.Unlock()
	return nil
}

func (r *CertReloader) watchLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := r.reload(); err != nil {
				log.Printf("[argus] certificate reload failed: %v", err)
			} else {
				log.Println("[argus] TLS certificates reloaded")
			}
		case <-r.stopCh:
			return
		}
	}
}
