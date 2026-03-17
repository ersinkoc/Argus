package policy

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// Loader watches and loads policy files.
type Loader struct {
	files        []string
	reloadInterval time.Duration
	current      *PolicySet
	mu           sync.RWMutex
	onReload     func()
	stopCh       chan struct{}
	wg           sync.WaitGroup
	lastModTimes map[string]time.Time
}

// NewLoader creates a new policy loader.
func NewLoader(files []string, reloadInterval time.Duration) *Loader {
	return &Loader{
		files:          files,
		reloadInterval: reloadInterval,
		stopCh:         make(chan struct{}),
		lastModTimes:   make(map[string]time.Time),
	}
}

// OnReload sets a callback for when policies are reloaded.
func (l *Loader) OnReload(fn func()) {
	l.onReload = fn
}

// Load reads and parses all policy files.
func (l *Loader) Load() error {
	merged := &PolicySet{
		Roles:    make(map[string]Role),
		Defaults: DefaultsConfig{Action: "audit", LogLevel: "standard", MaxRows: 100000},
	}

	for _, path := range l.files {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading policy file %q: %w", path, err)
		}

		var ps PolicySet
		if err := json.Unmarshal(data, &ps); err != nil {
			return fmt.Errorf("parsing policy file %q: %w", path, err)
		}

		// Merge
		if ps.Version != "" {
			merged.Version = ps.Version
		}
		if ps.Defaults.Action != "" {
			merged.Defaults = ps.Defaults
		}
		for k, v := range ps.Roles {
			merged.Roles[k] = v
		}
		merged.Policies = append(merged.Policies, ps.Policies...)

		// Track mod time
		if info, err := os.Stat(path); err == nil {
			l.lastModTimes[path] = info.ModTime()
		}
	}

	l.mu.Lock()
	l.current = merged
	l.mu.Unlock()

	return nil
}

// SetCurrent directly sets the policy set (for testing).
func (l *Loader) SetCurrent(ps *PolicySet) {
	l.mu.Lock()
	l.current = ps
	l.mu.Unlock()
}

// Current returns the current policy set.
func (l *Loader) Current() *PolicySet {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.current
}

// Start begins the file watcher.
func (l *Loader) Start() {
	if l.reloadInterval <= 0 {
		return
	}
	l.wg.Add(1)
	go l.watchLoop()
}

// Stop stops the file watcher.
func (l *Loader) Stop() {
	close(l.stopCh)
	l.wg.Wait()
}

func (l *Loader) watchLoop() {
	defer l.wg.Done()
	ticker := time.NewTicker(l.reloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if l.filesChanged() {
				log.Println("[argus] policy files changed, reloading...")
				if err := l.Load(); err != nil {
					log.Printf("[argus] policy reload failed: %v (keeping current policies)", err)
				} else {
					log.Println("[argus] policies reloaded successfully")
					if l.onReload != nil {
						l.onReload()
					}
				}
			}
		case <-l.stopCh:
			return
		}
	}
}

func (l *Loader) filesChanged() bool {
	for _, path := range l.files {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if lastMod, ok := l.lastModTimes[path]; ok {
			if info.ModTime().After(lastMod) {
				return true
			}
		}
	}
	return false
}
