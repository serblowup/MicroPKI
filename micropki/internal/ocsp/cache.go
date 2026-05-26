package ocsp

import (
	"sync"
	"time"
)

type CacheEntry struct {
	Response   *OCSPResponse
	Expiration time.Time
}

type ResponseCache struct {
	mu       sync.RWMutex
	entries  map[string]*CacheEntry
	ttl      time.Duration
	stopCh   chan struct{}
	closed   bool
}

func NewResponseCache(ttl time.Duration) *ResponseCache {
	cache := &ResponseCache{
		entries: make(map[string]*CacheEntry),
		ttl:     ttl,
		stopCh:  make(chan struct{}),
	}
	go cache.cleanupLoop()
	return cache
}

func (c *ResponseCache) Get(key string) (*OCSPResponse, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, false
	}

	entry, exists := c.entries[key]
	if !exists {
		return nil, false
	}

	if time.Now().After(entry.Expiration) {
		delete(c.entries, key)
		return nil, false
	}

	return entry.Response, true
}

func (c *ResponseCache) Set(key string, resp *OCSPResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}

	c.entries[key] = &CacheEntry{
		Response:   resp,
		Expiration: time.Now().Add(c.ttl),
	}
}

func (c *ResponseCache) cleanupLoop() {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			now := time.Now()
			for key, entry := range c.entries {
				if now.After(entry.Expiration) {
					delete(c.entries, key)
				}
			}
			c.mu.Unlock()
		case <-c.stopCh:
			return
		}
	}
}

// Close останавливает cleanupLoop и закрывает кэш
func (c *ResponseCache) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()
	
	close(c.stopCh)
}