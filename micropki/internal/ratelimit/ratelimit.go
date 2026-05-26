package ratelimit

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"MicroPKI/internal/logger"
)

type TokenBucket struct {
	rate       float64
	burst      int
	tokens     float64
	lastUpdate time.Time
	mu         sync.Mutex
}

func NewTokenBucket(rate float64, burst int) *TokenBucket {
	return &TokenBucket{
		rate:       rate,
		burst:      burst,
		tokens:     float64(burst),
		lastUpdate: time.Now(),
	}
}

func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastUpdate).Seconds()
	
	tb.tokens += elapsed * tb.rate
	if tb.tokens > float64(tb.burst) {
		tb.tokens = float64(tb.burst)
	}
	
	tb.lastUpdate = now

	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		return true
	}

	return false
}

type RateLimiter struct {
	mu       sync.Mutex
	clients  map[string]*TokenBucket
	rate     float64
	burst    int
	enabled  bool
	stopCh   chan struct{}
	closed   bool
}

func NewRateLimiter(rate float64, burst int) *RateLimiter {
	enabled := rate > 0

	limiter := &RateLimiter{
		clients: make(map[string]*TokenBucket),
		rate:    rate,
		burst:   burst,
		enabled: enabled,
		stopCh:  make(chan struct{}),
	}

	if enabled {
		go limiter.cleanupLoop()
	}

	return limiter
}

func (rl *RateLimiter) Allow(clientIP string) bool {
	if !rl.enabled {
		return true
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.closed {
		return true
	}

	bucket, exists := rl.clients[clientIP]
	if !exists {
		bucket = NewTokenBucket(rl.rate, rl.burst)
		rl.clients[clientIP] = bucket
	}

	allowed := bucket.Allow()
	
	if !allowed {
		logger.Warn("[RateLimit] превышен лимит для клиента %s (rate=%.1f/s, burst=%d)", 
			clientIP, rl.rate, rl.burst)
	}

	return allowed
}

func (rl *RateLimiter) GetRetryAfter() int {
	if rl.rate <= 0 {
		return 1
	}
	return int(1.0 / rl.rate)
}

func (rl *RateLimiter) IsEnabled() bool {
	return rl.enabled
}

func (rl *RateLimiter) GetRate() float64 {
	return rl.rate
}

func (rl *RateLimiter) GetBurst() int {
	return rl.burst
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			rl.Cleanup()
		case <-rl.stopCh:
			return
		}
	}
}

// Cleanup удаляет неактивных клиентов
func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	for ip, bucket := range rl.clients {
		bucket.mu.Lock()
		if bucket.tokens >= float64(bucket.burst) {
			delete(rl.clients, ip)
		}
		bucket.mu.Unlock()
	}
}

// Close останавливает cleanupLoop
func (rl *RateLimiter) Close() {
	rl.mu.Lock()
	if rl.closed {
		rl.mu.Unlock()
		return
	}
	rl.closed = true
	rl.mu.Unlock()
	
	close(rl.stopCh)
}

func RateLimitMiddleware(limiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.IsEnabled() {
				next.ServeHTTP(w, r)
				return
			}

			clientIP := getClientIP(r)
			
			if !limiter.Allow(clientIP) {
				retryAfter := limiter.GetRetryAfter()
				w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				
				response := map[string]interface{}{
					"error":       "rate_limit_exceeded",
					"message":     fmt.Sprintf("Превышен лимит запросов. Попробуйте через %d секунд", retryAfter),
					"retry_after": retryAfter,
				}
				
				json.NewEncoder(w).Encode(response)
				
				logger.Warn("[RateLimit] 429 Too Many Requests для %s", clientIP)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	
	return host
}