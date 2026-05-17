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

// TokenBucket реализует алгоритм token bucket для ограничения частоты запросов
type TokenBucket struct {
	rate       float64 // токенов в секунду
	burst      int     // максимальный размер ведра
	tokens     float64 // текущее количество токенов
	lastUpdate time.Time
	mu         sync.Mutex
}

// NewTokenBucket создает новый token bucket
func NewTokenBucket(rate float64, burst int) *TokenBucket {
	return &TokenBucket{
		rate:       rate,
		burst:      burst,
		tokens:     float64(burst),
		lastUpdate: time.Now(),
	}
}

// Allow проверяет, разрешен ли запрос
func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastUpdate).Seconds()
	
	// Добавляем токены за прошедшее время
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

// RateLimiter управляет ограничением частоты для множества клиентов
type RateLimiter struct {
	mu       sync.Mutex
	clients  map[string]*TokenBucket
	rate     float64 // запросов в секунду
	burst    int
	enabled  bool
}

// NewRateLimiter создает новый ограничитель частоты
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	enabled := rate > 0

	limiter := &RateLimiter{
		clients: make(map[string]*TokenBucket),
		rate:    rate,
		burst:   burst,
		enabled: enabled,
	}

	// Запускаем очистку старых клиентов
	if enabled {
		go limiter.cleanupLoop()
	}

	return limiter
}

// Allow проверяет, разрешен ли запрос для данного клиента
func (rl *RateLimiter) Allow(clientIP string) bool {
	if !rl.enabled {
		return true
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

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

// GetRetryAfter возвращает время в секундах до следующего разрешенного запроса
func (rl *RateLimiter) GetRetryAfter() int {
	return int(1.0 / rl.rate)
}

// IsEnabled возвращает true, если ограничение включено
func (rl *RateLimiter) IsEnabled() bool {
	return rl.enabled
}

// GetRate возвращает текущую частоту
func (rl *RateLimiter) GetRate() float64 {
	return rl.rate
}

// GetBurst возвращает текущий burst
func (rl *RateLimiter) GetBurst() int {
	return rl.burst
}

// cleanupLoop периодически очищает старых клиентов
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.cleanup()
	}
}

// cleanup удаляет клиентов, которые не активны более 10 минут
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Простая очистка: удаляем всех клиентов, у которых полное ведро
	// (они не делали запросов долгое время)
	for ip, bucket := range rl.clients {
		bucket.mu.Lock()
		if bucket.tokens >= float64(bucket.burst) {
			delete(rl.clients, ip)
		}
		bucket.mu.Unlock()
	}
}

// RateLimitMiddleware создает middleware для ограничения частоты запросов
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

// getClientIP извлекает IP клиента из запроса
func getClientIP(r *http.Request) string {
	// Проверяем X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := splitComma(xff)
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	
	// Проверяем X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// Используем RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	
	return host
}

func splitComma(s string) []string {
	var result []string
	for _, part := range splitString(s, ',') {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func splitString(s string, sep byte) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}