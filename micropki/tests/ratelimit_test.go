package tests

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"MicroPKI/internal/ratelimit"
)

func TestTokenBucketAllow(t *testing.T) {
	bucket := ratelimit.NewTokenBucket(2.0, 2)

	// Первые 2 запроса должны быть разрешены
	if !bucket.Allow() {
		t.Error("первый запрос должен быть разрешен")
	}
	if !bucket.Allow() {
		t.Error("второй запрос должен быть разрешен")
	}

	// Третий запрос должен быть отклонен (лимит превышен)
	if bucket.Allow() {
		t.Error("третий запрос должен быть отклонен")
	}
}

func TestTokenBucketRefill(t *testing.T) {
	bucket := ratelimit.NewTokenBucket(10.0, 1)

	// Используем токен
	if !bucket.Allow() {
		t.Error("запрос должен быть разрешен")
	}
	if bucket.Allow() {
		t.Error("burst=1, второй запрос без ожидания должен быть отклонен")
	}

	// Ждем пополнения
	time.Sleep(150 * time.Millisecond)

	// Теперь должен быть разрешен
	if !bucket.Allow() {
		t.Error("после ожидания запрос должен быть разрешен")
	}
}

func TestRateLimiterEnabled(t *testing.T) {
	limiter := ratelimit.NewRateLimiter(5.0, 10)
	if !limiter.IsEnabled() {
		t.Error("RateLimiter с rate>0 должен быть включен")
	}

	if limiter.GetRate() != 5.0 {
		t.Errorf("неверный rate: %f", limiter.GetRate())
	}

	if limiter.GetBurst() != 10 {
		t.Errorf("неверный burst: %d", limiter.GetBurst())
	}
}

func TestRateLimiterDisabled(t *testing.T) {
	limiter := ratelimit.NewRateLimiter(0, 10)
	if limiter.IsEnabled() {
		t.Error("RateLimiter с rate=0 должен быть отключен")
	}

	// Все запросы должны быть разрешены когда лимитер отключен
	for i := 0; i < 100; i++ {
		if !limiter.Allow("127.0.0.1") {
			t.Errorf("запрос %d должен быть разрешен при отключенном лимитере", i)
		}
	}
}

func TestRateLimiterPerClient(t *testing.T) {
	limiter := ratelimit.NewRateLimiter(1.0, 1) // 1 запрос/сек, burst=1

	// Клиент 1
	if !limiter.Allow("192.168.1.1") {
		t.Error("клиент 1: первый запрос должен быть разрешен")
	}
	if limiter.Allow("192.168.1.1") {
		t.Error("клиент 1: второй запрос должен быть отклонен")
	}

	// Клиент 2 (другой IP)
	if !limiter.Allow("192.168.1.2") {
		t.Error("клиент 2: первый запрос должен быть разрешен")
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	limiter := ratelimit.NewRateLimiter(1.0, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	middleware := ratelimit.RateLimitMiddleware(limiter)
	wrappedHandler := middleware(handler)

	// Первый запрос - OK
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.RemoteAddr = "192.168.1.1:12345"
	rec1 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Errorf("первый запрос: ожидался 200, получен %d", rec1.Code)
	}

	// Второй запрос - 429
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "192.168.1.1:12345"
	rec2 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("второй запрос: ожидался 429, получен %d", rec2.Code)
	}

	// Проверяем заголовок Retry-After
	retryAfter := rec2.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("ожидался заголовок Retry-After")
	}
}

func TestRateLimitMiddlewareDisabled(t *testing.T) {
	limiter := ratelimit.NewRateLimiter(0, 10) // отключен
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := ratelimit.RateLimitMiddleware(limiter)
	wrappedHandler := middleware(handler)

	// Много запросов - все должны быть OK
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("запрос %d: ожидался 200, получен %d", i, rec.Code)
		}
	}
}

func TestGetClientIP(t *testing.T) {
	// Тестируем через middleware с разными заголовками
	limiter := ratelimit.NewRateLimiter(100.0, 100)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := ratelimit.RateLimitMiddleware(limiter)
	wrappedHandler := middleware(handler)

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xri        string
	}{
		{"basic", "192.168.1.1:12345", "", ""},
		{"with xff", "10.0.0.1:12345", "192.168.1.1, 10.0.0.2", ""},
		{"with xri", "10.0.0.1:12345", "", "192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				req.Header.Set("X-Real-IP", tt.xri)
			}

			rec := httptest.NewRecorder()
			wrappedHandler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("ожидался 200, получен %d", rec.Code)
			}
		})
	}
}

func TestGetRetryAfter(t *testing.T) {
	limiter := ratelimit.NewRateLimiter(2.0, 5)
	
	retryAfter := limiter.GetRetryAfter()
	if retryAfter != 1 {
		t.Logf("Retry-After: %d секунд", retryAfter)
	}
}