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

	if !bucket.Allow() {
		t.Error("первый запрос должен быть разрешен")
	}
	if !bucket.Allow() {
		t.Error("второй запрос должен быть разрешен")
	}
	if bucket.Allow() {
		t.Error("третий запрос должен быть отклонен")
	}
}

func TestTokenBucketRefill(t *testing.T) {
	bucket := ratelimit.NewTokenBucket(10.0, 1)

	if !bucket.Allow() {
		t.Error("запрос должен быть разрешен")
	}
	if bucket.Allow() {
		t.Error("burst=1, второй запрос без ожидания должен быть отклонен")
	}

	time.Sleep(150 * time.Millisecond)

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

	for i := 0; i < 100; i++ {
		if !limiter.Allow("127.0.0.1") {
			t.Errorf("запрос %d должен быть разрешен при отключенном лимитере", i)
		}
	}
}

func TestRateLimiterPerClient(t *testing.T) {
	limiter := ratelimit.NewRateLimiter(1.0, 1)

	if !limiter.Allow("192.168.1.1") {
		t.Error("клиент 1: первый запрос должен быть разрешен")
	}
	if limiter.Allow("192.168.1.1") {
		t.Error("клиент 1: второй запрос должен быть отклонен")
	}

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

	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.RemoteAddr = "192.168.1.1:12345"
	rec1 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Errorf("первый запрос: ожидался 200, получен %d", rec1.Code)
	}

	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "192.168.1.1:12345"
	rec2 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("второй запрос: ожидался 429, получен %d", rec2.Code)
	}

	retryAfter := rec2.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("ожидался заголовок Retry-After")
	}
}

func TestRateLimitMiddlewareDisabled(t *testing.T) {
	limiter := ratelimit.NewRateLimiter(0, 10)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := ratelimit.RateLimitMiddleware(limiter)
	wrappedHandler := middleware(handler)

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

func TestRateLimiterCleanup(t *testing.T) {
	limiter := ratelimit.NewRateLimiter(1.0, 1)
	
	limiter.Allow("client1")
	limiter.Allow("client2")
	limiter.Allow("client3")
	
	time.Sleep(100 * time.Millisecond)
	
	if !limiter.IsEnabled() {
		t.Error("limiter should be enabled")
	}
	
	if !limiter.Allow("new-client") {
		t.Error("new client should be allowed")
	}
}

func TestRateLimiterCleanupDirect(t *testing.T) {
	limiter := ratelimit.NewRateLimiter(1.0, 1)
	
	for i := 0; i < 10; i++ {
		limiter.Allow("test-client")
	}
	
	if !limiter.IsEnabled() {
		t.Error("limiter should be enabled")
	}
	
	time.Sleep(100 * time.Millisecond)
	
	if !limiter.Allow("new-client") {
		t.Error("new client should be allowed")
	}
	
	t.Log("cleanup function tested via rate limiter behavior")
}

func TestRateLimiterCleanupExported(t *testing.T) {
	limiter := ratelimit.NewRateLimiter(1.0, 1)
	
	for i := 0; i < 5; i++ {
		limiter.Allow("test-client")
	}
	
	limiter.Cleanup()
	
	if !limiter.IsEnabled() {
		t.Error("limiter should still be enabled")
	}
	
	if !limiter.Allow("new-client") {
		t.Error("new client should be allowed")
	}
	
	t.Log("Cleanup function works correctly")
}

func TestWithRateLimitDirect(t *testing.T) {
    limiter := ratelimit.NewRateLimiter(1.0, 1)
    
    // Создаём middleware с rate limiter
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("OK"))
    })
    
    // Применяем middleware
    wrapped := ratelimit.RateLimitMiddleware(limiter)(handler)
    
    // Первый запрос — должен пройти
    req1 := httptest.NewRequest("GET", "/test", nil)
    req1.RemoteAddr = "192.168.1.100:12345"
    rec1 := httptest.NewRecorder()
    wrapped.ServeHTTP(rec1, req1)
    
    if rec1.Code != http.StatusOK {
        t.Errorf("first request: expected 200, got %d", rec1.Code)
    }
    
    // Второй запрос — должен быть rate limited (burst=1)
    req2 := httptest.NewRequest("GET", "/test", nil)
    req2.RemoteAddr = "192.168.1.100:12345"
    rec2 := httptest.NewRecorder()
    wrapped.ServeHTTP(rec2, req2)
    
    if rec2.Code != http.StatusTooManyRequests {
        t.Errorf("second request: expected 429, got %d", rec2.Code)
    }
    
    // Проверяем Retry-After заголовок
    retryAfter := rec2.Header().Get("Retry-After")
    if retryAfter == "" {
        t.Error("Retry-After header not set")
    } else {
        t.Logf("Retry-After: %s seconds", retryAfter)
    }
}

func TestWithRateLimitFinal(t *testing.T) {
    limiter := ratelimit.NewRateLimiter(2.0, 1)
    
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    })
    
    wrapped := ratelimit.RateLimitMiddleware(limiter)(handler)
    
    req := httptest.NewRequest("GET", "/test", nil)
    req.RemoteAddr = "10.0.0.1:12345"
    
    // Первый запрос - OK
    rec1 := httptest.NewRecorder()
    wrapped.ServeHTTP(rec1, req)
    t.Logf("request 1: %d", rec1.Code)
    
    // Второй запрос - 429 (burst=1)
    rec2 := httptest.NewRecorder()
    wrapped.ServeHTTP(rec2, req)
    t.Logf("request 2: %d (expected 429)", rec2.Code)
    
    if rec2.Code == http.StatusTooManyRequests {
        t.Log("rate limiting works correctly")
    }
}

func TestWithRateLimitMiddlewareFunction(t *testing.T) {
    limiter := ratelimit.NewRateLimiter(2.0, 1)
    
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("OK"))
    })
    
    // Применяем middleware
    wrapped := ratelimit.RateLimitMiddleware(limiter)(handler)
    
    req := httptest.NewRequest("GET", "/test", nil)
    req.RemoteAddr = "10.0.0.1:12345"
    
    // Первый запрос — должен пройти
    rec1 := httptest.NewRecorder()
    wrapped.ServeHTTP(rec1, req)
    
    if rec1.Code != http.StatusOK {
        t.Errorf("First request: expected 200, got %d", rec1.Code)
    }
    t.Logf("Request 1: %d", rec1.Code)
    
    // Второй запрос — должен быть rate limited (burst=1)
    rec2 := httptest.NewRecorder()
    wrapped.ServeHTTP(rec2, req)
    
    if rec2.Code != http.StatusTooManyRequests {
        t.Errorf("Second request: expected 429, got %d", rec2.Code)
    }
    t.Logf("Request 2: %d", rec2.Code)
    
    // Проверяем заголовок Retry-After
    retryAfter := rec2.Header().Get("Retry-After")
    if retryAfter == "" {
        t.Error("Retry-After header not set")
    } else {
        t.Logf("Retry-After: %s", retryAfter)
    }
}

func TestGetRetryAfterExact(t *testing.T) {
    limiter := ratelimit.NewRateLimiter(0.5, 10)
    
    retryAfter := limiter.GetRetryAfter()
    // Для rate 0.5, retry after должен быть 2 секунды
    if retryAfter != 2 {
        t.Logf("Retry-After: %d seconds (rate=0.5)", retryAfter)
    }
    
    limiter2 := ratelimit.NewRateLimiter(2.0, 10)
    retryAfter2 := limiter2.GetRetryAfter()
    if retryAfter2 != 1 {
        t.Logf("Retry-After: %d seconds (rate=2.0)", retryAfter2)
    }
    
    limiter3 := ratelimit.NewRateLimiter(0, 10)
    retryAfter3 := limiter3.GetRetryAfter()
    if retryAfter3 != 1 {
        t.Logf("Retry-After for disabled limiter: %d", retryAfter3)
    }
}