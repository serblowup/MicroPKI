package repository

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"MicroPKI/internal/database"
	"MicroPKI/internal/logger"
	"MicroPKI/internal/ratelimit"
)

type Server struct {
	host        string
	port        int
	db          *database.Database
	certDir     string
	crlDir      string
	httpServer  *http.Server
	router      *http.ServeMux
	rateLimiter *ratelimit.RateLimiter
}

func NewServer(host string, port int, db *database.Database, certDir string, crlDir string, rateLimit float64, rateBurst int) *Server {
	s := &Server{
		host:        host,
		port:        port,
		db:          db,
		certDir:     certDir,
		crlDir:      crlDir,
		router:      http.NewServeMux(),
		rateLimiter: ratelimit.NewRateLimiter(rateLimit, rateBurst),
	}

	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	// GET endpoints
	s.router.HandleFunc("GET /certificate/{serial}", s.withLogging(s.handleGetCertificate))
	s.router.HandleFunc("GET /ca/root", s.withLogging(s.handleGetRootCA))
	s.router.HandleFunc("GET /ca/intermediate", s.withLogging(s.handleGetIntermediateCA))
	s.router.HandleFunc("GET /crl", s.withLogging(s.handleCRL))
	s.router.HandleFunc("GET /crl/{filename}", s.withLogging(s.handleCRLFile))
	s.router.HandleFunc("GET /health", s.withLogging(s.handleHealth))
	
	// POST endpoints
	s.router.HandleFunc("POST /request-cert", s.withLogging(s.HandleRequestCert))
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	
	var handler http.Handler = s.router
	handler = s.withCORS(handler)
	
	if s.rateLimiter.IsEnabled() {
		handler = ratelimit.RateLimitMiddleware(s.rateLimiter)(handler)
		logger.Info("ограничение частоты включено: rate=%.1f/s, burst=%d", 
			s.rateLimiter.GetRate(), s.rateLimiter.GetBurst())
	}
	
	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	logger.Info("запуск HTTP сервера на %s", addr)
	logger.Info("директория с сертификатами: %s", s.certDir)
	logger.Info("директория с CRL: %s", s.crlDir)
	
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("ошибка HTTP сервера: %v", err)
		}
	}()

	logger.Info("сервер запущен. Нажмите Ctrl+C для остановки")
	
	<-stop
	logger.Info("получен сигнал завершения, останавливаем сервер...")
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := s.httpServer.Shutdown(ctx); err != nil {
		logger.Error("ошибка при остановке сервера: %v", err)
		return err
	}
	
	logger.Info("сервер остановлен")
	return nil
}

func (s *Server) Stop() error {
	if s.httpServer != nil {
		return s.httpServer.Close()
	}
	return nil
}

func IsRunning(host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (s *Server) Router() *http.ServeMux {
	return s.router
}

func (s *Server) CertDir() string {
	return s.certDir
}

func (s *Server) CrlDir() string {
	return s.crlDir
}

func (s *Server) WithCORS(handler http.Handler) http.Handler {
	return s.withCORS(handler)
}

// GetRateLimiter возвращает rate limiter
func (s *Server) GetRateLimiter() *ratelimit.RateLimiter {
	return s.rateLimiter
}