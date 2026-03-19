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
)

type Server struct {
	host       string
	port       int
	db         *database.Database
	certDir    string
	httpServer *http.Server
	router     *http.ServeMux
}

func NewServer(host string, port int, db *database.Database, certDir string) *Server {
	s := &Server{
		host:    host,
		port:    port,
		db:      db,
		certDir: certDir,
		router:  http.NewServeMux(),
	}

	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	s.router.HandleFunc("GET /certificate/{serial}", s.withLogging(s.handleGetCertificate))
	
	s.router.HandleFunc("GET /ca/root", s.withLogging(s.handleGetRootCA))
	s.router.HandleFunc("GET /ca/intermediate", s.withLogging(s.handleGetIntermediateCA))
	
	s.router.HandleFunc("GET /crl", s.withLogging(s.handleCRL))
	
	s.router.HandleFunc("GET /health", s.withLogging(s.handleHealth))
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	
	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.withCORS(s.router),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	logger.Info("запуск HTTP сервера на %s", addr)
	logger.Info("директория с сертификатами: %s", s.certDir)
	
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

// Функции для тестов

func (s *Server) Router() *http.ServeMux {
	return s.router
}

func (s *Server) CertDir() string {
	return s.certDir
}

func (s *Server) WithCORS(handler http.Handler) http.Handler {
	return s.withCORS(handler)
}
