package repository

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"MicroPKI/internal/logger"
)

func (s *Server) handleGetCertificate(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	if serial == "" {
		http.Error(w, "серийный номер не указан", http.StatusBadRequest)
		return
	}

	serial = strings.ToLower(serial)
	if _, err := hex.DecodeString(serial); err != nil {
		logger.Warn("неверный формат серийного номера: %s", serial)
		http.Error(w, "неверный формат серийного номера (ожидается hex)", http.StatusBadRequest)
		return
	}

	logger.Info("[HTTP] запрос сертификата: serial=%s, client=%s", serial, r.RemoteAddr)

	record, err := s.db.GetCertificateBySerial(serial)
	if err != nil {
		logger.Error("[HTTP] ошибка поиска в БД: %v", err)
		http.Error(w, "внутренняя ошибка сервера", http.StatusInternalServerError)
		return
	}

	if record == nil {
		if found := s.tryServeFromFileSystem(w, serial); found {
			return
		}
		
		logger.Info("[HTTP] сертификат не найден: serial=%s", serial)
		http.Error(w, "сертификат не найден", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=\"cert-%s.pem\"", serial))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(record.CertPEM))
	
	logger.Info("[HTTP] сертификат отправлен: serial=%s, size=%d", serial, len(record.CertPEM))
}

func (s *Server) handleGetRootCA(w http.ResponseWriter, r *http.Request) {
	logger.Info("[HTTP] запрос корневого сертификата CA, client=%s", r.RemoteAddr)
	
	certPath := filepath.Join(s.certDir, "ca.cert.pem")
	s.serveCAFile(w, certPath, "root-ca.pem")
}

func (s *Server) handleGetIntermediateCA(w http.ResponseWriter, r *http.Request) {
	logger.Info("[HTTP] запрос промежуточного сертификата CA, client=%s", r.RemoteAddr)
	
	possiblePaths := []string{
		filepath.Join(s.certDir, "intermediate.cert.pem"),
		filepath.Join(s.certDir, "intermediate.ca.pem"),
		filepath.Join(s.certDir, "intermediate.pem"),
	}
	
	for _, path := range possiblePaths {
		if s.serveCAFile(w, path, "intermediate-ca.pem") {
			return
		}
	}
	
	logger.Warn("[HTTP] промежуточный сертификат CA не найден")
	http.Error(w, "промежуточный сертификат CA не найден", http.StatusNotFound)
}

func (s *Server) handleCRL(w http.ResponseWriter, r *http.Request) {
	logger.Info("[HTTP] запрос CRL (заглушка), client=%s", r.RemoteAddr)
	
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("CRL generation not yet implemented - Sprint 4"))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	dbStatus := "ok"
	if err := s.db.DB.Ping(); err != nil {
		dbStatus = "error"
	}
	
	response := fmt.Sprintf(`{
		"status": "ok",
		"timestamp": "%s",
		"database": "%s",
		"cert_dir": "%s"
	}`, time.Now().UTC().Format(time.RFC3339), dbStatus, s.certDir)
	
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response))
}

func (s *Server) tryServeFromFileSystem(w http.ResponseWriter, serial string) bool {
	files, err := filepath.Glob(filepath.Join(s.certDir, "*.pem"))
	if err != nil {
		return false
	}
	
	for _, file := range files {
		if strings.Contains(strings.ToLower(file), strings.ToLower(serial)) {
			data, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=\"%s\"", filepath.Base(file)))
			w.WriteHeader(http.StatusOK)
			w.Write(data)
			
			logger.Info("[HTTP] сертификат найден в файловой системе: %s", file)
			return true
		}
	}
	
	return false
}

func (s *Server) serveCAFile(w http.ResponseWriter, path string, filename string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=\"%s\"", filename))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	
	logger.Info("[HTTP] CA сертификат отправлен: %s", path)
	return true
}