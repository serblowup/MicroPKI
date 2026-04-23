package repository

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"MicroPKI/internal/certs"
	"MicroPKI/internal/cryptoutil"
	"MicroPKI/internal/csr"
	"MicroPKI/internal/logger"
	"MicroPKI/internal/san"
	"MicroPKI/internal/templates"
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
	caParam := r.URL.Query().Get("ca")
	
	var crlPath string
	if caParam == "" || caParam == "intermediate" {
		crlPath = filepath.Join(s.crlDir, "intermediate.crl.pem")
		if _, err := os.Stat(crlPath); os.IsNotExist(err) {
			crlPath = filepath.Join(s.crlDir, "intermediate.crl.pem")
		}
	} else if caParam == "root" {
		crlPath = filepath.Join(s.crlDir, "root.crl.pem")
	} else {
		http.Error(w, "неверный параметр ca. Используйте root или intermediate", http.StatusBadRequest)
		return
	}
	
	logger.Info("[HTTP] запрос CRL: ca=%s, path=%s, client=%s", caParam, crlPath, r.RemoteAddr)
	
	s.serveCRLFile(w, crlPath)
}

func (s *Server) handleCRLFile(w http.ResponseWriter, r *http.Request) {
	filename := r.PathValue("filename")
	if filename == "" {
		http.Error(w, "имя файла не указано", http.StatusBadRequest)
		return
	}
	
	if !strings.HasSuffix(filename, ".crl") && !strings.HasSuffix(filename, ".crl.pem") {
		filename = filename + ".crl.pem"
	}
	
	crlPath := filepath.Join(s.crlDir, filename)
	
	if _, err := os.Stat(crlPath); os.IsNotExist(err) {
		altPath := filepath.Join(s.crlDir, strings.TrimSuffix(filename, ".pem"))
		if _, err := os.Stat(altPath); err == nil {
			crlPath = altPath
		}
	}
	
	logger.Info("[HTTP] запрос CRL файла: %s, path=%s, client=%s", filename, crlPath, r.RemoteAddr)
	
	s.serveCRLFile(w, crlPath)
}

// HandleRequestCert обрабатывает запросы на выпуск сертификата из CSR (REPO-15)
func (s *Server) HandleRequestCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// Проверка API ключа (если настроен)
	if expectedKey := os.Getenv("MICROPKI_API_KEY"); expectedKey != "" {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey != expectedKey {
			logger.Warn("[HTTP] неверный API ключ от %s", r.RemoteAddr)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "Unauthorized: неверный API ключ",
			})
			return
		}
	}
	
	// Парсим multipart форму
	if err := r.ParseMultipartForm(10 << 20); err != nil { // 10 MB
		logger.Error("[HTTP] ошибка парсинга формы: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "ошибка парсинга формы",
		})
		return
	}
	
	// Получаем template
	templateName := r.FormValue("template")
	if templateName == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "template не указан",
		})
		return
	}
	
	// Получаем CSR файл
	file, _, err := r.FormFile("csr")
	if err != nil {
		logger.Error("[HTTP] ошибка получения CSR: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "CSR файл не найден",
		})
		return
	}
	defer file.Close()
	
	csrData, err := io.ReadAll(file)
	if err != nil {
		logger.Error("[HTTP] ошибка чтения CSR: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "ошибка чтения CSR",
		})
		return
	}
	
	// Логируем запрос
	logger.Info("[HTTP] запрос на выпуск сертификата: template=%s, client=%s, size=%d", 
		templateName, r.RemoteAddr, len(csrData))
	
	// Выпускаем сертификат
	certPEM, err := s.issueCertificateFromCSR(csrData, templateName, r.RemoteAddr)
	if err != nil {
		logger.Error("[HTTP] ошибка выпуска сертификата: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	
	// Логируем успешную выдачу (LOG-16)
	logger.Info("[HTTP] сертификат успешно выпущен через API: template=%s, client=%s", 
		templateName, r.RemoteAddr)
	
	auditData := map[string]interface{}{
		"action":    "api_certificate_issued",
		"template":  templateName,
		"client_ip": r.RemoteAddr,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	logger.AuditJSON("api_certificate_issued", auditData)
	
	// Отправляем сертификат
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=\"certificate.pem\"")
	w.WriteHeader(http.StatusCreated)
	w.Write(certPEM)
}

// issueCertificateFromCSR выпускает сертификат из CSR
func (s *Server) issueCertificateFromCSR(csrData []byte, templateName, clientIP string) ([]byte, error) {
	// Парсим CSR
	csrObj, err := csr.ParseCSR(csrData)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга CSR: %w", err)
	}
	
	// Проверяем подпись CSR
	if err := csrObj.CheckSignature(); err != nil {
		return nil, fmt.Errorf("неверная подпись CSR: %w", err)
	}
	
	// Проверяем, что CSR не запрашивает CA сертификат
	for _, ext := range csrObj.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 19}) { // BasicConstraints
			var basicConstraints struct {
				IsCA bool `asn1:"optional"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &basicConstraints); err == nil {
				if basicConstraints.IsCA {
					return nil, fmt.Errorf("CSR запрашивает CA сертификат, что не разрешено")
				}
			}
		}
	}
	
	// Загружаем CA сертификат и ключ
	caCertPath := filepath.Join(s.certDir, "intermediate.cert.pem")
	caKeyPath := filepath.Join(filepath.Dir(s.certDir), "private", "intermediate.key.pem")
	caPassPath := filepath.Join(filepath.Dir(s.certDir), "..", "inter.pass")
	
	// Проверяем существование файлов
	if _, err := os.Stat(caCertPath); err != nil {
		return nil, fmt.Errorf("CA сертификат не найден: %s", caCertPath)
	}
	if _, err := os.Stat(caKeyPath); err != nil {
		return nil, fmt.Errorf("CA ключ не найден: %s", caKeyPath)
	}
	
	caPass, err := os.ReadFile(caPassPath)
	if err != nil {
		// Пробуем альтернативный путь
		caPassPath = filepath.Join(filepath.Dir(s.certDir), "inter.pass")
		caPass, err = os.ReadFile(caPassPath)
		if err != nil {
			return nil, fmt.Errorf("файл пароля CA не найден")
		}
	}
	
	// Очищаем пароль от символов новой строки
	if len(caPass) > 0 && caPass[len(caPass)-1] == '\n' {
		caPass = caPass[:len(caPass)-1]
	}
	defer func() {
		for i := range caPass {
			caPass[i] = 0
		}
	}()
	
	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения ключа CA: %w", err)
	}
	
	caKey, err := cryptoutil.LoadEncryptedPrivateKeyFromPEM(caKeyPEM, caPass)
	if err != nil {
		return nil, fmt.Errorf("ошибка загрузки ключа CA (неверный пароль?): %w", err)
	}
	
	caSigner, ok := caKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("ключ CA не поддерживает подписание")
	}
	
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения сертификата CA: %w", err)
	}
	
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать сертификат CA")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга сертификата CA: %w", err)
	}
	
	// Получаем шаблон
	templateType := templates.TemplateType(templateName)
	tmpl, err := templates.GetTemplate(templateType)
	if err != nil {
		return nil, fmt.Errorf("неизвестный шаблон: %s", templateName)
	}
	
	// Извлекаем SAN из CSR
	var sanEntries []san.SANEntry
	for _, ext := range csrObj.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 17}) { // Subject Alternative Name
			sanEntries, err = parseSANExtension(ext.Value)
			if err != nil {
				logger.Warn("[HTTP] ошибка парсинга SAN из CSR: %v", err)
			}
			break
		}
	}
	
	// Валидируем SAN для шаблона
	if err := templates.ValidateSANsForTemplate(tmpl, sanEntries); err != nil {
		return nil, fmt.Errorf("неверные SAN для шаблона %s: %w", templateName, err)
	}
	
	// Генерируем серийный номер
	serialNumber, err := certs.GenerateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации серийного номера: %w", err)
	}
	
	// Вычисляем SKI
	ski, err := certs.CalculateSKI(csrObj.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка вычисления SKI: %w", err)
	}
	
	// Создаем шаблон сертификата
	validityDays := 365 // По умолчанию 1 год
	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csrObj.Subject,
		Issuer:       caCert.Subject,
		NotBefore:    time.Now().UTC(),
		NotAfter:     time.Now().UTC().AddDate(0, 0, validityDays),
		
		KeyUsage:    tmpl.KeyUsage,
		ExtKeyUsage: tmpl.ExtKeyUsage,
		
		BasicConstraintsValid: true,
		IsCA:                  false,
		
		SubjectKeyId:   ski,
		AuthorityKeyId: caCert.SubjectKeyId,
	}
	
	// Добавляем SAN в сертификат
	for _, entry := range sanEntries {
		switch entry.Type {
		case "dns":
			certTemplate.DNSNames = append(certTemplate.DNSNames, entry.Value)
		case "ip":
			ip := net.ParseIP(entry.Value)
			if ip != nil {
				certTemplate.IPAddresses = append(certTemplate.IPAddresses, ip)
			}
		case "email":
			certTemplate.EmailAddresses = append(certTemplate.EmailAddresses, entry.Value)
		case "uri":
			if u, err := url.Parse(entry.Value); err == nil {
				certTemplate.URIs = append(certTemplate.URIs, u)
			}
		}
	}
	
	// Подписываем сертификат
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, csrObj.PublicKey, caSigner)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания сертификата: %w", err)
	}
	
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	
	// Сохраняем в БД
	if s.db != nil {
		cert, err := x509.ParseCertificate(certDER)
		if err == nil {
			if err := s.db.InsertCertificate(cert, certPEM, "valid"); err != nil {
				logger.Warn("[HTTP] не удалось сохранить сертификат в БД: %v", err)
			} else {
				logger.Info("[HTTP] сертификат сохранен в БД: serial=%x", cert.SerialNumber)
			}
		}
	}
	
	return certPEM, nil
}

// parseSANExtension парсит SAN расширение из CSR
func parseSANExtension(value []byte) ([]san.SANEntry, error) {
	var rawValues []asn1.RawValue
	if _, err := asn1.Unmarshal(value, &rawValues); err != nil {
		return nil, err
	}
	
	var entries []san.SANEntry
	for _, rv := range rawValues {
		switch rv.Tag {
		case 2: // dNSName
			entries = append(entries, san.SANEntry{Type: "dns", Value: string(rv.Bytes)})
		case 7: // iPAddress
			ip := net.IP(rv.Bytes)
			entries = append(entries, san.SANEntry{Type: "ip", Value: ip.String()})
		case 1: // rfc822Name
			entries = append(entries, san.SANEntry{Type: "email", Value: string(rv.Bytes)})
		case 6: // uniformResourceIdentifier
			entries = append(entries, san.SANEntry{Type: "uri", Value: string(rv.Bytes)})
		}
	}
	
	return entries, nil
}

func (s *Server) serveCRLFile(w http.ResponseWriter, crlPath string) {
	data, err := os.ReadFile(crlPath)
	if err != nil {
		logger.Warn("[HTTP] CRL файл не найден: %s", crlPath)
		http.Error(w, "CRL не найден", http.StatusNotFound)
		return
	}
	
	fileInfo, err := os.Stat(crlPath)
	if err == nil {
		w.Header().Set("Last-Modified", fileInfo.ModTime().UTC().Format(http.TimeFormat))
	}
	
	hash := sha256.Sum256(data)
	etag := fmt.Sprintf(`"%x"`, hash[:8])
	w.Header().Set("ETag", etag)
	
	w.Header().Set("Cache-Control", "max-age=3600")
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=\"%s\"", filepath.Base(crlPath)))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	
	logger.Info("[HTTP] CRL отправлен: %s, size=%d", crlPath, len(data))
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
		"cert_dir": "%s",
		"crl_dir": "%s"
	}`, time.Now().UTC().Format(time.RFC3339), dbStatus, s.certDir, s.crlDir)
	
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