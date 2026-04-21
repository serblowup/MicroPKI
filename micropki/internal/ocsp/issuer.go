package ocsp

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"

	"MicroPKI/internal/logger"
)

type IssuerManager struct {
	mu       sync.RWMutex
	issuers  map[string]*IssuerInfo
	hashMap  map[string]*IssuerInfo // key = string(nameHash) + string(keyHash)
}

func NewIssuerManager() *IssuerManager {
	return &IssuerManager{
		issuers: make(map[string]*IssuerInfo),
		hashMap: make(map[string]*IssuerInfo),
	}
}

func (im *IssuerManager) LoadIssuer(certPath string) (*IssuerInfo, error) {
	im.mu.Lock()
	defer im.mu.Unlock()

	if info, exists := im.issuers[certPath]; exists {
		return info, nil
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения сертификата эмитента: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать сертификат эмитента")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга сертификата эмитента: %w", err)
	}

	// IssuerNameHash = SHA1(Subject DN в DER кодировке)
	issuerNameHash := sha1.Sum(cert.RawSubject)
	
	// IssuerKeyHash = SHA1(только публичный ключ в DER, без алгоритма)
	// Это соответствует тому, как OpenSSL вычисляет хеш для OCSP
	var issuerKeyHash [20]byte
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		// Для RSA: хешируем публичный ключ в PKCS1 DER-кодировке
		pubDER := x509.MarshalPKCS1PublicKey(pub)
		issuerKeyHash = sha1.Sum(pubDER)
	case *ecdsa.PublicKey:
		// Для ECDSA: хешируем публичный ключ в DER-кодировке
		pubDER, err := x509.MarshalPKIXPublicKey(pub)
		if err == nil {
			issuerKeyHash = sha1.Sum(pubDER)
		} else {
			// Fallback
			issuerKeyHash = sha1.Sum(cert.RawSubjectPublicKeyInfo)
		}
	default:
		// Fallback для других типов ключей
		issuerKeyHash = sha1.Sum(cert.RawSubjectPublicKeyInfo)
	}

	logger.Info("[OCSP] загружен эмитент: subject=%s", cert.Subject.String())
	logger.Info("[OCSP]   nameHash=%x", issuerNameHash[:])
	logger.Info("[OCSP]   keyHash=%x", issuerKeyHash[:])
	
	if len(cert.SubjectKeyId) > 0 {
		logger.Info("[OCSP]   SKI: %x", cert.SubjectKeyId)
		skiHash := sha1.Sum(cert.SubjectKeyId)
		logger.Info("[OCSP]   skiHash=%x", skiHash[:])
	}

	info := &IssuerInfo{
		Certificate:   cert,
		SubjectHash:   issuerNameHash[:],
		KeyHash:       issuerKeyHash[:],
		SubjectString: cert.Subject.String(),
	}

	im.issuers[certPath] = info
	
	// Сохраняем с комбинированным ключом nameHash + keyHash
	hashKey := string(issuerNameHash[:]) + string(issuerKeyHash[:])
	im.hashMap[hashKey] = info

	logger.Info("[OCSP] эмитент добавлен в hashMap с ключом %x%x", issuerNameHash[:4], issuerKeyHash[:4])

	return info, nil
}

func (im *IssuerManager) FindByHashes(nameHash, keyHash []byte) *IssuerInfo {
	im.mu.RLock()
	defer im.mu.RUnlock()

	logger.Info("[OCSP] поиск эмитента: nameHash=%x, keyHash=%x", nameHash, keyHash)

	// Ищем по комбинированному ключу nameHash + keyHash
	hashKey := string(nameHash) + string(keyHash)
	if info, exists := im.hashMap[hashKey]; exists {
		logger.Info("[OCSP] эмитент найден по комбинированному ключу: %s", info.SubjectString)
		return info
	}

	// Если не нашли по комбинированному ключу, ищем только по nameHash
	// (для совместимости с разными реализациями OCSP)
	for _, info := range im.issuers {
		if string(info.SubjectHash) == string(nameHash) {
			// Проверяем keyHash
			if string(info.KeyHash) == string(keyHash) {
				logger.Info("[OCSP] эмитент найден по keyHash: %s", info.SubjectString)
				// Добавляем в hashMap для будущих запросов
				im.hashMap[hashKey] = info
				return info
			}
			
			// Проверяем SKI хеш (для совместимости с некоторыми реализациями)
			if len(info.Certificate.SubjectKeyId) > 0 {
				skiHash := sha1.Sum(info.Certificate.SubjectKeyId)
				if string(skiHash[:]) == string(keyHash) {
					logger.Info("[OCSP] эмитент найден по SKI хешу: %s", info.SubjectString)
					// Добавляем в hashMap для будущих запросов
					im.hashMap[hashKey] = info
					return info
				}
			}
			
			logger.Warn("[OCSP] nameHash совпал, но keyHash не совпадает")
			logger.Warn("[OCSP]   ожидался keyHash: %x", info.KeyHash)
			logger.Warn("[OCSP]   получен keyHash:  %x", keyHash)
			if len(info.Certificate.SubjectKeyId) > 0 {
				skiHash := sha1.Sum(info.Certificate.SubjectKeyId)
				logger.Warn("[OCSP]   SKI хеш: %x", skiHash[:])
			}
		}
	}

	logger.Warn("[OCSP] эмитент не найден")
	logger.Info("[OCSP] загруженные эмитенты (%d):", len(im.issuers))
	for path, info := range im.issuers {
		logger.Info("[OCSP]   %s:", path)
		logger.Info("[OCSP]     subject: %s", info.SubjectString)
		logger.Info("[OCSP]     nameHash: %x", info.SubjectHash)
		logger.Info("[OCSP]     keyHash: %x", info.KeyHash)
	}

	return nil
}

func (im *IssuerManager) GetIssuerBySubject(subject string) *IssuerInfo {
	im.mu.RLock()
	defer im.mu.RUnlock()

	for _, info := range im.issuers {
		if info.SubjectString == subject {
			return info
		}
	}
	return nil
}

func (im *IssuerManager) GetAllIssuers() []*IssuerInfo {
	im.mu.RLock()
	defer im.mu.RUnlock()

	issuers := make([]*IssuerInfo, 0, len(im.issuers))
	for _, info := range im.issuers {
		issuers = append(issuers, info)
	}
	return issuers
}

func (im *IssuerManager) ReloadIssuer(certPath string) (*IssuerInfo, error) {
	im.mu.Lock()
	defer im.mu.Unlock()

	// Удаляем старую запись если есть
	if oldInfo, exists := im.issuers[certPath]; exists {
		oldHashKey := string(oldInfo.SubjectHash) + string(oldInfo.KeyHash)
		delete(im.hashMap, oldHashKey)
		delete(im.issuers, certPath)
	}

	// Загружаем заново
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения сертификата эмитента: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать сертификат эмитента")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга сертификата эмитента: %w", err)
	}

	issuerNameHash := sha1.Sum(cert.RawSubject)
	
	var issuerKeyHash [20]byte
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		pubDER := x509.MarshalPKCS1PublicKey(pub)
		issuerKeyHash = sha1.Sum(pubDER)
	case *ecdsa.PublicKey:
		pubDER, err := x509.MarshalPKIXPublicKey(pub)
		if err == nil {
			issuerKeyHash = sha1.Sum(pubDER)
		} else {
			issuerKeyHash = sha1.Sum(cert.RawSubjectPublicKeyInfo)
		}
	default:
		issuerKeyHash = sha1.Sum(cert.RawSubjectPublicKeyInfo)
	}

	logger.Info("[OCSP] перезагружен эмитент: subject=%s", cert.Subject.String())
	logger.Info("[OCSP]   nameHash=%x", issuerNameHash[:])
	logger.Info("[OCSP]   keyHash=%x", issuerKeyHash[:])

	info := &IssuerInfo{
		Certificate:   cert,
		SubjectHash:   issuerNameHash[:],
		KeyHash:       issuerKeyHash[:],
		SubjectString: cert.Subject.String(),
	}

	im.issuers[certPath] = info
	hashKey := string(issuerNameHash[:]) + string(issuerKeyHash[:])
	im.hashMap[hashKey] = info

	return info, nil
}

func (im *IssuerManager) LoadIssuerFromBytes(certPEM []byte, source string) (*IssuerInfo, error) {
	im.mu.Lock()
	defer im.mu.Unlock()

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать сертификат эмитента")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга сертификата эмитента: %w", err)
	}

	issuerNameHash := sha1.Sum(cert.RawSubject)
	
	var issuerKeyHash [20]byte
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		pubDER := x509.MarshalPKCS1PublicKey(pub)
		issuerKeyHash = sha1.Sum(pubDER)
	case *ecdsa.PublicKey:
		pubDER, err := x509.MarshalPKIXPublicKey(pub)
		if err == nil {
			issuerKeyHash = sha1.Sum(pubDER)
		} else {
			issuerKeyHash = sha1.Sum(cert.RawSubjectPublicKeyInfo)
		}
	default:
		issuerKeyHash = sha1.Sum(cert.RawSubjectPublicKeyInfo)
	}

	logger.Info("[OCSP] загружен эмитент из %s: subject=%s", source, cert.Subject.String())
	logger.Info("[OCSP]   nameHash=%x", issuerNameHash[:])
	logger.Info("[OCSP]   keyHash=%x", issuerKeyHash[:])

	info := &IssuerInfo{
		Certificate:   cert,
		SubjectHash:   issuerNameHash[:],
		KeyHash:       issuerKeyHash[:],
		SubjectString: cert.Subject.String(),
	}

	im.issuers[source] = info
	hashKey := string(issuerNameHash[:]) + string(issuerKeyHash[:])
	im.hashMap[hashKey] = info

	return info, nil
}

func (im *IssuerManager) RemoveIssuer(certPath string) {
	im.mu.Lock()
	defer im.mu.Unlock()

	if info, exists := im.issuers[certPath]; exists {
		hashKey := string(info.SubjectHash) + string(info.KeyHash)
		delete(im.hashMap, hashKey)
		delete(im.issuers, certPath)
		logger.Info("[OCSP] удален эмитент: %s", certPath)
	}
}

func (im *IssuerManager) Clear() {
	im.mu.Lock()
	defer im.mu.Unlock()

	im.issuers = make(map[string]*IssuerInfo)
	im.hashMap = make(map[string]*IssuerInfo)
	logger.Info("[OCSP] очищены все эмитенты")
}
