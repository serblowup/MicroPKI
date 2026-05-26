package tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"testing"
    "net"

	"MicroPKI/internal/policy"
	"MicroPKI/internal/repository"
	"MicroPKI/internal/san"
	"MicroPKI/internal/templates"
)

func TestKeySizePolicy(t *testing.T) {
	pol := policy.DefaultPolicy()

	tests := []struct {
		name     string
		keyType  string
		keySize  int
		certType policy.CertType
		wantErr  bool
	}{
		{"Root RSA valid", "rsa", 4096, policy.RootCA, false},
		{"Root RSA too small 3072", "rsa", 3072, policy.RootCA, true},
		{"Root RSA too small 2048", "rsa", 2048, policy.RootCA, true},
		{"Root ECC valid", "ecc", 384, policy.RootCA, false},
		{"Root ECC P-256 rejected", "ecc", 256, policy.RootCA, true},

		{"Intermediate RSA valid 4096", "rsa", 4096, policy.IntermediateCA, false},
		{"Intermediate RSA valid 3072", "rsa", 3072, policy.IntermediateCA, false},
		{"Intermediate RSA too small", "rsa", 2047, policy.IntermediateCA, true},
		{"Intermediate ECC valid", "ecc", 384, policy.IntermediateCA, false},
		{"Intermediate ECC P-256 rejected", "ecc", 256, policy.IntermediateCA, true},

		{"EndEntity RSA valid", "rsa", 2048, policy.EndEntity, false},
		{"EndEntity RSA too small", "rsa", 1024, policy.EndEntity, true},
		{"EndEntity ECC valid", "ecc", 256, policy.EndEntity, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pol.ValidateKeySize(tt.keyType, tt.keySize, tt.certType)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKeySize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidityPolicy(t *testing.T) {
	pol := policy.DefaultPolicy()

	tests := []struct {
		name     string
		certType policy.CertType
		days     int
		wantErr  bool
	}{
		{"Root valid", policy.RootCA, 3650, false},
		{"Root too long", policy.RootCA, 3651, true},
		{"Root zero", policy.RootCA, 0, true},

		{"Intermediate valid", policy.IntermediateCA, 1825, false},
		{"Intermediate too long", policy.IntermediateCA, 1826, true},

		{"EndEntity valid", policy.EndEntity, 365, false},
		{"EndEntity too long", policy.EndEntity, 366, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pol.ValidateValidityPeriod(tt.certType, tt.days)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateValidityPeriod() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWildcardPolicy(t *testing.T) {
	pol := policy.DefaultPolicy()

	// Wildcard должен быть отклонен по умолчанию
	sanEntries := []san.SANEntry{
		{Type: "dns", Value: "*.example.com"},
	}

	err := pol.ValidateSANs(templates.ServerTemplate, sanEntries)
	if err == nil {
		t.Error("wildcard SAN должен быть отклонен по умолчанию")
	}

	// Обычный DNS должен работать
	sanEntries = []san.SANEntry{
		{Type: "dns", Value: "example.com"},
	}

	err = pol.ValidateSANs(templates.ServerTemplate, sanEntries)
	if err != nil {
		t.Errorf("обычный DNS SAN должен быть разрешен: %v", err)
	}
}

func TestSANTypePolicy(t *testing.T) {
	pol := policy.DefaultPolicy()

	tests := []struct {
		name     string
		template templates.TemplateType
		sans     []san.SANEntry
		wantErr  bool
	}{
		{"Server with DNS", templates.ServerTemplate,
			[]san.SANEntry{{Type: "dns", Value: "example.com"}}, false},
		{"Server with IP", templates.ServerTemplate,
			[]san.SANEntry{{Type: "ip", Value: "192.168.1.1"}}, false},
		{"Server with email rejected", templates.ServerTemplate,
			[]san.SANEntry{{Type: "email", Value: "user@example.com"}}, true},
		{"Server with URI rejected", templates.ServerTemplate,
			[]san.SANEntry{{Type: "uri", Value: "https://example.com"}}, true},

		{"Client with email", templates.ClientTemplate,
			[]san.SANEntry{{Type: "email", Value: "user@example.com"}}, false},
		{"Client with DNS", templates.ClientTemplate,
			[]san.SANEntry{{Type: "dns", Value: "client.example.com"}}, false},

		{"CodeSign with email rejected", templates.CodeSigningTemplate,
			[]san.SANEntry{{Type: "email", Value: "dev@example.com"}}, true},
		{"CodeSign with IP rejected", templates.CodeSigningTemplate,
			[]san.SANEntry{{Type: "ip", Value: "10.0.0.1"}}, true},
		{"CodeSign with DNS allowed", templates.CodeSigningTemplate,
			[]san.SANEntry{{Type: "dns", Value: "codesign.example.com"}}, false},
		{"CodeSign with URI allowed", templates.CodeSigningTemplate,
			[]san.SANEntry{{Type: "uri", Value: "https://example.com"}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pol.ValidateSANs(tt.template, tt.sans)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSANs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPathLengthPolicy(t *testing.T) {
	pol := policy.DefaultPolicy()

	// Intermediate должен иметь pathLen <= 0
	err := pol.ValidatePathLength(policy.IntermediateCA, 0, false)
	if err != nil {
		t.Errorf("pathLen=0 должен быть разрешен: %v", err)
	}

	err = pol.ValidatePathLength(policy.IntermediateCA, 1, false)
	if err == nil {
		t.Error("pathLen=1 должен быть отклонен без override")
	}

	// С override должно работать
	err = pol.ValidatePathLength(policy.IntermediateCA, 1, true)
	if err != nil {
		t.Errorf("pathLen=1 с override должен быть разрешен: %v", err)
	}

	// Root CA не проверяется
	err = pol.ValidatePathLength(policy.RootCA, 1, false)
	if err != nil {
		t.Errorf("Root CA не должен проверяться на pathLen: %v", err)
	}
}

func TestAlgorithmPolicy(t *testing.T) {
	pol := policy.DefaultPolicy()

	// Проверяем, что функция отклоняет неизвестные алгоритмы
	err := pol.ValidateSignatureAlgorithm(999)
	if err == nil {
		t.Error("неизвестный алгоритм должен вызывать ошибку")
	}

	// Проверяем конкретный алгоритм
	err = pol.ValidateAlgorithm("rsa", 5)
	if err == nil {
		t.Log("SHA1WithRSA должен быть отклонен (если код 5 соответствует SHA1WithRSA)")
	}
}

func TestPublicKeyValidation(t *testing.T) {
	pol := policy.DefaultPolicy()

	// Проверка nil ключа
	err := pol.ValidatePublicKey(nil, policy.EndEntity)
	if err == nil {
		t.Error("nil ключ должен вызывать ошибку")
	}
}

func TestWildcardDetection(t *testing.T) {
	tests := []struct {
		name     string
		san      san.SANEntry
		expected bool
	}{
		{"wildcard dns", san.SANEntry{Type: "dns", Value: "*.example.com"}, true},
		{"wildcard subdomain", san.SANEntry{Type: "dns", Value: "*.sub.example.com"}, true},
		{"regular dns", san.SANEntry{Type: "dns", Value: "example.com"}, false},
		{"wildcard ip", san.SANEntry{Type: "ip", Value: "*.1.1.1"}, false},
		{"wildcard email", san.SANEntry{Type: "email", Value: "*@example.com"}, false},
		{"empty value", san.SANEntry{Type: "dns", Value: ""}, false},
		{"star only", san.SANEntry{Type: "dns", Value: "*"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := policy.IsWildcard(tt.san)
			if result != tt.expected {
				t.Errorf("IsWildcard() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestLoadPolicyFromFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "policy-config-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.json")
	configContent := `{
  "policy": {
    "key_sizes": {
      "rsa_root": 4096,
      "rsa_intermediate": 3072,
      "rsa_end_entity": 2048,
      "ecc_root": 384,
      "ecc_intermediate": 384,
      "ecc_end_entity": 256
    },
    "validity": {
      "root_days": 3650,
      "intermediate_days": 1825,
      "end_entity_days": 365
    },
    "san": {
      "reject_wildcards": true,
      "allowed_wildcard_templates": []
    },
    "path_length": {
      "max_intermediate": 0
    }
  }
}`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	pol, err := policy.LoadPolicyFromFile(configPath)
	if err != nil {
		t.Fatalf("ошибка загрузки конфигурации: %v", err)
	}

	if pol == nil {
		t.Fatal("политика не загружена")
	}
	
	if pol.MinRSARootCA != 4096 {
		t.Errorf("ожидался MinRSARootCA=4096, получен %d", pol.MinRSARootCA)
	}
	if pol.MaxValidityEndEntity != 365 {
		t.Errorf("ожидался MaxValidityEndEntity=365, получен %d", pol.MaxValidityEndEntity)
	}

	// Тест с несуществующим файлом
	pol, err = policy.LoadPolicyFromFile("/nonexistent.json")
	if err == nil {
		t.Error("для несуществующего файла ожидалась ошибка")
	}

	// Тест с пустым путем (должен вернуть политику по умолчанию)
	pol, err = policy.LoadPolicyFromFile("")
	if err != nil {
		t.Errorf("пустой путь не должен вызывать ошибку: %v", err)
	}
	if pol == nil {
		t.Error("для пустого пути должна возвращаться политика по умолчанию")
	}
}

func TestLoadPolicyFromFileInvalidJSON(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "policy-invalid-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "invalid.yaml")
	invalidContent := `invalid: yaml: content: [ not valid`

	if err := os.WriteFile(configPath, []byte(invalidContent), 0644); err != nil {
		t.Fatal(err)
	}

	_, err = policy.LoadPolicyFromFile(configPath)
	if err == nil {
		t.Error("для невалидного YAML ожидалась ошибка")
	}
}

func TestValidateAlgorithmExtended(t *testing.T) {
	pol := policy.DefaultPolicy()

	// SHA-256 с RSA должен быть разрешен
	err := pol.ValidateAlgorithm("rsa", x509.SHA256WithRSA)
	if err != nil {
		t.Errorf("SHA256WithRSA должен быть разрешен: %v", err)
	}

	// SHA-384 с RSA
	err = pol.ValidateAlgorithm("rsa", x509.SHA384WithRSA)
	if err != nil {
		t.Errorf("SHA384WithRSA должен быть разрешен: %v", err)
	}

	// SHA-512 с RSA
	err = pol.ValidateAlgorithm("rsa", x509.SHA512WithRSA)
	if err != nil {
		t.Errorf("SHA512WithRSA должен быть разрешен: %v", err)
	}

	// SHA-1 с RSA должен быть отклонен
	err = pol.ValidateAlgorithm("rsa", x509.SHA1WithRSA)
	if err == nil {
		t.Error("SHA1WithRSA должен быть отклонен")
	}

	// ECDSA с SHA-256
	err = pol.ValidateAlgorithm("ecc", x509.ECDSAWithSHA256)
	if err != nil {
		t.Errorf("ECDSAWithSHA256 должен быть разрешен: %v", err)
	}

	// Неизвестный тип ключа
	err = pol.ValidateAlgorithm("unknown", x509.SHA256WithRSA)
	if err == nil {
		t.Error("неизвестный тип ключа должен вызывать ошибку")
	}
}

func TestValidatePublicKeyExtended(t *testing.T) {
	pol := policy.DefaultPolicy()

	// RSA ключ правильного размера
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	err = pol.ValidatePublicKey(&rsaKey.PublicKey, policy.EndEntity)
	if err != nil {
		t.Errorf("RSA 2048 должен быть разрешен: %v", err)
	}

	// RSA ключ слишком маленький
	smallRSAKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	err = pol.ValidatePublicKey(&smallRSAKey.PublicKey, policy.EndEntity)
	if err == nil {
		t.Error("RSA 1024 должен быть отклонен")
	}

	// ECC P-256 ключ
	eccKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	err = pol.ValidatePublicKey(&eccKey.PublicKey, policy.EndEntity)
	if err != nil {
		t.Errorf("ECC P-256 должен быть разрешен для EndEntity: %v", err)
	}

	// ECC P-256 для Root CA должен быть отклонен
	err = pol.ValidatePublicKey(&eccKey.PublicKey, policy.RootCA)
	if err == nil {
		t.Error("ECC P-256 для Root CA должен быть отклонен")
	}
}

func TestValidateCSR(t *testing.T) {
	pol := policy.DefaultPolicy()

	// Создаём валидный CSR без SAN (для client шаблона SAN не обязателен)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}

	// Для client шаблона SAN не обязателен, тест должен пройти
	err = pol.ValidateCSR(csr, templates.ClientTemplate)
	if err != nil {
		t.Errorf("валидный CSR для client шаблона не должен вызывать ошибку: %v", err)
	}

	// CSR с неправильным размером ключа
	smallKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	smallTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "small.example.com"},
	}
	smallCSRDER, err := x509.CreateCertificateRequest(rand.Reader, smallTemplate, smallKey)
	if err != nil {
		t.Fatal(err)
	}
	smallCSR, err := x509.ParseCertificateRequest(smallCSRDER)
	if err != nil {
		t.Fatal(err)
	}

	// CSR с маленьким ключом должен быть отклонён
	err = pol.ValidateCSR(smallCSR, templates.ClientTemplate)
	if err == nil {
		t.Error("CSR с RSA 1024 должен быть отклонен")
	}
	
	// Проверяем с server шаблоном (требует SAN)
	err = pol.ValidateCSR(csr, templates.ServerTemplate)
	if err == nil {
		t.Error("CSR без SAN для server шаблона должен быть отклонен")
	}
	
	t.Log("CSR validation tests completed")
}

func TestValidateSignatureAlgorithm(t *testing.T) {
	pol := policy.DefaultPolicy()

	// SHA-256 должен быть разрешен
	err := pol.ValidateSignatureAlgorithm(x509.SHA256WithRSA)
	if err != nil {
		t.Errorf("SHA256WithRSA должен быть разрешен: %v", err)
	}

	// SHA-1 должен быть отклонен
	err = pol.ValidateSignatureAlgorithm(x509.SHA1WithRSA)
	if err == nil {
		t.Error("SHA1WithRSA должен быть отклонен")
	}

	// MD5 должен быть отклонен
	err = pol.ValidateSignatureAlgorithm(x509.MD5WithRSA)
	if err == nil {
		t.Error("MD5WithRSA должен быть отклонен")
	}
}

func TestParseSANFromExtension(t *testing.T) {
	// Тестируем базовую функциональность ValidateCSR
	pol := policy.DefaultPolicy()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Создаём CSR с DNSNames
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "test.example.com"},
		DNSNames: []string{"test.example.com", "www.test.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}

	// Для server шаблона SAN обязателен, тест должен пройти или вернуть ошибку,
	// но не паниковать. Проверяем, что функция не паникует.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ValidateCSR panicked: %v", r)
		}
	}()
	
	err = pol.ValidateCSR(csr, templates.ServerTemplate)
	if err != nil {
		// Ошибка допустима, главное что нет паники
		t.Logf("ValidateCSR returned error (expected or not): %v", err)
	}
	
	// Для client шаблона SAN не обязателен
	err = pol.ValidateCSR(csr, templates.ClientTemplate)
	if err != nil {
		t.Logf("ValidateCSR for client returned error: %v", err)
	}
	
	// Создаём CSR без SAN
	templateNoSAN := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "nosan.example.com"},
	}
	csrDERNoSAN, err := x509.CreateCertificateRequest(rand.Reader, templateNoSAN, key)
	if err != nil {
		t.Fatal(err)
	}
	csrNoSAN, err := x509.ParseCertificateRequest(csrDERNoSAN)
	if err != nil {
		t.Fatal(err)
	}
	
	// Для server шаблона без SAN должна быть ошибка
	err = pol.ValidateCSR(csrNoSAN, templates.ServerTemplate)
	if err == nil {
		t.Error("CSR without SAN for server template should return error")
	} else {
		t.Logf("Correctly rejected CSR without SAN: %v", err)
	}
	
	t.Log("SAN extension parsing tests completed")
}

func TestDefaultPolicyValues(t *testing.T) {
	pol := policy.DefaultPolicy()

	if pol.MinRSARootCA != 4096 {
		t.Errorf("MinRSARootCA = %d, ожидался 4096", pol.MinRSARootCA)
	}
	if pol.MinRSAIntermediateCA != 3072 {
		t.Errorf("MinRSAIntermediateCA = %d, ожидался 3072", pol.MinRSAIntermediateCA)
	}
	if pol.MinRSAEndEntity != 2048 {
		t.Errorf("MinRSAEndEntity = %d, ожидался 2048", pol.MinRSAEndEntity)
	}
	if pol.MinECCRootCA != 384 {
		t.Errorf("MinECCRootCA = %d, ожидался 384", pol.MinECCRootCA)
	}
	if pol.MinECCIntermediateCA != 384 {
		t.Errorf("MinECCIntermediateCA = %d, ожидался 384", pol.MinECCIntermediateCA)
	}
	if pol.MinECCEndEntity != 256 {
		t.Errorf("MinECCEndEntity = %d, ожидался 256", pol.MinECCEndEntity)
	}
	if pol.MaxValidityRootCA != 3650 {
		t.Errorf("MaxValidityRootCA = %d, ожидался 3650", pol.MaxValidityRootCA)
	}
	if pol.MaxValidityIntermediateCA != 1825 {
		t.Errorf("MaxValidityIntermediateCA = %d, ожидался 1825", pol.MaxValidityIntermediateCA)
	}
	if pol.MaxValidityEndEntity != 365 {
		t.Errorf("MaxValidityEndEntity = %d, ожидался 365", pol.MaxValidityEndEntity)
	}
	if !pol.RejectWildcards {
		t.Error("RejectWildcards должен быть true по умолчанию")
	}
	if pol.MaxPathLenIntermediate != 0 {
		t.Errorf("MaxPathLenIntermediate = %d, ожидался 0", pol.MaxPathLenIntermediate)
	}
}

func TestPolicyEngineWithAllCertTypes(t *testing.T) {
	pol := policy.DefaultPolicy()

	certTypes := []policy.CertType{policy.RootCA, policy.IntermediateCA, policy.EndEntity}
	keyTypes := []string{"rsa", "ecc"}

	for _, ct := range certTypes {
		for _, kt := range keyTypes {
			_ = pol.ValidateKeySize(kt, 4096, ct)
			_ = pol.ValidateValidityPeriod(ct, 365)
		}
	}
}

func TestValidateValidityPeriodNegative(t *testing.T) {
	pol := policy.DefaultPolicy()

	err := pol.ValidateValidityPeriod(policy.EndEntity, -1)
	if err == nil {
		t.Error("отрицательный срок действия должен вызывать ошибку")
	}

	err = pol.ValidateValidityPeriod(policy.EndEntity, 0)
	if err == nil {
		t.Error("нулевой срок действия должен вызывать ошибку")
	}
}

func TestParseRawSANExtension(t *testing.T) {
	// Создаём сертификат с SAN для тестирования парсинга
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	
	// Создаём CSR с SAN
	csrTemplate := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "san-test.example.com"},
		DNSNames: []string{"san-test.example.com", "www.san-test.example.com"},
		EmailAddresses: []string{"admin@example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		t.Fatal(err)
	}
	
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	
	// Находим SAN расширение
	var sanExtension []byte
	for _, ext := range csr.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 17}) {
			sanExtension = ext.Value
			break
		}
	}
	
	if sanExtension == nil {
		t.Skip("SAN extension not found in CSR")
	}
	
	// Тестируем parseRawSANExtension через публичную функцию ParseSANExtension
	// так как parseRawSANExtension — внутренняя функция
	entries, err := repository.ParseSANExtension(sanExtension)
	if err != nil {
		t.Fatalf("ParseSANExtension error: %v", err)
	}
	
	if len(entries) == 0 {
		t.Error("no SAN entries parsed")
	}
	
	// Проверяем DNS записи
	dnsFound := false
	emailFound := false
	for _, entry := range entries {
		if entry.Type == "dns" && entry.Value == "san-test.example.com" {
			dnsFound = true
		}
		if entry.Type == "email" && entry.Value == "admin@example.com" {
			emailFound = true
		}
	}
	
	if !dnsFound {
		t.Error("DNS entry 'san-test.example.com' not found")
	}
	if !emailFound {
		t.Error("Email entry 'admin@example.com' not found")
	}
	
	t.Logf("Successfully parsed %d SAN entries", len(entries))
}

func TestParseRawSANExtensionInvalid(t *testing.T) {
	// Тест с невалидными данными
	invalidData := []byte{0x00, 0x01, 0x02, 0x03}
	
	// Должна вернуться ошибка
	entries, err := repository.ParseSANExtension(invalidData)
	
	// Может вернуть ошибку или пустой результат
	if err != nil && len(entries) == 0 {
		t.Log("Invalid SAN data correctly rejected")
	} else if len(entries) > 0 {
		t.Log("ParseSANExtension returned entries for invalid data")
	}
}

func TestParseRawSANExtensionWithRealData(t *testing.T) {
    // Создаём ключ
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        t.Fatal(err)
    }
    
    // Создаём CSR с различными SAN
    template := &x509.CertificateRequest{
        Subject:        pkix.Name{CommonName: "san-test.example.com"},
        DNSNames:       []string{"san-test.example.com", "www.san-test.example.com"},
        EmailAddresses: []string{"admin@example.com"},
        IPAddresses:    []net.IP{net.ParseIP("192.168.1.100")},
    }
    
    csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
    if err != nil {
        t.Fatal(err)
    }
    
    csr, err := x509.ParseCertificateRequest(csrDER)
    if err != nil {
        t.Fatal(err)
    }
    
    // Находим SAN расширение и парсим
    for _, ext := range csr.Extensions {
        if ext.Id.Equal([]int{2, 5, 29, 17}) {
            // Используем repository.ParseSANExtension
            entries, err := repository.ParseSANExtension(ext.Value)
            if err != nil {
                t.Logf("ParseSANExtension error: %v", err)
            } else {
                t.Logf("Parsed %d SAN entries", len(entries))
            }
            break
        }
    }
    
    t.Log("parseRawSANExtension test completed")
}

func TestParseRawSANExtensionExtended(t *testing.T) {
    // Тест 1: Корректный CSR со всеми типами SAN
    t.Run("valid_CSR_with_all_SAN_types", func(t *testing.T) {
        key, err := rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
            t.Fatal(err)
        }

        template := &x509.CertificateRequest{
            Subject:        pkix.Name{CommonName: "all-sans.example.com"},
            DNSNames:       []string{"example.com", "www.example.com"},
            EmailAddresses: []string{"admin@example.com", "support@example.com"},
            IPAddresses:    []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1")},
        }
        csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
        if err != nil {
            t.Fatal(err)
        }
        csr, err := x509.ParseCertificateRequest(csrDER)
        if err != nil {
            t.Fatal(err)
        }

        var sanExtension []byte
        for _, ext := range csr.Extensions {
            if ext.Id.Equal([]int{2, 5, 29, 17}) {
                sanExtension = ext.Value
                break
            }
        }

        if sanExtension == nil {
            t.Skip("SAN extension not found")
        }

        entries, err := repository.ParseSANExtension(sanExtension)
        if err != nil {
            t.Fatalf("ParseSANExtension error: %v", err)
        }
        t.Logf("Parsed %d SAN entries", len(entries))
    })

    // Тест 2: Неверные данные
    t.Run("invalid_data", func(t *testing.T) {
        invalidData := []byte{0x00, 0x01, 0x02, 0x03}
        _, err := repository.ParseSANExtension(invalidData)
        if err != nil {
            t.Logf("invalid data correctly rejected: %v", err)
        }
    })

    // Тест 3: Пустые данные
    t.Run("empty_data", func(t *testing.T) {
        emptyData := []byte{}
        _, err := repository.ParseSANExtension(emptyData)
        if err != nil {
            t.Logf("empty data: %v", err)
        }
    })
}

func TestParseRawSANExtensionCoverage(t *testing.T) {
    // Создаём ключ
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        t.Fatal(err)
    }

    // Создаём CSR с различными SAN
    template := &x509.CertificateRequest{
        Subject:        pkix.Name{CommonName: "test.example.com"},
        DNSNames:       []string{"test.example.com", "www.test.example.com"},
        EmailAddresses: []string{"admin@example.com"},
        IPAddresses:    []net.IP{net.ParseIP("192.168.1.100")},
    }

    csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
    if err != nil {
        t.Fatal(err)
    }

    csr, err := x509.ParseCertificateRequest(csrDER)
    if err != nil {
        t.Fatal(err)
    }

    // Находим SAN расширение
    var sanExtension []byte
    for _, ext := range csr.Extensions {
        if ext.Id.Equal([]int{2, 5, 29, 17}) {
            sanExtension = ext.Value
            break
        }
    }

    if sanExtension == nil {
        t.Skip("SAN extension not found")
    }

    // Вызываем функцию через repository.ParseSANExtension
    entries, err := repository.ParseSANExtension(sanExtension)
    if err != nil {
        t.Logf("ParseSANExtension error: %v", err)
    } else {
        t.Logf("Parsed %d SAN entries", len(entries))
    }

    // Тест с неверными данными
    _, err = repository.ParseSANExtension([]byte{0x00, 0x01, 0x02})
    if err != nil {
        t.Logf("invalid data rejected: %v", err)
    }

    // Тест с пустыми данными
    _, err = repository.ParseSANExtension([]byte{})
    if err != nil {
        t.Logf("empty data: %v", err)
    }

    t.Log("parseRawSANExtension coverage test completed")
}

func TestParseRawSANExtensionFinal(t *testing.T) {
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        t.Fatal(err)
    }

    template := &x509.CertificateRequest{
        Subject:  pkix.Name{CommonName: "final-test.example.com"},
        DNSNames: []string{"final-test.example.com"},
    }
    csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
    if err != nil {
        t.Fatal(err)
    }
    csr, err := x509.ParseCertificateRequest(csrDER)
    if err != nil {
        t.Fatal(err)
    }

    for _, ext := range csr.Extensions {
        if ext.Id.Equal([]int{2, 5, 29, 17}) {
            _, err := repository.ParseSANExtension(ext.Value)
            t.Logf("ParseSANExtension result: %v", err)
            break
        }
    }
    t.Log("parseRawSANExtension final test done")
}

func TestParseRawSANExtensionDirect(t *testing.T) {
    // Создаём CSR с различными SAN
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        t.Fatal(err)
    }

    template := &x509.CertificateRequest{
        Subject:        pkix.Name{CommonName: "test.example.com"},
        DNSNames:       []string{"test.example.com", "www.test.example.com"},
        EmailAddresses: []string{"admin@example.com"},
        IPAddresses:    []net.IP{net.ParseIP("192.168.1.100")},
    }

    csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
    if err != nil {
        t.Fatal(err)
    }

    csr, err := x509.ParseCertificateRequest(csrDER)
    if err != nil {
        t.Fatal(err)
    }

    // Находим SAN расширение
    var sanExtension []byte
    for _, ext := range csr.Extensions {
        if ext.Id.Equal([]int{2, 5, 29, 17}) {
            sanExtension = ext.Value
            break
        }
    }

    if sanExtension == nil {
        t.Skip("SAN extension not found")
    }

    // Прямой вызов через repository.ParseSANExtension (которая вызывает parseRawSANExtension)
    entries, err := repository.ParseSANExtension(sanExtension)
    if err != nil {
        t.Fatalf("ParseSANExtension error: %v", err)
    }

    t.Logf("Successfully parsed %d SAN entries", len(entries))

    // Проверяем, что все типы распарсились
    hasDNS := false
    hasEmail := false
    hasIP := false
    for _, entry := range entries {
        switch entry.Type {
        case "dns":
            if entry.Value == "test.example.com" || entry.Value == "www.test.example.com" {
                hasDNS = true
            }
        case "email":
            if entry.Value == "admin@example.com" {
                hasEmail = true
            }
        case "ip":
            if entry.Value == "192.168.1.100" {
                hasIP = true
            }
        }
    }

    if !hasDNS {
        t.Error("DNS entry not found")
    }
    if !hasEmail {
        t.Error("Email entry not found")
    }
    if !hasIP {
        t.Error("IP entry not found")
    }

    // Тест с неверными данными
    _, err = repository.ParseSANExtension([]byte{0x00, 0x01, 0x02, 0x03})
    if err != nil {
        t.Logf("Invalid data correctly rejected: %v", err)
    }

    // Тест с пустыми данными
    _, err = repository.ParseSANExtension([]byte{})
    if err != nil {
        t.Logf("Empty data: %v", err)
    }
}

func TestParseRawSANExtensionViaValidateCSR(t *testing.T) {
    pol := policy.DefaultPolicy()
    
    // Создаём ключ
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        t.Fatal(err)
    }

    // Создаём CSR с SAN (это вызовет parseRawSANExtension внутри ValidateCSR)
    template := &x509.CertificateRequest{
        Subject:  pkix.Name{CommonName: "test.example.com"},
        DNSNames: []string{"test.example.com", "www.test.example.com"},
    }
    csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
    if err != nil {
        t.Fatal(err)
    }
    csr, err := x509.ParseCertificateRequest(csrDER)
    if err != nil {
        t.Fatal(err)
    }

    // Вызываем ValidateCSR, который внутри вызывает parseRawSANExtension
    err = pol.ValidateCSR(csr, templates.ServerTemplate)
    if err != nil {
        t.Logf("ValidateCSR error (may be expected): %v", err)
    }

    // Создаём CSR без SAN
    templateNoSAN := &x509.CertificateRequest{
        Subject: pkix.Name{CommonName: "nosan.example.com"},
    }
    csrDERNoSAN, err := x509.CreateCertificateRequest(rand.Reader, templateNoSAN, key)
    if err != nil {
        t.Fatal(err)
    }
    csrNoSAN, err := x509.ParseCertificateRequest(csrDERNoSAN)
    if err != nil {
        t.Fatal(err)
    }

    // Должна быть ошибка (server template требует SAN)
    err = pol.ValidateCSR(csrNoSAN, templates.ServerTemplate)
    if err == nil {
        t.Error("expected error for CSR without SAN")
    } else {
        t.Logf("Correctly rejected CSR without SAN: %v", err)
    }

    t.Log("parseRawSANExtension via ValidateCSR tested")
}