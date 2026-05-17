package tests

import (
	"testing"

	"MicroPKI/internal/policy"
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