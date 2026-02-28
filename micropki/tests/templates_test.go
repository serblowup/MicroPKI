package tests

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"MicroPKI/internal/san"
	"MicroPKI/internal/templates"
)

func TestGetTemplate(t *testing.T) {
	tests := []struct {
		templateType templates.TemplateType
		expectError  bool
	}{
		{templates.ServerTemplate, false},
		{templates.ClientTemplate, false},
		{templates.CodeSigningTemplate, false},
		{"invalid", true},
	}

	for _, tt := range tests {
		tmpl, err := templates.GetTemplate(tt.templateType)
		if tt.expectError && err == nil {
			t.Errorf("для типа %s ожидалась ошибка", tt.templateType)
		}
		if !tt.expectError && err != nil {
			t.Errorf("для типа %s ошибка: %v", tt.templateType, err)
		}
		if !tt.expectError && tmpl == nil {
			t.Errorf("для типа %s шаблон не создан", tt.templateType)
		}
	}
}

func TestValidateSANsForTemplate(t *testing.T) {
	serverTmpl, _ := templates.GetTemplate(templates.ServerTemplate)
	clientTmpl, _ := templates.GetTemplate(templates.ClientTemplate)
	codeTmpl, _ := templates.GetTemplate(templates.CodeSigningTemplate)

	tests := []struct {
		name     string
		tmpl     *templates.CertTemplate
		sans     []san.SANEntry
		wantErr  bool
	}{
		{
			name:    "сервер с DNS",
			tmpl:    serverTmpl,
			sans:    []san.SANEntry{{Type: "dns", Value: "example.com"}},
			wantErr: false,
		},
		{
			name:    "сервер с IP",
			tmpl:    serverTmpl,
			sans:    []san.SANEntry{{Type: "ip", Value: "192.168.1.1"}},
			wantErr: false,
		},
		{
			name:    "сервер без SAN",
			tmpl:    serverTmpl,
			sans:    []san.SANEntry{},
			wantErr: true,
		},
		{
			name:    "сервер с email",
			tmpl:    serverTmpl,
			sans:    []san.SANEntry{{Type: "email", Value: "test@example.com"}},
			wantErr: true,
		},
		{
			name:    "клиент с email",
			tmpl:    clientTmpl,
			sans:    []san.SANEntry{{Type: "email", Value: "test@example.com"}},
			wantErr: false,
		},
		{
			name:    "клиент с DNS",
			tmpl:    clientTmpl,
			sans:    []san.SANEntry{{Type: "dns", Value: "example.com"}},
			wantErr: false,
		},
		{
			name:    "код с DNS",
			tmpl:    codeTmpl,
			sans:    []san.SANEntry{{Type: "dns", Value: "example.com"}},
			wantErr: false,
		},
		{
			name:    "код с IP",
			tmpl:    codeTmpl,
			sans:    []san.SANEntry{{Type: "ip", Value: "192.168.1.1"}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := templates.ValidateSANsForTemplate(tt.tmpl, tt.sans)
			if tt.wantErr && err == nil {
				t.Error("ожидалась ошибка, но ее не было")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("неожиданная ошибка: %v", err)
			}
		})
	}
}

func TestBuildCertificateTemplate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	sans := []san.SANEntry{
		{Type: "dns", Value: "example.com"},
		{Type: "ip", Value: "192.168.1.1"},
	}

	template, err := templates.BuildCertificateTemplate(
		templates.ServerTemplate,
		"/CN=example.com",
		&key.PublicKey,
		sans,
		365,
		false,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	if template.IsCA {
		t.Error("серверный сертификат не должен быть CA")
	}

	if len(template.DNSNames) != 1 || template.DNSNames[0] != "example.com" {
		t.Error("DNS имена не установлены правильно")
	}

	if len(template.IPAddresses) != 1 || template.IPAddresses[0].String() != "192.168.1.1" {
		t.Error("IP адреса не установлены правильно")
	}
}