package tests

import (
	"testing"

	"MicroPKI/internal/san"
)

func TestParseSANString(t *testing.T) {
	tests := []struct {
		input    string
		expected san.SANEntry
		wantErr  bool
	}{
		{"dns:example.com", san.SANEntry{Type: "dns", Value: "example.com"}, false},
		{"ip:192.168.1.1", san.SANEntry{Type: "ip", Value: "192.168.1.1"}, false},
		{"email:test@example.com", san.SANEntry{Type: "email", Value: "test@example.com"}, false},
		{"uri:https://example.com", san.SANEntry{Type: "uri", Value: "https://example.com"}, false},
		{"invalid", san.SANEntry{}, true},
		{"unknown:value", san.SANEntry{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			entry, err := san.ParseSANString(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("ожидалась ошибка, но ее не было")
				}
				return
			}
			if err != nil {
				t.Errorf("неожиданная ошибка: %v", err)
				return
			}
			if entry.Type != tt.expected.Type || entry.Value != tt.expected.Value {
				t.Errorf("ожидалось %+v, получено %+v", tt.expected, entry)
			}
		})
	}
}

func TestParseSANs(t *testing.T) {
	inputs := []string{
		"dns:example.com",
		"ip:192.168.1.1",
		"email:test@example.com",
	}

	entries, err := san.ParseSANs(inputs)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) != 3 {
		t.Errorf("ожидалось 3 записи, получено %d", len(entries))
	}
}

func TestValidateSANEntry(t *testing.T) {
	tests := []struct {
		entry   san.SANEntry
		wantErr bool
	}{
		{san.SANEntry{Type: "dns", Value: "example.com"}, false},
		{san.SANEntry{Type: "dns", Value: ""}, true},
		{san.SANEntry{Type: "ip", Value: "192.168.1.1"}, false},
		{san.SANEntry{Type: "ip", Value: "invalid"}, true},
		{san.SANEntry{Type: "email", Value: "test@example.com"}, false},
		{san.SANEntry{Type: "email", Value: "invalid"}, true},
		{san.SANEntry{Type: "uri", Value: "https://example.com"}, false},
		{san.SANEntry{Type: "uri", Value: "://invalid"}, true},
		{san.SANEntry{Type: "unknown", Value: "value"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.entry.Type+":"+tt.entry.Value, func(t *testing.T) {
			err := san.ValidateSANEntry(tt.entry)
			if tt.wantErr && err == nil {
				t.Error("ожидалась ошибка, но ее не было")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("неожиданная ошибка: %v", err)
			}
		})
	}
}