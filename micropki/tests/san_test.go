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
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if entry.Type != tt.expected.Type || entry.Value != tt.expected.Value {
				t.Errorf("expected %+v, got %+v", tt.expected, entry)
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
		t.Errorf("expected 3 entries, got %d", len(entries))
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
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateSANs(t *testing.T) {
	validEntries := []san.SANEntry{
		{Type: "dns", Value: "example.com"},
		{Type: "ip", Value: "192.168.1.1"},
		{Type: "email", Value: "test@example.com"},
		{Type: "uri", Value: "https://example.com"},
	}

	err := san.ValidateSANs(validEntries)
	if err != nil {
		t.Errorf("ValidateSANs should pass for valid entries: %v", err)
	}

	invalidEntries := []san.SANEntry{
		{Type: "dns", Value: ""},
		{Type: "ip", Value: "invalid"},
		{Type: "email", Value: "invalid"},
		{Type: "uri", Value: "://invalid"},
	}

	err = san.ValidateSANs(invalidEntries)
	if err == nil {
		t.Error("ValidateSANs should fail for invalid entries")
	} else {
		t.Logf("Correctly rejected invalid entries: %v", err)
	}
}

func TestIsWildcard(t *testing.T) {
	tests := []struct {
		entry    san.SANEntry
		expected bool
	}{
		{san.SANEntry{Type: "dns", Value: "*.example.com"}, true},
		{san.SANEntry{Type: "dns", Value: "*.sub.example.com"}, true},
		{san.SANEntry{Type: "dns", Value: "example.com"}, false},
		{san.SANEntry{Type: "dns", Value: "*"}, false},
		{san.SANEntry{Type: "ip", Value: "*.1.1.1"}, false},
		{san.SANEntry{Type: "email", Value: "*@example.com"}, false},
	}

	for _, tt := range tests {
		result := san.IsWildcard(tt.entry)
		if result != tt.expected {
			t.Errorf("IsWildcard(%+v) = %v, expected %v", tt.entry, result, tt.expected)
		}
	}
}