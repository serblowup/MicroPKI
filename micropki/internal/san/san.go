package san

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

type SANEntry struct {
	Type  string
	Value string
}

func ParseSANString(san string) (*SANEntry, error) {
	parts := strings.SplitN(san, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("неверный формат SAN: %s (ожидалось type:value)", san)
	}

	sanType := strings.ToLower(parts[0])
	value := parts[1]

	switch sanType {
	case "dns", "ip", "email", "uri":
		return &SANEntry{Type: sanType, Value: value}, nil
	default:
		return nil, fmt.Errorf("неподдерживаемый тип SAN: %s", sanType)
	}
}

func ParseSANs(sanStrings []string) ([]SANEntry, error) {
	var entries []SANEntry
	for _, san := range sanStrings {
		entry, err := ParseSANString(san)
		if err != nil {
			return nil, err
		}
		entries = append(entries, *entry)
	}
	return entries, nil
}

func ValidateSANEntry(entry SANEntry) error {
	switch entry.Type {
	case "dns":
		if entry.Value == "" {
			return fmt.Errorf("DNS имя не может быть пустым")
		}
	case "ip":
		if net.ParseIP(entry.Value) == nil {
			return fmt.Errorf("неверный IP адрес: %s", entry.Value)
		}
	case "email":
		if !strings.Contains(entry.Value, "@") {
			return fmt.Errorf("неверный email адрес: %s", entry.Value)
		}
	case "uri":
		if _, err := url.Parse(entry.Value); err != nil {
			return fmt.Errorf("неверный URI: %s", entry.Value)
		}
	default:
		return fmt.Errorf("неподдерживаемый тип SAN: %s", entry.Type)
	}
	return nil
}

func ValidateSANs(entries []SANEntry) error {
	for _, entry := range entries {
		if err := ValidateSANEntry(entry); err != nil {
			return err
		}
	}
	return nil
}