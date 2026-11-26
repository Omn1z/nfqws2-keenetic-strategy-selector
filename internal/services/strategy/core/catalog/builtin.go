package catalog

import (
	"encoding/json"
	"fmt"
	"strings"
)

func parseBuiltin(data []byte) ([]Strategy, error) {
	var items []Strategy
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("invalid strategy catalog: %w", err)
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("empty strategy catalog")
	}
	seen := make(map[string]bool, len(items))
	for i, s := range items {
		if s.ID == "" || strings.TrimSpace(s.ID) != s.ID || seen[s.ID] || strings.TrimSpace(s.Name) == "" || s.Source != "builtin" {
			return nil, fmt.Errorf("invalid strategy catalog entry %d", i+1)
		}
		seen[s.ID] = true
		switch s.L7 {
		case "tls", "http", "quic":
		default:
			return nil, fmt.Errorf("invalid L7 in strategy catalog entry %d", i+1)
		}
		if err := Validate(s.ArgLine); err != nil {
			return nil, fmt.Errorf("strategy catalog entry %d: %w", i+1, err)
		}
	}
	return items, nil
}
