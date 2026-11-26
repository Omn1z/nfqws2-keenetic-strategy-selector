//go:build n2s_compact

package catalog

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"nfqws2strategy/internal/tools/modules"
)

// A package may be installed, upgraded or removed while the panel is running.
// Read its small catalog on demand so changes take effect immediately.
func Builtin() ([]Strategy, error) {
	path := filepath.Join(modules.Dir(), "strategies", "catalog.json")
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return []Strategy{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("opening strategy catalog: %w", err)
	}
	defer f.Close()
	const maxBytes = 64 << 10
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading strategy catalog: %w", err)
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("strategy catalog exceeds %d bytes", maxBytes)
	}
	return parseBuiltin(data)
}
