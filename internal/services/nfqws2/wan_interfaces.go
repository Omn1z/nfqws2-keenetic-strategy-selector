package nfqws2

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"nfqws2strategy/internal/tools/config"
	"nfqws2strategy/internal/tools/logbuf"
)

// PrepareWANInterfaces repairs literal interface lists before the vendor init
// reads them. Its shell loops split on whitespace, not commas. Persisting the
// canonical value also covers subsequent native firewall hooks and reboots.
// The vendor sources its .run snapshot after the main config. Normalize each
// independently: pending edits to ports/policy/WANs must not replace live values.
func (m *Manager) PrepareWANInterfaces() (bool, error) {
	m.assetsMu.Lock()
	defer m.assetsMu.Unlock()
	if m.cfg.Nfqws2Conf == "" {
		return false, nil
	}
	type update struct {
		loc  assetLocation
		data []byte
		mode os.FileMode
	}
	var updates []update
	// Read and validate both before writing, so a malformed snapshot does not
	// leave the main config partially repaired. A missing snapshot is normal
	// before startup or after stopping the engine; do not create one here.
	for _, name := range []string{m.cfg.Nfqws2Conf, m.cfg.Nfqws2Conf + ".run"} {
		loc := assetLocation{filepath.Dir(name), filepath.Base(name), "conf"}
		data, mode, err := readAssetLocation(loc)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("%s: %w", loc.name, err)
		}
		normalized, err := config.NormalizeWANInterfaces(string(data))
		if err != nil {
			return false, fmt.Errorf("%s: %w", loc.name, err)
		}
		if normalized != string(data) {
			updates = append(updates, update{loc, []byte(normalized), mode})
		}
	}
	changed := false
	for _, u := range updates {
		if err := writeAssetLocation(u.loc, u.data, u.mode); err != nil {
			return changed, fmt.Errorf("%s: %w", u.loc.name, err)
		}
		changed = true
		logbuf.Append("nfqws2", "info", u.loc.name+": ISP_INTERFACE приведён к формату NFQWS2")
	}
	return changed, nil
}
