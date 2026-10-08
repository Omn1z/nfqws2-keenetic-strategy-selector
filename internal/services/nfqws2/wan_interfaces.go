package nfqws2

import (
	"errors"
	"os"
	"path/filepath"

	"nfqws2strategy/internal/tools/config"
	"nfqws2strategy/internal/tools/logbuf"
)

// PrepareWANInterfaces repairs literal interface lists before the vendor init
// reads them. Its shell loops split on whitespace, not commas. Persisting the
// canonical value also covers subsequent native firewall hooks and reboots.
func (m *Manager) PrepareWANInterfaces() (bool, error) {
	m.assetsMu.Lock()
	defer m.assetsMu.Unlock()
	if m.cfg.Nfqws2Conf == "" {
		return false, nil
	}
	loc := assetLocation{filepath.Dir(m.cfg.Nfqws2Conf), filepath.Base(m.cfg.Nfqws2Conf), "conf"}
	data, mode, err := readAssetLocation(loc)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	normalized, err := config.NormalizeWANInterfaces(string(data))
	if err != nil {
		return false, err
	}
	if normalized == string(data) {
		return false, nil
	}
	if err := writeAssetLocation(loc, []byte(normalized), mode); err != nil {
		return false, err
	}
	logbuf.Append("nfqws2", "info", "ISP_INTERFACE: список WAN-интерфейсов приведён к формату NFQWS2")
	return true, nil
}
