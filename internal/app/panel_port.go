package app

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
)

const panelPortsFile = "ports.json"

type panelPortsConfig struct {
	PanelPort int `json:"panel_port"`
}

// PanelListener is implemented by the web server. The persistence callback is
// called only after the replacement socket has been bound successfully.
type PanelListener interface {
	Address() string
	ChangePort(port int, persist func() error) error
}

// ResolvePanelListenAddr keeps the configured listen host but applies the port
// saved in System settings, including when an older init script passes -l.
func ResolvePanelListenAddr(dataDir, fallback string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, panelPortsFile))
	if os.IsNotExist(err) {
		return fallback, nil
	}
	if err != nil {
		return "", err
	}
	var cfg panelPortsConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return "", fmt.Errorf("read panel port: %w", err)
	}
	if err := validatePanelPort(cfg.PanelPort); err != nil {
		return "", err
	}
	host, _, err := net.SplitHostPort(fallback)
	if err != nil {
		return "", fmt.Errorf("invalid panel listen address: %w", err)
	}
	return net.JoinHostPort(host, strconv.Itoa(cfg.PanelPort)), nil
}

func validatePanelPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("порт панели должен быть от 1 до 65535")
	}
	return nil
}

func (a *App) SetPanelListener(listener PanelListener) {
	a.panelMu.Lock()
	defer a.panelMu.Unlock()
	a.panelListener = listener
}

func (a *App) PanelPort() int {
	a.panelMu.Lock()
	listener := a.panelListener
	a.panelMu.Unlock()
	addr := a.Cfg.ListenAddr
	if listener != nil {
		addr = listener.Address()
	}
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(p)
	return port
}

func (a *App) SetPanelPort(port int) error {
	if err := validatePanelPort(port); err != nil {
		return err
	}
	a.panelMu.Lock()
	listener := a.panelListener
	a.panelMu.Unlock()
	if listener == nil {
		return fmt.Errorf("изменение порта панели недоступно до запуска HTTP-сервера")
	}
	return listener.ChangePort(port, func() error {
		if err := a.store.Save(panelPortsFile, panelPortsConfig{PanelPort: port}); err != nil {
			return fmt.Errorf("сохранить порт панели: %w", err)
		}
		return nil
	})
}
