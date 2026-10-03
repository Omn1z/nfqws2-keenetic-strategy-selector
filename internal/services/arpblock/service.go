// Package arpblock controls native Wi-Fi client isolation. It deliberately does
// not pretend that a MAC firewall can hide broadcasts on a shared LAN.
package arpblock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var ErrConflict = errors.New("настройки сегментов изменились; обновите данные и проверьте выбранный сегмент")

type Segment struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Address  string   `json:"address"`
	Members  []string `json:"members"`
	SSIDs    []string `json:"ssids"`
	Enabled  bool     `json:"enabled"`
	Up       bool     `json:"up"`
	Eligible bool     `json:"eligible"`
	Reason   string   `json:"reason"`
	Home     bool     `json:"home"`
}

type Client struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Segment  string `json:"segment"`
	AP       string `json:"ap"`
}

type View struct {
	Platform  string    `json:"platform"`
	Supported bool      `json:"supported"`
	Reason    string    `json:"reason"`
	Revision  string    `json:"revision"`
	Segments  []Segment `json:"segments"`
	Clients   []Client  `json:"clients"`
	CheckedAt int64     `json:"checked_at"`
}

type Change struct {
	Segment  string `json:"segment"`
	Enabled  bool   `json:"enabled"`
	Revision string `json:"revision"`
}

type commandFunc func(context.Context, string) (string, error)

// No startup mutation, background polling, firewall hooks, or packet processing:
// Keenetic owns enforcement and persists the setting in its native config.
type Service struct {
	gate     chan struct{}
	platform string
	reason   string
	run      commandFunc
	cache    View
	expires  time.Time
}

func New() *Service {
	platform, reason, run := nativeBackend()
	return &Service{gate: make(chan struct{}, 1), platform: platform, reason: reason, run: run}
}

func (s *Service) acquire(ctx context.Context) error {
	select {
	case s.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) View(ctx context.Context) (View, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := s.acquire(ctx); err != nil {
		return View{}, err
	}
	defer func() { <-s.gate }()
	if time.Now().Before(s.expires) {
		return s.cache, nil
	}
	v, _, err := s.inspect(ctx, true)
	if err == nil {
		s.cache = v
		s.expires = time.Now().Add(5 * time.Second)
	}
	return v, err
}

func (s *Service) inspect(ctx context.Context, clients bool) (View, NativeConfig, error) {
	v := View{Platform: s.platform, Reason: s.reason, Supported: s.run != nil, Segments: []Segment{}, Clients: []Client{}, CheckedAt: time.Now().Unix()}
	if s.run == nil {
		return v, NativeConfig{}, nil
	}
	raw, err := s.run(ctx, "show running-config")
	if err != nil {
		return v, NativeConfig{}, err
	}
	cfg, err := ParseKeeneticConfig(raw)
	if err != nil {
		return v, cfg, err
	}
	// Hash only parsed topology/settings, never secrets from running-config.
	encoded, err := json.Marshal(cfg)
	if err != nil {
		return v, cfg, err
	}
	digest := sha256.Sum256(encoded)
	v.Revision = hex.EncodeToString(digest[:])
	for _, b := range cfg.Bridges {
		seg := Segment{ID: b.ID, Name: b.Description, Address: b.Address, Members: append([]string{}, b.Members...), SSIDs: []string{}, Enabled: b.PeerIsolation, Up: b.Up, Home: b.ID == "Bridge0" || b.Rename == "Home"}
		if seg.Name == "" {
			seg.Name = b.Rename
		}
		if seg.Name == "" {
			seg.Name = b.ID
		}
		for _, ap := range cfg.AccessPoints {
			if contains(b.Members, ap.ID) || (ap.Rename != "" && contains(b.Members, ap.Rename)) {
				if ap.SSID != "" && !contains(seg.SSIDs, ap.SSID) {
					seg.SSIDs = append(seg.SSIDs, ap.SSID)
				}
			}
		}
		// Read-only eligibility is conservative. A live type/state check is also
		// mandatory immediately before the actual mutation.
		if err := validateConfigTarget(b); err != nil {
			seg.Reason = err.Error()
		} else {
			seg.Eligible = true
		}
		v.Segments = append(v.Segments, seg)
	}
	if clients {
		s.addClients(ctx, &v, cfg)
	}
	return v, cfg, nil
}

func (s *Service) addClients(ctx context.Context, v *View, cfg NativeConfig) {
	associations, err := s.run(ctx, "show associations")
	if err != nil {
		v.Reason = "Не удалось прочитать Wi-Fi клиентов: " + err.Error()
		return
	}
	leases, err := s.run(ctx, "show ip dhcp bindings")
	if err != nil {
		v.Reason = "Адреса и имена клиентов недоступны: " + err.Error()
	}
	v.Clients = parseClients(associations, leases, cfg)
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func findBridge(cfg NativeConfig, id string) (NativeBridgeConfig, error) {
	for _, b := range cfg.Bridges {
		if b.ID == id {
			return b, nil
		}
	}
	return NativeBridgeConfig{}, fmt.Errorf("сегмент не найден")
}

func validateConfigTarget(b NativeBridgeConfig) error {
	if !nativeBridgePattern.MatchString(b.ID) {
		return fmt.Errorf("неизвестный интерфейс")
	}
	if !b.ExplicitSecurity || (b.SecurityLevel != "private" && b.SecurityLevel != "protected") {
		return fmt.Errorf("это не локальный сегмент private/protected")
	}
	if b.Global {
		return fmt.Errorf("это WAN/global интерфейс")
	}
	if !b.Up {
		return fmt.Errorf("сегмент выключен")
	}
	if len(b.Members) == 0 {
		return fmt.Errorf("к сегменту не подключены интерфейсы")
	}
	if !validNativeIPv4(b.Address, b.Mask) {
		return fmt.Errorf("не определён адрес локального сегмента")
	}
	return nil
}

func isolationCommand(id string, enabled bool) string {
	command := "interface " + id + " "
	if !enabled {
		command += "no "
	}
	return command + "peer-isolation"
}

func (s *Service) SetIsolation(ctx context.Context, change Change) (View, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err := s.acquire(ctx); err != nil {
		return View{}, err
	}
	defer func() { <-s.gate }()
	s.expires = time.Time{}
	v, cfg, err := s.inspect(ctx, false)
	if err != nil {
		return v, err
	}
	if !v.Supported {
		return v, fmt.Errorf("%s", v.Reason)
	}
	if change.Revision == "" || change.Revision != v.Revision {
		return v, ErrConflict
	}
	b, err := findBridge(cfg, change.Segment)
	if err != nil {
		return v, err
	}
	if err = validateConfigTarget(b); err != nil {
		return v, err
	}
	statusText, err := s.run(ctx, "show interface "+b.ID)
	if err != nil {
		return v, err
	}
	status, err := ParseKeeneticInterfaceStatus(statusText, b.ID)
	if err != nil {
		return v, err
	}
	if err = ValidatePeerIsolationTarget(b, status); err != nil {
		return v, err
	}
	if b.PeerIsolation == change.Enabled {
		return s.finish(ctx, v, cfg), nil
	}
	if err := ctx.Err(); err != nil {
		return v, err
	}
	// Finish verification or rollback even if the browser disconnects after
	// sending the mutation. Every native command also has its own deadline.
	applyCtx, applyCancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer applyCancel()
	var confirmed View
	var confirmedConfig NativeConfig
	if _, err = s.run(applyCtx, isolationCommand(b.ID, change.Enabled)); err == nil {
		confirmed, confirmedConfig, err = s.verify(applyCtx, b.ID, change.Enabled)
	}
	if err == nil {
		_, err = s.run(applyCtx, "system configuration save")
	}
	if err != nil {
		restoreCtx, restoreCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer restoreCancel()
		_, restoreErr := s.run(restoreCtx, isolationCommand(b.ID, b.PeerIsolation))
		if restoreErr == nil {
			_, _, restoreErr = s.verify(restoreCtx, b.ID, b.PeerIsolation)
		}
		if restoreErr == nil {
			_, restoreErr = s.run(restoreCtx, "system configuration save")
		}
		if restoreErr != nil {
			return v, fmt.Errorf("%w; возврат настройки не подтверждён: %v. Проверьте изоляцию сегмента в Keenetic", err, restoreErr)
		}
		return v, fmt.Errorf("%w; предыдущая настройка восстановлена", err)
	}
	return s.finish(applyCtx, confirmed, confirmedConfig), nil
}

func (s *Service) verify(ctx context.Context, id string, enabled bool) (View, NativeConfig, error) {
	v, cfg, err := s.inspect(ctx, false)
	if err != nil {
		return v, cfg, err
	}
	b, err := findBridge(cfg, id)
	if err != nil {
		return v, cfg, err
	}
	if b.PeerIsolation != enabled {
		return v, cfg, fmt.Errorf("Keenetic не подтвердил настройку изоляции")
	}
	return v, cfg, nil
}

func (s *Service) finish(ctx context.Context, v View, cfg NativeConfig) View {
	// The toggle has already been verified and persisted. An optional client
	// inventory failure must not misreport that successful mutation as failed.
	s.addClients(ctx, &v, cfg)
	s.cache = v
	s.expires = time.Now().Add(5 * time.Second)
	return v
}

// Only compare fixed, validated native identifiers. MAC or hostname values are
// display-only and can never become command text.
func bridgeForAP(cfg NativeConfig, id string) string {
	alias := ""
	for _, ap := range cfg.AccessPoints {
		if ap.ID == id {
			alias = ap.Rename
			break
		}
	}
	for _, b := range cfg.Bridges {
		if contains(b.Members, id) || (alias != "" && contains(b.Members, alias)) {
			return b.ID
		}
	}
	return ""
}
