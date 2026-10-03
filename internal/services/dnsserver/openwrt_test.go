package dnsserver

import (
	"context"
	"errors"
	"testing"

	"nfqws2strategy/internal/services/openwrtdns"
)

type testOpenWrtManager struct {
	binding             *openwrtdns.Binding
	readErr, restoreErr error
	restores            int
	beforeRestore       func()
}

func (m *testOpenWrtManager) Status(context.Context) (openwrtdns.State, error) {
	return openwrtdns.State{}, nil
}
func (m *testOpenWrtManager) Apply(context.Context, string, string, openwrtdns.Endpoint, string) error {
	return nil
}
func (m *testOpenWrtManager) CurrentBinding() (*openwrtdns.Binding, error) {
	return m.binding, m.readErr
}
func (m *testOpenWrtManager) Restore(context.Context, string) error {
	m.restores++
	if m.beforeRestore != nil {
		m.beforeRestore()
	}
	if m.restoreErr == nil {
		m.binding = nil
	}
	return m.restoreErr
}

func TestOpenWrtBindingLifecycleUsesEffectiveEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		host    string
		port    int
		restore bool
	}{
		{"same endpoint stays bound", true, "127.0.0.1", 5356, false},
		{"disabled restores upstream", false, "127.0.0.1", 5356, true},
		{"system port changed", true, "127.0.0.1", 5456, true},
		{"automatic LAN address changed", true, "192.168.4.1", 5356, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := importTestService(t)
			m := &testOpenWrtManager{binding: &openwrtdns.Binding{Endpoint: openwrtdns.Endpoint{Host: "127.0.0.1", Port: 5356}}}
			s.openwrt = m
			cfg := s.Config()
			cfg.Enabled, cfg.ListenHost, cfg.DNSPort = tc.enabled, "auto", tc.port
			if restored, err := s.reconcileOpenWrtDNSLocked(cfg, tc.host); err != nil || restored != tc.restore {
				t.Fatal(err)
			}
			if (m.restores == 1) != tc.restore {
				t.Fatalf("restore calls=%d", m.restores)
			}
		})
	}
}

func TestOpenWrtRestoreFailurePreventsDisableAndPersistence(t *testing.T) {
	s := importTestService(t)
	s.cfg.Enabled = true
	previous := s.Config()
	if err := s.store.Save(configFile, previous); err != nil {
		t.Fatal(err)
	}
	m := &testOpenWrtManager{binding: &openwrtdns.Binding{Endpoint: openwrtdns.Endpoint{Host: "127.0.0.1", Port: previous.DNSPort}}, restoreErr: errors.New("uci config changed")}
	m.beforeRestore = func() {
		if !s.Config().Enabled {
			t.Error("DNS disabled before upstream restored")
		}
	}
	s.openwrt = m
	if err := s.SetEnabled(false); err == nil {
		t.Fatal("disabled DNS despite dangling OpenWrt forwarding")
	}
	if ConfigDigest(s.Config()) != ConfigDigest(previous) {
		t.Fatal("failed restore changed DNS settings")
	}
	var saved Config
	if err := s.store.Load(configFile, &saved); err != nil {
		t.Fatal(err)
	}
	if ConfigDigest(saved) != ConfigDigest(previous) {
		t.Fatal("failed restore persisted disabled DNS")
	}
	m.restoreErr = nil
	if err := s.SetEnabled(false); err != nil {
		t.Fatal(err)
	}
	if s.Config().Enabled || m.binding != nil || m.restores != 2 {
		t.Fatal("successful disable retained custom DNS binding")
	}
}

func TestOpenWrtMalformedBackupDoesNotDiscardDNSSettings(t *testing.T) {
	s := importTestService(t)
	s.openwrt = &testOpenWrtManager{readErr: errors.New("invalid backup")}
	before := s.Config()
	changed := before
	changed.CacheSize++
	if err := s.SetConfig(changed); err == nil {
		t.Fatal("ignored unreadable binding snapshot")
	}
	if ConfigDigest(s.Config()) != ConfigDigest(before) {
		t.Fatal("unreadable snapshot changed config")
	}
}

func TestOpenWrtDisabledStartupRestoresNativeDNS(t *testing.T) {
	for _, fail := range []bool{false, true} {
		s := importTestService(t)
		s.cfg.Enabled = false
		m := &testOpenWrtManager{binding: &openwrtdns.Binding{Endpoint: openwrtdns.Endpoint{Host: "127.0.0.1", Port: 5356}}}
		if fail {
			m.restoreErr = errors.New("native DNS conflict")
		}
		s.openwrt = m
		s.StartEnabled()
		if m.restores != 1 || s.controlCancel != nil || s.active != nil {
			t.Fatalf("disabled startup: restores=%d, control=%v, active=%v", m.restores, s.controlCancel != nil, s.active != nil)
		}
		if (m.binding != nil) != fail {
			t.Fatal("startup discarded failed restoration or retained successful binding")
		}
	}
}
