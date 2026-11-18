package dnsserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"nfqws2strategy/internal/tools/store"
)

func persistenceService(t *testing.T, cfg Config) *Service {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Enabled, cfg.ListenHost = false, "127.0.0.1"
	if err := st.Save(configFile, cfg); err != nil {
		t.Fatal(err)
	}
	s := New(st, &resolverTestBackend{}, func(string) (string, error) { return "127.0.0.1", nil })
	t.Cleanup(s.Close)
	return s
}

// A fixed temporary filename is no longer a fault injection point: writes use
// unique staging files. Block the primary path without changing its old bytes.
func blockDNSConfigSave(t *testing.T, s *Service) func() {
	t.Helper()
	path, saved := s.store.Path(configFile), s.store.Path(configFile+".fixture-before")
	if err := os.Rename(path, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		_ = os.Rename(saved, path)
		t.Fatal(err)
	}
	blocked := true
	restore := func() {
		if !blocked {
			return
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(saved, path); err != nil {
			t.Fatal(err)
		}
		blocked = false
	}
	t.Cleanup(restore)
	return restore
}

func TestDNSConfigUnreadableNeverOverwrittenByOrdinaryControls(t *testing.T) {
	for name, raw := range map[string][]byte{"empty": nil, "zeroed": make([]byte, 64), "null": []byte("null"), "empty_object": []byte("{}"), "truncated": []byte("{\"saved_rules\":["), "invalid_values": []byte("{\"timeout_seconds\":-1}")} {
		t.Run(name, func(t *testing.T) {
			st, err := store.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(st.Path(configFile), raw, 0600); err != nil {
				t.Fatal(err)
			}
			s := New(st, &resolverTestBackend{}, func(string) (string, error) { return "127.0.0.1", nil })
			defer s.Close()
			if s.Status().ConfigError == "" || s.Status().ConfigHash != "" {
				t.Fatal("invalid configuration was presented as editable defaults")
			}
			for _, mutate := range []func() error{
				func() error { return s.SetLoggingEnabled(false) }, func() error { return s.SetEnabled(false) },
				func() error { return s.SetConfig(Default()) }, func() error { return s.SetMethodEnabled(Default().DefaultUpstream.Address, "nfqws", false) },
			} {
				if err := mutate(); err == nil {
					t.Fatal("ordinary control overwrote a failed load")
				}
			}
			after, err := os.ReadFile(st.Path(configFile))
			if err != nil || !bytes.Equal(after, raw) {
				t.Fatal("damaged primary bytes were changed")
			}
		})
	}
}

func TestDNSConfigRecoveryPreservesUserRulesAndExplicitEmptyRules(t *testing.T) {
	for _, empty := range []bool{false, true} {
		cfg := Default()
		if empty {
			cfg.Rules = []Rule{}
		} else {
			cfg.Rules = cfg.Rules[:1]
			cfg.Rules[0].Domain = "preserved.example"
		}
		cfg.DefaultPool = []Upstream{{Address: "https://9.9.9.9/dns-query"}}
		s := persistenceService(t, cfg)
		want := s.Config()
		if err := os.WriteFile(s.store.Path(configFile), make([]byte, 80), 0600); err != nil {
			t.Fatal(err)
		}
		restarted := New(s.store, &resolverTestBackend{}, func(string) (string, error) { return "127.0.0.1", nil })
		defer restarted.Close()
		if got := restarted.Config(); !reflect.DeepEqual(got, want) {
			t.Fatal("verified recovery changed user settings")
		}
		if restarted.Status().ConfigError != "" || restarted.Status().ConfigWarning == "" {
			t.Fatal("recovery was not surfaced accurately")
		}
	}
}

func TestDNSConfigStaleTabRejectedAndIndependentSwitchesPreserved(t *testing.T) {
	s := persistenceService(t, Default())
	old := s.Config()
	base := s.Status().ConfigHash
	if err := s.UpdateConfig(base, func(cfg Config) Config { cfg.Rules = []Rule{}; return cfg }); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := s.UpdateConfig(base, func(Config) Config { called = true; old.CacheSize = 99; return old }); !errors.Is(err, ErrConfigConflict) || called {
		t.Fatal("stale tab overwrote newer rules")
	}
	base = s.Status().ConfigHash
	if err := s.SetLoggingEnabled(false); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMethodEnabled(s.Config().DefaultUpstream.Address, "nfqws", false); err != nil {
		t.Fatal(err)
	}
	if s.Status().ConfigHash != base {
		t.Fatal("independent controls invalidated the editable revision")
	}
	if err := s.UpdateConfig(base, func(cfg Config) Config { cfg.CacheSize = 99; return cfg }); err != nil {
		t.Fatal(err)
	}
	cfg := s.Config()
	if len(cfg.Rules) != 0 || cfg.LoggingEnabled || len(cfg.DisabledMethods) != 1 || cfg.CacheSize != 99 {
		t.Fatal("atomic merge lost independent or newer fields")
	}
}

func TestDNSRestoreReloadsActualDiskEvenWhenCallbackFails(t *testing.T) {
	s := persistenceService(t, Default())
	restored := s.Config()
	restored.Rules = []Rule{}
	restored.CacheSize = 77
	wire, _ := json.Marshal(restored)
	failure := errors.New("simulated archive commit error")
	err := s.WithConfigRestore(func() error {
		if err := os.WriteFile(s.store.Path(configFile), wire, 0600); err != nil {
			return err
		}
		return failure
	})
	if !errors.Is(err, failure) || !reflect.DeepEqual(s.Config(), restored) {
		t.Fatal("restore error left stale in-memory settings")
	}
	after, _ := os.ReadFile(s.store.Path(configFile))
	if !bytes.Equal(after, wire) {
		t.Fatal("restore reload rewrote the primary")
	}
	if err := s.SetLoggingEnabled(false); err != nil {
		t.Fatal(err)
	}
	var saved Config
	if err := s.store.Load(configFile, &saved); err != nil || len(saved.Rules) != 0 || saved.CacheSize != 77 {
		t.Fatal("later control resurrected pre-restore settings")
	}
}

func TestDNSRestoreFailedReloadBlocksWritesUntilValidatedReload(t *testing.T) {
	s := persistenceService(t, Default())
	var restorePath func()
	if err := s.WithConfigRestore(func() error { restorePath = blockDNSConfigSave(t, s); return nil }); err == nil {
		t.Fatal("unreadable restored file was accepted")
	}
	restorePath()
	if err := s.SetLoggingEnabled(false); err == nil {
		t.Fatal("old memory was allowed to save after a failed reload")
	}
	if err := s.WithConfigRestore(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.SetLoggingEnabled(false); err != nil {
		t.Fatal(err)
	}
}

func TestDNSRestoreUnchangedRetainsWorkingResolver(t *testing.T) {
	s, _, _ := newDNSServiceFixture(t, 8)
	run := activeDNSRun(s)
	failure := errors.New("archive unchanged")
	if err := s.WithConfigRestore(func() error { return failure }); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if activeDNSRun(s) != run {
		t.Fatal("unchanged disk restoration restarted a healthy resolver")
	}
}

func TestDNSExplicitImportCanRecoverInvalidConfiguration(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(st.Path(configFile), []byte("null"), 0600); err != nil {
		t.Fatal(err)
	}
	s := New(st, &resolverTestBackend{}, func(string) (string, error) { return "127.0.0.1", nil })
	defer s.Close()
	cfg := Default()
	cfg.ListenHost = "127.0.0.1"
	cfg.Rules = []Rule{}
	if err := s.ImportConfig(cfg, ConfigDigest(s.Config())); err != nil {
		t.Fatal(err)
	}
	if s.ConfigError() != nil || len(s.Config().Rules) != 0 {
		t.Fatal("explicit validated import did not clear the recovery guard")
	}
	if err := s.SetLoggingEnabled(false); err != nil {
		t.Fatal(err)
	}
}

func TestDNSUncertainCommitReloadsNewRulesBeforeUnrelatedSave(t *testing.T) {
	s := persistenceService(t, Default())
	newConfig := s.Config()
	newConfig.Rules = []Rule{}
	newConfig.CacheSize = 91
	failure := errors.New("simulated post-rename directory sync failure")
	s.saveConfig = func(cfg Config) error {
		wire, err := json.Marshal(cfg)
		if err != nil { return err }
		if err := os.WriteFile(s.store.Path(configFile),wire,0600);err!=nil{return err}
		return &store.CommitError{Err:failure}
	}
	if err:=s.SetConfig(newConfig);!errors.Is(err,failure){t.Fatal("uncertain durability was falsely acknowledged")}
	if !reflect.DeepEqual(s.Config(),newConfig)||s.ConfigError()!=nil{t.Fatal("uncertain commit left stale memory capable of overwriting committed rules")}
	s.saveConfig=nil
	if err:=s.SetLoggingEnabled(false);err!=nil{t.Fatal(err)}
	var saved Config
	if err:=s.store.Load(configFile,&saved);err!=nil||len(saved.Rules)!=0||saved.CacheSize!=91{t.Fatal("unrelated save erased the committed rule list")}
}
