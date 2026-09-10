package proxy

import (
	"net"
	"testing"

	"nfqws2strategy/internal/services/tgws"
	"nfqws2strategy/internal/tools/store"
)

func TestDeferredStartKeepsEnabledAndSecret(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	cfg := tgws.Default()
	cfg.Enabled = true
	cfg.Port = port
	cfg.PoolSize = 0
	cfg.CFProxy = false
	cfg.Secret = "00112233445566778899aabbccddeeff"
	if err := st.Save(tgwsConfigFile, cfg); err != nil {
		t.Fatal(err)
	}
	s := New(st)
	t.Cleanup(s.StopTGWS)
	if s.TGWS().Running() {
		t.Fatal("proxy started before the host finished network initialization")
	}
	if !s.TGWS().Config().Enabled {
		t.Fatal("deferred start lost desired enabled state")
	}
	s.StartEnabled()
	if !s.TGWS().Running() {
		t.Fatal("enabled proxy did not start")
	}
	if s.Socks5().Running() {
		t.Fatal("disabled SOCKS5 unexpectedly started")
	}
	s.StopTGWS()
	var persisted tgws.Config
	if err := st.Load(tgwsConfigFile, &persisted); err != nil {
		t.Fatal(err)
	}
	if !persisted.Enabled || persisted.Port != port || persisted.Secret != cfg.Secret {
		t.Fatal("lifecycle changed connection identity")
	}
}
