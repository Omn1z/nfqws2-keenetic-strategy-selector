package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nfqws2strategy/internal/tools/config"
)

func successfulAutoResult(args string, coefficient float64) StrategyResult {
	return StrategyResult{ArgLine: args, Success: true, TargetsTotal: 2, TargetsOK: 2, Coefficient: coefficient}
}

func TestAutoPickWinnerRejectsHTTPDespiteHigherScore(t *testing.T) {
	http := successfulAutoResult(regressionHTTPArgs, 100)
	http.L7 = "tls" // A persisted or incorrect label cannot override argv.
	tls := successfulAutoResult(regressionTLSArgs, 10)
	tls.L7 = "http" // Conversely, old metadata cannot disqualify a real TLS profile.
	partial := successfulAutoResult(regressionTLSArgs, 1000)
	partial.TargetsOK = 1
	empty := successfulAutoResult(regressionTLSArgs, 1000)
	empty.TargetsTotal, empty.TargetsOK = 0, 0
	failed := successfulAutoResult(regressionTLSArgs, 1000)
	failed.Success = false
	results := []StrategyResult{http, partial, empty, failed, tls}
	winner, err := autoPickWinner(results)
	if err != nil || winner.ArgLine != regressionTLSArgs || winner.Coefficient != 10 {
		t.Fatalf("wrong winner: %+v, %v", winner, err)
	}
	if results[0].ArgLine != regressionHTTPArgs {
		t.Fatal("winner selection reordered stored results")
	}
	if winner, err := autoPickWinner(results[:4]); err == nil || winner != nil {
		t.Fatalf("automated winner selected without a validated TLS result: %+v, %v", winner, err)
	}
}

func TestAutoPickApplyRejectsHTTPBeforeBackupOrWrite(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "nfqws2.conf")
	original := "# keep user settings\nNFQWS_ARGS=\"" + regressionTLSArgs + "\"\nNFQWS_ARGS_QUIC=\"--filter-udp=443 --lua-desync=fake:blob=quic_initial\"\nNFQWS_ARGS_UDP=\"--filter-udp=50000 --lua-desync=fake\"\n"
	if err := os.WriteFile(conf, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	backup := conf + ".n2s.bak"
	if err := os.WriteFile(backup, []byte("previous known good backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &App{Cfg: &config.Config{Nfqws2Conf: conf}}
	if err := a.applyAutoPickStrategy(successfulAutoResult(regressionHTTPArgs, 100), false); err == nil {
		t.Fatal("automated HTTP-only overwrite accepted")
	}
	for path, want := range map[string]string{conf: original, backup: "previous known good backup"} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("rejected winner modified %s: %q, %v", filepath.Base(path), got, err)
		}
	}
	// A valid TLS selection still applies, preserves unrelated protocol fields,
	// and backs up the exact previous file for recovery.
	newTLS := "--filter-tcp=80,443 --filter-l7=tls --lua-desync=multisplit:pos=1,midsld"
	if err := a.applyAutoPickStrategy(successfulAutoResult(newTLS, 10), false); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(conf)
	if want := strings.Replace(original, regressionTLSArgs, newTLS, 1); err != nil || string(got) != want {
		t.Fatalf("valid auto apply changed unrelated settings: %q, %v", got, err)
	}
	if got, err := os.ReadFile(backup); err != nil || string(got) != original {
		t.Fatalf("valid auto apply lost backup: %q, %v", got, err)
	}
	// The explicit manual API has a different contract: users may intentionally
	// replace NFQWS_ARGS with an HTTP strategy, or edit complete profiles.
	if err := a.ApplyStrategyToConfig(regressionHTTPArgs, false); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(conf)
	if want := strings.Replace(original, regressionTLSArgs, regressionHTTPArgs, 1); err != nil || string(got) != want {
		t.Fatalf("explicit manual HTTP apply was changed: %q, %v", got, err)
	}
}
