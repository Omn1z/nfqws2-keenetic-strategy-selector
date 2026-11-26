//go:build n2s_compact

package app

import (
	"testing"

	"nfqws2strategy/internal/services/strategy/core/catalog"
	"nfqws2strategy/internal/tools/store"
)

func TestCompactKeepsSavedStrategiesWithoutBuiltinPackage(t *testing.T) {
	t.Setenv("N2S_MODULE_DIR", t.TempDir())
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := &App{store: st}
	empty, err := a.Strategies()
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("clean compact catalog = %v, %v", empty, err)
	}
	created, err := a.SaveCustomStrategy(catalog.Strategy{Name: "saved", L7: "tls", ArgLine: "--filter-tcp=443"})
	if err != nil {
		t.Fatal(err)
	}
	reopened := &App{store: st}
	if err := st.Load(customStrategiesFile, &reopened.custom); err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Strategies()
	if err != nil || len(got) != 1 || got[0] != created {
		t.Fatalf("saved strategy unavailable without builtin package: %v", err)
	}
	if len(catalog.AutoCandidates()) == 0 {
		t.Fatal("automatic selection lost its candidates")
	}
}
